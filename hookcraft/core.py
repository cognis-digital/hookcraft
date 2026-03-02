"""Core engine for HOOKCRAFT.

Pipeline:  YAML text -> dict (parse_yaml) -> Intent (parse_intent)
           -> lint_intent (findings) -> generate_script (Frida JS)

No third-party dependencies. The YAML subset supported is intentionally
small but covers the intent schema: mappings, lists, nested blocks,
scalars (str/int/float/bool/null), inline lists [a, b], comments and
quoted strings.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


class HookcraftError(Exception):
    """Raised for malformed intents or YAML."""


# --------------------------------------------------------------------------
# Minimal YAML parser (mapping/list/scalar subset, indentation based)
# --------------------------------------------------------------------------

_INT_RE = re.compile(r"^[-+]?\d+$")
_FLOAT_RE = re.compile(r"^[-+]?(\d+\.\d*|\.\d+|\d+)([eE][-+]?\d+)?$")


def _scalar(raw: str) -> Any:
    s = raw.strip()
    if s == "" or s == "~" or s.lower() == "null":
        return None
    if len(s) >= 2 and s[0] in "\"'" and s[-1] == s[0]:
        return s[1:-1]
    low = s.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if _INT_RE.match(s):
        return int(s)
    if _FLOAT_RE.match(s) and any(c in s for c in ".eE"):
        try:
            return float(s)
        except ValueError:
            pass
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        if not inner:
            return []
        return [_scalar(p) for p in _split_inline(inner)]
    return s


def _split_inline(inner: str) -> list[str]:
    parts, buf, quote = [], [], None
    for ch in inner:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            buf.append(ch)
        elif ch == ",":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if buf:
        parts.append("".join(buf))
    return [p.strip() for p in parts]


def _strip_comment(line: str) -> str:
    out, quote = [], None
    for ch in line:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            out.append(ch)
        elif ch == "#":
            break
        else:
            out.append(ch)
    return "".join(out).rstrip()


class _Line:
    __slots__ = ("indent", "text", "no")

    def __init__(self, indent: int, text: str, no: int):
        self.indent = indent
        self.text = text
        self.no = no


def parse_yaml(text: str) -> Any:
    """Parse the supported YAML subset into Python data structures."""
    lines: list[_Line] = []
    for i, raw in enumerate(text.splitlines(), start=1):
        stripped = _strip_comment(raw)
        if stripped.strip() == "":
            continue
        leading = stripped[: len(stripped) - len(stripped.lstrip())]
        if "\t" in leading:
            raise HookcraftError(f"line {i}: tabs are not allowed for indentation")
        indent = len(stripped) - len(stripped.lstrip(" "))
        lines.append(_Line(indent, stripped.strip(), i))
    if not lines:
        return None
    value, idx = _parse_block(lines, 0, lines[0].indent)
    if idx != len(lines):
        raise HookcraftError(
            f"line {lines[idx].no}: unexpected indentation / trailing content"
        )
    return value


def _parse_block(lines: list[_Line], idx: int, indent: int):
    if lines[idx].text.startswith("- "):
        return _parse_list(lines, idx, indent)
    return _parse_map(lines, idx, indent)


def _parse_list(lines, idx, indent):
    items = []
    while idx < len(lines) and lines[idx].indent == indent and lines[idx].text.startswith("- "):
        body = lines[idx].text[2:].strip()
        ln = lines[idx]
        if ":" in body and not _looks_like_value(body):
            # inline first key of a mapping item: synthesize a virtual line
            synthetic = _Line(indent + 2, body, ln.no)
            block_lines = [synthetic]
            j = idx + 1
            while j < len(lines) and lines[j].indent > indent:
                block_lines.append(lines[j])
                j += 1
            val, used = _parse_map(block_lines, 0, indent + 2)
            items.append(val)
            idx = j
        elif body == "":
            j = idx + 1
            block_lines = []
            while j < len(lines) and lines[j].indent > indent:
                block_lines.append(lines[j])
                j += 1
            if not block_lines:
                items.append(None)
            else:
                val, _ = _parse_block(block_lines, 0, block_lines[0].indent)
                items.append(val)
            idx = j
        else:
            items.append(_scalar(body))
            idx += 1
    return items, idx


def _looks_like_value(body: str) -> bool:
    # "key: value" where value is non-empty -> still a mapping; treat False
    # A pure scalar with a colon inside quotes is handled by _scalar.
    if body[0] in "\"'":
        return True
    return False


def _parse_map(lines, idx, indent):
    mapping: dict[str, Any] = {}
    while idx < len(lines) and lines[idx].indent == indent:
        ln = lines[idx]
        if ln.text.startswith("- "):
            break
        if ":" not in ln.text:
            raise HookcraftError(f"line {ln.no}: expected 'key: value' mapping")
        key, _, rest = ln.text.partition(":")
        key = key.strip()
        rest = rest.strip()
        if rest != "":
            mapping[key] = _scalar(rest)
            idx += 1
        else:
            j = idx + 1
            if j < len(lines) and lines[j].indent > indent:
                child_indent = lines[j].indent
                child_lines = []
                while j < len(lines) and lines[j].indent >= child_indent:
                    if lines[j].indent < child_indent:
                        break
                    child_lines.append(lines[j])
                    j += 1
                val, _ = _parse_block(child_lines, 0, child_indent)
                mapping[key] = val
                idx = j
            else:
                mapping[key] = None
                idx += 1
    return mapping, idx


# --------------------------------------------------------------------------
# Intent model
# --------------------------------------------------------------------------

VALID_KINDS = {"native_export", "objc_method", "java_method", "address", "module_init"}


@dataclass
class Hook:
    name: str
    kind: str
    raw: dict[str, Any] = field(default_factory=dict)

    # common
    log_args: bool = True
    log_return: bool = True
    backtrace: bool = False

    # native_export / module_init
    module: str | None = None
    symbol: str | None = None

    # address
    address: str | None = None

    # objc_method:  "-[NSString stringWithString:]"
    selector: str | None = None

    # java_method
    java_class: str | None = None
    method: str | None = None
    overload: list[str] | None = None


@dataclass
class Intent:
    target: str
    platform: str
    hooks: list[Hook] = field(default_factory=list)
    description: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


VALID_PLATFORMS = {"android", "ios", "linux", "macos", "windows", "generic"}


def parse_intent(data: Any) -> Intent:
    if not isinstance(data, dict):
        raise HookcraftError("intent root must be a mapping")
    target = data.get("target")
    if not isinstance(target, str) or not target.strip():
        raise HookcraftError("intent 'target' (process name or package) is required")
    platform = (data.get("platform") or "generic")
    if not isinstance(platform, str):
        raise HookcraftError("'platform' must be a string")
    platform = platform.lower()

    raw_hooks = data.get("hooks") or []
    if not isinstance(raw_hooks, list):
        raise HookcraftError("'hooks' must be a list")

    hooks: list[Hook] = []
    for i, h in enumerate(raw_hooks):
        if not isinstance(h, dict):
            raise HookcraftError(f"hooks[{i}] must be a mapping")
        kind = h.get("kind")
        if kind is None:
            # infer kind from present fields
            if "selector" in h:
                kind = "objc_method"
            elif "class" in h or "java_class" in h:
                kind = "java_method"
            elif "address" in h:
                kind = "address"
            elif "symbol" in h:
                kind = "native_export"
            else:
                kind = "native_export"
        name = h.get("name") or f"{kind}_{i}"
        hook = Hook(name=str(name), kind=str(kind), raw=h)
        hook.log_args = bool(h.get("log_args", True))
        hook.log_return = bool(h.get("log_return", True))
        hook.backtrace = bool(h.get("backtrace", False))
        hook.module = h.get("module")
        hook.symbol = h.get("symbol")
        hook.address = h.get("address")
        hook.selector = h.get("selector")
        hook.java_class = h.get("class") or h.get("java_class")
        hook.method = h.get("method")
        ov = h.get("overload")
        if ov is not None and not isinstance(ov, list):
            ov = [ov]
        hook.overload = ov
        hooks.append(hook)

    return Intent(
        target=target.strip(),
        platform=platform,
        hooks=hooks,
        description=data.get("description"),
        raw=data,
    )


# --------------------------------------------------------------------------
# Linter
# --------------------------------------------------------------------------

@dataclass
class Finding:
    severity: str  # error | warning | info
    where: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"severity": self.severity, "where": self.where, "message": self.message}


def lint_intent(intent: Intent) -> list[Finding]:
    """Return findings. Any 'error' severity means the intent is unsafe to build."""
    out: list[Finding] = []

    if intent.platform not in VALID_PLATFORMS:
        out.append(Finding("warning", "platform",
                           f"unknown platform '{intent.platform}' "
                           f"(known: {', '.join(sorted(VALID_PLATFORMS))})"))

    if not intent.hooks:
        out.append(Finding("error", "hooks", "no hooks defined; nothing to generate"))

    seen_names: dict[str, int] = {}
    for h in intent.hooks:
        seen_names[h.name] = seen_names.get(h.name, 0) + 1

    for name, count in seen_names.items():
        if count > 1:
            out.append(Finding("warning", f"hook:{name}",
                               f"duplicate hook name used {count} times"))

    for h in intent.hooks:
        where = f"hook:{h.name}"
        if h.kind not in VALID_KINDS:
            out.append(Finding("error", where,
                               f"unknown kind '{h.kind}' "
                               f"(valid: {', '.join(sorted(VALID_KINDS))})"))
            continue

        if h.kind == "native_export":
            if not h.symbol:
                out.append(Finding("error", where, "native_export requires 'symbol'"))
            if not h.module:
                out.append(Finding("info", where,
                                   "no 'module' given; symbol resolved across all modules"))
        elif h.kind == "module_init":
            if not h.module:
                out.append(Finding("error", where, "module_init requires 'module'"))
        elif h.kind == "address":
            if not h.address:
                out.append(Finding("error", where, "address hook requires 'address'"))
            elif not re.match(r"^0x[0-9a-fA-F]+$", str(h.address)):
                out.append(Finding("error", where,
                                   f"address '{h.address}' must be hex like 0x1234"))
        elif h.kind == "objc_method":
            if intent.platform not in ("ios", "macos", "generic"):
                out.append(Finding("warning", where,
                                   "objc_method only applies to ios/macos targets"))
            if not h.selector:
                out.append(Finding("error", where,
                                   "objc_method requires 'selector' e.g. '-[NSURL initWithString:]'"))
            elif not re.match(r"^[+-]\[\s*\S+\s+\S+\]$", str(h.selector)):
                out.append(Finding("warning", where,
                                   f"selector '{h.selector}' does not look like '-[Class sel]'"))
        elif h.kind == "java_method":
            if intent.platform not in ("android", "generic"):
                out.append(Finding("warning", where,
                                   "java_method only applies to android targets"))
            if not h.java_class:
                out.append(Finding("error", where, "java_method requires 'class'"))
            if not h.method:
                out.append(Finding("error", where, "java_method requires 'method'"))

    return out


def has_errors(findings: list[Finding]) -> bool:
    return any(f.severity == "error" for f in findings)


# --------------------------------------------------------------------------
# Frida JS code generation
# --------------------------------------------------------------------------

def _js(s: str) -> str:
    return json.dumps(s)


def _emit_native(h: Hook) -> str:
    sym = _js(h.symbol or "")
    mod = _js(h.module) if h.module else "null"
    lines = [
        f"  // hook: {h.name} (native_export)",
        f"  (function () {{",
        f"    var addr = Module.findExportByName({mod}, {sym});",
        f"    if (addr === null) {{ log('[!] export not found: ' + {sym}); return; }}",
        f"    Interceptor.attach(addr, {{",
        f"      onEnter: function (args) {{",
        f"        this.t0 = Date.now();",
    ]
    if h.log_args:
        lines.append("        var dumped = [];")
        lines.append("        for (var i = 0; i < 4; i++) { dumped.push(args[i].toString()); }")
        lines.append(f"        emit({{ hook: {_js(h.name)}, event: 'enter', args: dumped }});")
    if h.backtrace:
        lines.append("        emit({ hook: " + _js(h.name) + ", event: 'backtrace',"
                     " stack: Thread.backtrace(this.context, Backtracer.ACCURATE)"
                     ".map(DebugSymbol.fromAddress).map(String) });")
    lines.append("      },")
    lines.append("      onLeave: function (retval) {")
    if h.log_return:
        lines.append(f"        emit({{ hook: {_js(h.name)}, event: 'leave',"
                     " retval: retval.toString(), ms: Date.now() - this.t0 });")
    lines.append("      }")
    lines.append("    });")
    lines.append(f"    log('[+] hooked native export {h.symbol}');")
    lines.append("  })();")
    return "\n".join(lines)


def _emit_address(h: Hook) -> str:
    addr = _js(str(h.address))
    lines = [
        f"  // hook: {h.name} (address)",
        f"  (function () {{",
        f"    var addr = ptr({addr});",
        f"    Interceptor.attach(addr, {{",
        f"      onEnter: function (args) {{",
    ]
    if h.log_args:
        lines.append("        var dumped = [];")
        lines.append("        for (var i = 0; i < 4; i++) { dumped.push(args[i].toString()); }")
        lines.append(f"        emit({{ hook: {_js(h.name)}, event: 'enter', args: dumped }});")
    if h.backtrace:
        lines.append("        emit({ hook: " + _js(h.name) + ", event: 'backtrace',"
                     " stack: Thread.backtrace(this.context, Backtracer.ACCURATE)"
                     ".map(DebugSymbol.fromAddress).map(String) });")
    lines.append("      },")
    lines.append("      onLeave: function (retval) {")
    if h.log_return:
        lines.append(f"        emit({{ hook: {_js(h.name)}, event: 'leave', retval: retval.toString() }});")
    lines.append("      }")
    lines.append("    });")
    lines.append(f"    log('[+] hooked address {h.address}');")
    lines.append("  })();")
    return "\n".join(lines)


def _emit_objc(h: Hook) -> str:
    sel = _js(h.selector or "")
    lines = [
        f"  // hook: {h.name} (objc_method)",
        f"  if (ObjC.available) {{",
        f"    var target = {sel};",
        f"    var resolver = new ApiResolver('objc');",
        f"    var matches = resolver.enumerateMatches(target);",
        f"    if (matches.length === 0) {{ log('[!] no objc match: ' + target); }}",
        f"    matches.forEach(function (m) {{",
        f"      Interceptor.attach(m.address, {{",
        f"        onEnter: function (args) {{",
    ]
    if h.log_args:
        lines.append(f"          emit({{ hook: {_js(h.name)}, event: 'enter',"
                     " selector: m.name, receiver: new ObjC.Object(args[0]).toString() });")
    lines.append("        },")
    lines.append("        onLeave: function (retval) {")
    if h.log_return:
        lines.append(f"          emit({{ hook: {_js(h.name)}, event: 'leave', retval: retval.toString() }});")
    lines.append("        }")
    lines.append("      });")
    lines.append("    });")
    lines.append(f"    log('[+] hooked objc {h.selector}');")
    lines.append("  } else { log('[!] ObjC runtime not available'); }")
    return "\n".join(lines)


def _emit_java(h: Hook) -> str:
    cls = _js(h.java_class or "")
    method = _js(h.method or "")
    overload_call = ""
    if h.overload:
        args = ", ".join(_js(a) for a in h.overload)
        overload_call = f".overload({args})"
    lines = [
        f"  // hook: {h.name} (java_method)",
        f"  Java.perform(function () {{",
        f"    try {{",
        f"      var Cls = Java.use({cls});",
        f"      Cls[{method}]{overload_call}.implementation = function () {{",
    ]
    if h.log_args:
        lines.append("        var a = [];")
        lines.append("        for (var i = 0; i < arguments.length; i++) {")
        lines.append("          a.push('' + arguments[i]);")
        lines.append("        }")
        lines.append(f"        emit({{ hook: {_js(h.name)}, event: 'enter',"
                     f" cls: {cls}, method: {method}, args: a }});")
    if h.backtrace:
        lines.append("        emit({ hook: " + _js(h.name) + ", event: 'backtrace',"
                     " stack: Java.use('android.util.Log').getStackTraceString("
                     "Java.use('java.lang.Exception').$new()) });")
    lines.append("        var ret = this[" + method + "].apply(this, arguments);")
    if h.log_return:
        lines.append(f"        emit({{ hook: {_js(h.name)}, event: 'leave', retval: '' + ret }});")
    lines.append("        return ret;")
    lines.append("      };")
    lines.append(f"      send({{ _hookcraft: 'ready', hook: {_js(h.name)} }});")
    lines.append(f"      console.log('[+] hooked java {h.java_class}.{h.method}');")
    lines.append("    } catch (e) { console.log('[!] java hook failed: ' + e); }")
    lines.append("  });")
    return "\n".join(lines)


def _emit_module_init(h: Hook) -> str:
    mod = _js(h.module or "")
    lines = [
        f"  // hook: {h.name} (module_init)",
        f"  (function () {{",
        f"    var watching = {mod};",
        f"    var done = false;",
        f"    var existing = Process.findModuleByName(watching);",
        f"    if (existing) {{ emit({{ hook: {_js(h.name)}, event: 'loaded',"
        " base: existing.base.toString(), already: true }); done = true; }",
        f"    if (!done) {{",
        f"      MODULE_OBSERVERS.push({{ name: watching, hook: {_js(h.name)} }});",
        "      log('[*] waiting for module: ' + watching);",
        "    }",
        "  })();",
    ]
    return "\n".join(lines)


_EMITTERS = {
    "native_export": _emit_native,
    "address": _emit_address,
    "objc_method": _emit_objc,
    "java_method": _emit_java,
    "module_init": _emit_module_init,
}


_PRELUDE = """\
/*
 * Generated by HOOKCRAFT v{version}
 * target:   {target}
 * platform: {platform}
 * hooks:    {nhooks}
 *
 * Run:  frida -U -f {target} -l hooks.js --no-pause
 *  or:  frida -U -n {target} -l hooks.js
 *
 * DO NOT EDIT BY HAND -- regenerate from the YAML intent instead.
 */
'use strict';

var HOOKCRAFT = {{ target: {target_js}, platform: {platform_js} }};
var MODULE_OBSERVERS = [];

function log(msg) {{ console.log('[hookcraft] ' + msg); }}
function emit(obj) {{ obj._ts = Date.now(); send(obj); }}

// Observe module loads for any module_init hooks.
try {{
  var _loadHook = Module.findExportByName(null, 'dlopen') ||
                  Module.findExportByName(null, 'android_dlopen_ext');
  if (_loadHook) {{
    Interceptor.attach(_loadHook, {{
      onLeave: function () {{
        MODULE_OBSERVERS.forEach(function (o) {{
          var m = Process.findModuleByName(o.name);
          if (m) {{ emit({{ hook: o.hook, event: 'loaded', base: m.base.toString() }}); }}
        }});
      }}
    }});
  }}
}} catch (e) {{ log('module-load observer unavailable: ' + e); }}

function installHooks() {{
"""

_EPILOGUE = """\
  send({ _hookcraft: 'installed', count: %d });
  log('all hooks installed (%d)');
}

%s
"""


def generate_script(intent: Intent) -> str:
    """Render the full Frida JavaScript agent for an intent."""
    blocks = []
    for h in intent.hooks:
        emitter = _EMITTERS.get(h.kind)
        if emitter is None:
            raise HookcraftError(f"cannot emit unknown hook kind '{h.kind}'")
        blocks.append(emitter(h))

    prelude = _PRELUDE.format(
        version="1.0.0",
        target=intent.target,
        platform=intent.platform,
        nhooks=len(intent.hooks),
        target_js=_js(intent.target),
        platform_js=_js(intent.platform),
    )

    body = "\n\n".join(blocks)

    n = len(intent.hooks)
    bootstrap = "installHooks();"
    epilogue = _EPILOGUE % (n, n, bootstrap)

    return prelude + body + "\n" + epilogue


def build(yaml_text: str, *, strict: bool = True) -> tuple[str, Intent, list[Finding]]:
    """High level: parse + lint + generate.

    Returns (script, intent, findings). If strict and there are error-level
    findings, raises HookcraftError before generating.
    """
    data = parse_yaml(yaml_text)
    intent = parse_intent(data)
    findings = lint_intent(intent)
    if strict and has_errors(findings):
        msgs = "; ".join(f"{f.where}: {f.message}" for f in findings if f.severity == "error")
        raise HookcraftError(f"intent has errors: {msgs}")
    script = generate_script(intent)
    return script, intent, findings
