"""Command-line interface for HOOKCRAFT."""

from __future__ import annotations

import argparse
import json
import sys

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    HookcraftError,
    build,
    generate_script,
    has_errors,
    lint_intent,
    parse_intent,
    parse_yaml,
)

EXAMPLES = """\
examples:
  # Generate a Frida script and print it to stdout
  python -m hookcraft generate intent.yaml

  # Write the agent to a file
  python -m hookcraft generate intent.yaml -o hooks.js

  # Lint an intent for CI (non-zero exit on errors)
  python -m hookcraft lint intent.yaml --format json

  # Machine-readable build result (script + findings) for pipelines
  python -m hookcraft generate intent.yaml --format json | jq .findings
"""


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _findings_table(findings) -> str:
    if not findings:
        return "no findings -- intent is clean"
    width = max(len(f.severity) for f in findings)
    rows = []
    for f in findings:
        rows.append(f"{f.severity.upper():<{width}}  {f.where:<22}  {f.message}")
    return "\n".join(rows)


def _cmd_generate(args) -> int:
    text = _read(args.intent)
    try:
        if args.no_strict:
            data = parse_yaml(text)
            intent = parse_intent(data)
            findings = lint_intent(intent)
            script = generate_script(intent)
        else:
            script, intent, findings = build(text, strict=True)
    except HookcraftError as exc:
        if args.format == "json":
            print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.output and args.format != "json":
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(script)

    if args.format == "json":
        out = {
            "ok": not has_errors(findings),
            "target": intent.target,
            "platform": intent.platform,
            "hooks": len(intent.hooks),
            "findings": [f.to_dict() for f in findings],
            "script": script,
        }
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(script)
            out["written_to"] = args.output
            out.pop("script")
        print(json.dumps(out, indent=2))
    else:
        if args.output:
            print(f"wrote {len(intent.hooks)} hook(s) for '{intent.target}' to {args.output}",
                  file=sys.stderr)
            if findings:
                print(_findings_table(findings), file=sys.stderr)
        else:
            print(script)
            if findings:
                print("\n// --- lint findings ---", file=sys.stderr)
                print(_findings_table(findings), file=sys.stderr)

    return 1 if has_errors(findings) else 0


def _cmd_lint(args) -> int:
    text = _read(args.intent)
    try:
        data = parse_yaml(text)
        intent = parse_intent(data)
    except HookcraftError as exc:
        if args.format == "json":
            print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 2

    findings = lint_intent(intent)
    if args.format == "json":
        print(json.dumps({
            "ok": not has_errors(findings),
            "target": intent.target,
            "platform": intent.platform,
            "hooks": len(intent.hooks),
            "findings": [f.to_dict() for f in findings],
        }, indent=2))
    else:
        print(f"target={intent.target} platform={intent.platform} hooks={len(intent.hooks)}")
        print(_findings_table(findings))

    return 1 if has_errors(findings) else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hookcraft",
        description="Generate Frida instrumentation scripts from a YAML intent.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument("--format", choices=["table", "json"], default="table",
                   dest="global_format",
                   help="output format (default: table); may also be given "
                        "after the subcommand")

    sub = p.add_subparsers(dest="command", metavar="<command>")

    g = sub.add_parser("generate", help="render the Frida JS agent from an intent")
    g.add_argument("intent", help="path to the YAML intent file ('-' for stdin)")
    g.add_argument("-o", "--output", help="write the agent to this file")
    g.add_argument("--no-strict", action="store_true",
                   help="generate even if the intent has error-level findings")
    g.add_argument("--format", choices=["table", "json"], default=None,
                   help="output format (overrides the global --format)")
    g.set_defaults(func=_cmd_generate)

    l = sub.add_parser("lint", help="validate an intent and report findings")
    l.add_argument("intent", help="path to the YAML intent file ('-' for stdin)")
    l.add_argument("--format", choices=["table", "json"], default=None,
                   help="output format (overrides the global --format)")
    l.set_defaults(func=_cmd_lint)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    # Resolve --format: a value given after the subcommand wins; otherwise
    # fall back to the global --format (so both positions work).
    sub_fmt = getattr(args, "format", None)
    args.format = sub_fmt if sub_fmt is not None else getattr(args, "global_format", "table")
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"error: file not found: {exc.filename}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
