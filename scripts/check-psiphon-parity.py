#!/usr/bin/env python3
"""Check the Psiphon lane's config map against the pinned tunnel-core.

`docs/psiphon-parity.md` classifies every JSON field of the pinned
`psiphon.Config` that `KNOWN_SETTINGS` does not accept. A field that appears in
neither place is an unclassified gap, so a new pin cannot add one silently.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile

CONFIG = "upstream/psiphon-tunnel-core/psiphon/config.go"
SOURCE = "crates/ferrox-app/src/psiphon.rs"
DOC = "docs/psiphon-parity.md"
PINS = "upstream/pins.toml"
GIT = shutil.which("git")

CLASSES = {
    "client-front", "client-api", "client-core", "client-replay",
    "client-packet-tunnel", "client-dns", "client-keepalive",
    "client-liveness", "client-tls", "client-obfuscation",
    "client-routing", "client-transfers", "client-inproxy",
    "relay-inproxy", "relay-server", "diagnostics", "migration",
    "host-hook", "upstream-disabled",
}
STATES = {"missing", "not-a-client-lane"}


def between(text, begin, end, fails, label):
    start = text.find(begin)
    stop = text.find(end, start + 1) if start >= 0 else -1
    if start < 0 or stop < 0:
        fails.append(f"{DOC}: no {label} between {begin} and {end}")
        return ""
    return text[start + len(begin):stop]


def without_comment(line, in_block, quote=None, escaped=False):
    out = []
    index = 0
    while index < len(line):
        if in_block:
            end = line.find("*/", index)
            if end < 0:
                return "".join(out), True, quote, escaped
            index = end + 2
            in_block = False
            continue
        char = line[index]
        if quote is not None:
            out.append(char)
            if escaped:
                escaped = False
            elif char == "\\" and quote != "`":
                escaped = True
            elif char == quote:
                quote = None
        elif char in ('"', "'", '`'):
            quote = char
            out.append(char)
        elif char == "/" and line[index:index + 2] == "//":
            break
        elif char == "/" and line[index:index + 2] == "/*":
            in_block = True
            index += 2
            continue
        else:
            out.append(char)
        index += 1
    return "".join(out), in_block, quote, escaped


def brace_delta(line, quote=None, escaped=False):
    delta = 0
    for char in line:
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\" and quote != "`":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in ('"', "'", '`'):
            quote = char
        elif char == "{":
            delta += 1
        elif char == "}":
            delta -= 1
    return delta, quote, escaped


def upstream_fields(root):
    path = os.path.join(root, CONFIG)
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as f:
        text = f.read()
    marker = "type Config struct {"
    start = text.find(marker)
    if start < 0:
        return None
    # Count braces outside Go comments so a brace in a comment cannot hide the end.
    depth = 0
    end = len(text)
    in_block = False
    in_line = False
    quote = None
    escaped = False
    index = start + len(marker) - 1
    while index < len(text):
        if in_block:
            if text[index:index + 2] == "*/":
                in_block = False
                index += 2
                continue
            index += 1
            continue
        if in_line:
            if text[index] == "\n":
                in_line = False
            index += 1
            continue
        if quote is not None:
            if escaped:
                escaped = False
            elif text[index] == "\\" and quote != "`":
                escaped = True
            elif text[index] == quote:
                quote = None
            index += 1
            continue
        if text[index:index + 2] == "//":
            in_line = True
            index += 2
            continue
        if text[index:index + 2] == "/*":
            in_block = True
            index += 2
            continue
        if text[index] in ('"', "'", '`'):
            quote = text[index]
            index += 1
            continue
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                end = index
                break
        index += 1
    body = text[start + len(marker):end]
    fields = []
    depth = 0
    in_block = False
    quote = None
    escaped = False
    for line in body.splitlines():
        start_quote, start_escaped = quote, escaped
        line, in_block, quote, escaped = without_comment(
            line, in_block, quote, escaped
        )
        line = line.strip()
        top = depth == 0
        delta, _, _ = brace_delta(line, start_quote, start_escaped)
        depth += delta
        if not top or not line:
            continue
        match = re.match(r"^([A-Z]\w*)\s+[^`]*(?:`([^`]*)`)?", line)
        if not match:
            continue
        tag = re.search(r'json:"([^"]*)"', match.group(2) or "")
        if tag and tag.group(1) == "-":
            continue
        name = tag.group(1).split(",")[0] if tag else ""
        fields.append(name or match.group(1))
    return fields


def known_settings(root):
    path = os.path.join(root, SOURCE)
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as f:
        text = f.read()
    marker = "const KNOWN_SETTINGS: &[&str] = &["
    start = text.find(marker)
    if start < 0:
        return None
    end = text.find("];", start)
    if end < 0:
        return None
    return re.findall(r'"([^"]+)"', text[start:end])


def git_run(*args, check=False, **kwargs):
    if GIT is None:
        raise RuntimeError("git is not on PATH")
    return subprocess.run([GIT, *args], check=check, **kwargs)


def checkout_rev(root):
    path = os.path.join(root, "upstream/psiphon-tunnel-core")
    try:
        out = git_run(
            "-C", path, "rev-parse", "HEAD",
            capture_output=True, text=True, check=True,
        )
    except (OSError, RuntimeError, subprocess.CalledProcessError):
        return None
    return out.stdout.strip() or None


def pin_rev(root):
    path = os.path.join(root, PINS)
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as f:
        text = f.read()
    match = re.search(
        r"^\[sources\.psiphon-tunnel-core\]$(.*?)(?=^\[|\Z)", text,
        re.M | re.S,
    )
    if not match:
        return None
    rev = re.search(r"^rev\s*=\s*\"([0-9a-f]+)\"", match.group(1), re.M)
    return rev.group(1) if rev else None


def parse_doc(root, fails):
    path = os.path.join(root, DOC)
    if not os.path.isfile(path):
        fails.append(f"{DOC}: missing")
        return {}, set(), set()
    with open(path, encoding="utf-8") as f:
        text = f.read()

    rows = {}
    seen = {}
    begin = "<!-- parity:begin -->"
    block = between(text, begin, "<!-- parity:end -->", fails,
                    "parity table")
    offset = text[:text.find(begin)].count("\n") + 1
    for number, line in enumerate(block.splitlines(), 1):
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) != 3 or cells[0] in ("class", "") \
                or set(cells[0]) == {"-"}:
            continue
        line_no = offset + number - 1
        cls = cells[0].strip().strip("`").strip()
        state = cells[1].strip().strip("`").strip()
        listed = cells[2]
        rows[line_no] = {"class": cls, "state": state}
        if cls not in CLASSES:
            fails.append(f"{DOC}:{line_no}: class {cls!r} is not one of "
                         f"{', '.join(sorted(CLASSES))}")
        if state not in STATES:
            fails.append(f"{DOC}:{line_no}: state {state!r} is not one of "
                         f"{', '.join(sorted(STATES))}")
        want = "missing" if cls.startswith("client-") else "not-a-client-lane"
        if state != want:
            fails.append(f"{DOC}:{line_no}: {cls} takes state {want!r}, "
                         f"not {state!r}")
        names = [name.strip().strip("`").strip()
                 for name in listed.split(",") if name.strip()]
        if not names:
            fails.append(f"{DOC}:{line_no}: no field names")
        for name in names:
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                fails.append(f"{DOC}:{line_no}: {name!r} is not a field name")
            if name in seen:
                fails.append(f"{DOC}: {name} is listed twice "
                             f"(lines {seen[name]} and {line_no})")
            else:
                seen[name] = line_no
    if not rows:
        fails.append(f"{DOC}: the parity table has no rows")

    aliases = set()
    block = between(text, "<!-- aliases:begin -->", "<!-- aliases:end -->",
                    fails, "alias list")
    for token in re.split(r"[,\s]+", block):
        token = token.strip().strip("`").strip()
        if token:
            aliases.add(token)
    if not aliases:
        fails.append(f"{DOC}: the alias list is empty")
    return rows, set(seen), aliases


def run_check(root):
    fails = []
    upstream = upstream_fields(root)
    known = known_settings(root)
    if upstream is None:
        fails.append(f"{CONFIG}: missing; run "
                     "`scripts/fetch-upstream.sh --only psiphon-tunnel-core`")
        upstream = []
    if known is None:
        fails.append(f"{SOURCE}: no KNOWN_SETTINGS list")
        known = []

    upstream_set = set(upstream)
    known_set = set(known)
    expected = upstream_set - known_set
    aliases_expected = known_set - upstream_set

    _, listed, aliases = parse_doc(root, fails)

    missing = sorted(expected - listed)
    extra = sorted(listed - expected)
    unknown = sorted(listed - upstream_set)
    known_listed = sorted(listed & known_set)
    if missing:
        fails.append("unclassified upstream field(s): " + ", ".join(missing))
    if extra:
        fails.append("field(s) not an upstream gap: " + ", ".join(extra))
    if unknown:
        fails.append("field(s) not in the pinned Config: " + ", ".join(unknown))
    if known_listed:
        fails.append("accepted field(s) also listed as a gap: "
                     + ", ".join(known_listed))

    aliases_missing = sorted(aliases_expected - aliases)
    aliases_extra = sorted(aliases - aliases_expected)
    if aliases_missing:
        fails.append("alias spelling(s) not in the map: "
                     + ", ".join(aliases_missing))
    if aliases_extra:
        fails.append("spelling(s) not a KNOWN_SETTINGS alias: "
                     + ", ".join(aliases_extra))

    rev = pin_rev(root)
    if rev is None:
        fails.append(f"{PINS}: no psiphon-tunnel-core rev")
    else:
        checkout = checkout_rev(root)
        if checkout is None:
            fails.append(f"{CONFIG}: cannot read the checkout revision")
        elif checkout != rev:
            fails.append(
                f"{CONFIG}: checkout is at {checkout[:7]}, not the pinned {rev[:7]}"
            )
        path = os.path.join(root, DOC)
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as f:
                text = f.read()
            if rev[:7] not in text:
                fails.append(f"{DOC}: does not cite the pinned rev {rev[:7]}")

    return fails, {
        "upstream": len(upstream_set),
        "known": len(known_set),
        "known_upstream": len(upstream_set & known_set),
        "aliases": len(aliases_expected),
        "gaps": len(expected),
    }


def selftest():
    root = tempfile.mkdtemp(prefix="psiphon-parity-")
    try:
        os.makedirs(os.path.join(root, "upstream/psiphon-tunnel-core/psiphon"))
        os.makedirs(os.path.join(root, "crates/ferrox-app/src"))
        os.makedirs(os.path.join(root, "docs"))
        config = os.path.join(root, CONFIG)
        source = os.path.join(root, SOURCE)
        doc = os.path.join(root, DOC)
        pins = os.path.join(root, PINS)
        with open(config, "w", encoding="utf-8") as f:
            f.write(
                "package psiphon\n\n"
                "type Config struct {\n"
                "\tA string `json:\",omitempty\"`\n"
                "\tB string `json:\",omitempty\"`\n"
                "\tC string `json:\",omitempty\"`\n"
                "}\n"
            )
        git_run(
            "init", "-q", os.path.join(root, "upstream/psiphon-tunnel-core"),
            check=True,
        )
        git_run(
            "-C", os.path.join(root, "upstream/psiphon-tunnel-core"),
            "add", "psiphon/config.go",
            check=True,
        )
        git_run(
            "-C", os.path.join(root, "upstream/psiphon-tunnel-core"),
            "-c", "user.name=parity", "-c", "user.email=parity@test",
            "commit", "--no-gpg-sign", "-q", "-m", "fixture",
            check=True,
        )
        rev = checkout_rev(root)
        assert rev is not None
        with open(source, "w", encoding="utf-8") as f:
            f.write(
                "const KNOWN_SETTINGS: &[&str] = &[\n"
                '    "A",\n    "alias",\n];\n'
            )
        with open(pins, "w", encoding="utf-8") as f:
            f.write(
                "[sources.psiphon-tunnel-core]\n"
                f'rev = "{rev}"\n'
            )
        good = (
            f"pinned @ `{rev[:7]}`\n"
            "<!-- parity:begin -->\n"
            "| class | state | fields |\n"
            "| --- | --- | --- |\n"
            "| `client-core` | `missing` | `B` |\n"
            "| `relay-server` | `not-a-client-lane` | `C` |\n"
            "<!-- parity:end -->\n"
            "<!-- aliases:begin -->\n"
            "`alias`\n"
            "<!-- aliases:end -->\n"
        )
        with open(doc, "w", encoding="utf-8") as f:
            f.write(good)

        fails, counts = run_check(root)
        if fails or counts["gaps"] != 2:
            print("check-psiphon-parity: self-test baseline failed")
            for line in fails:
                print("  " + line)
            return 1

        def expect(label, want, edit):
            with open(doc, "w", encoding="utf-8") as f:
                f.write(edit(good))
            fails, _ = run_check(root)
            if not fails:
                print(f"check-psiphon-parity: self-test {label} still passes")
                return False
            if not any(want in line for line in fails):
                print(f"check-psiphon-parity: self-test {label} failed for "
                      f"the wrong reason")
                for line in fails:
                    print("  " + line)
                return False
            return True

        cases = [
            ("missing row", "unclassified upstream field(s): B",
             lambda text: text.replace("| `client-core` | `missing` | `B` |\n",
                                       "")),
            ("known field listed", "field(s) not an upstream gap: A",
             lambda text: text.replace("| `client-core` | `missing` | `B` |",
                                       "| `client-core` | `missing` | `B`, `A` |")),
            ("foreign field", "field(s) not in the pinned Config: Z",
             lambda text: text.replace("| `client-core` | `missing` | `B` |",
                                       "| `client-core` | `missing` | `B`, `Z` |")),
            ("duplicate field", "is listed twice",
             lambda text: text.replace(
                 "| `relay-server` | `not-a-client-lane` | `C` |",
                 "| `relay-server` | `not-a-client-lane` | `B` |")),
            ("unknown class", "class 'client-nope' is not one of",
             lambda text: text.replace("`client-core`", "`client-nope`")),
            ("wrong state", "takes state 'missing', not 'not-a-client-lane'",
             lambda text: text.replace(
                 "| `client-core` | `missing` |",
                 "| `client-core` | `not-a-client-lane` |")),
            ("alias drift", "alias spelling(s) not in the map: alias",
             lambda text: text.replace("`alias`\n", "")),
            ("rev drift", "does not cite the pinned rev " + rev[:7],
             lambda text: text.replace(f"`{rev[:7]}`", "`fedcba9`")),
        ]
        for label, want, edit in cases:
            if not expect(label, want, edit):
                return 1
        # The unclassified-field mutation must also touch Config, not the doc.
        with open(doc, "w", encoding="utf-8") as f:
            f.write(good)
        with open(config, "w", encoding="utf-8") as f:
            f.write(
                "package psiphon\n\n"
                "type Config struct {\n"
                "\tA string `json:\",omitempty\"`\n"
                "\tB string `json:\",omitempty\"`\n"
                "\tC string `json:\",omitempty\"`\n"
                "\tD string `json:\",omitempty\"`\n"
                "\t// {\n"
                "\tE bool\n"
                "\t/* } */ F string `json:\"-\"`\n"
                "\tG string `json:\"g\" {\n"
                "// } {\n"
                "`\n"
                "\tH string `json:\",omitempty\"`\n"
                "\tNested struct {\n"
                "\t\tInner string `json:\"inner\"`\n"
                "\t}\n"
                "\tK string `json:\",omitempty\"`\n"
                "}\n"
            )
        fails, _ = run_check(root)
        if not any("unclassified upstream field(s): D, E, G, H, K" in line
                   for line in fails):
            print("check-psiphon-parity: self-test untagged field still passes")
            return 1
        if any("F" in line for line in fails):
            print("check-psiphon-parity: self-test json:\"-\" field is listed")
            return 1
        if any("Inner" in line for line in fails):
            print("check-psiphon-parity: self-test nested field is listed")
            return 1
        print("check-psiphon-parity: self-test passed (ten mutations refused)")
        return 0
    finally:
        shutil.rmtree(root, ignore_errors=True)


def main():
    root = os.environ.get("FERROX_ROOT") or os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
    if "--selftest" in sys.argv[1:]:
        return selftest()
    fails, counts = run_check(root)
    if fails:
        for line in fails:
            print(f"check-psiphon-parity: {line}", file=sys.stderr)
        print(f"check-psiphon-parity: {len(fails)} problem(s)", file=sys.stderr)
        return 1
    print(f"check-psiphon-parity: {counts['upstream']} upstream field(s), "
          f"{counts['known']} accepted spelling(s) "
          f"({counts['known_upstream']} upstream, {counts['aliases']} aliases), "
          f"{counts['gaps']} classified gap(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
