#!/usr/bin/env python3
"""Regenerate the generated regions of `docs/index.html` from `docs/*.md`.

The documentation portal is a single static page: the sidebar, the metadata map
(`DOCS_META`) and the inlined markdown bodies (`DOCS_CONTENT`) all have to agree
with the files in `docs/`. Hand-editing three copies is how a portal ends up
advertising documents that no longer exist, so those three regions are generated
from the table below and this script is the only thing that should write them.

Usage (from the repository root):

    python scripts/build_docs_portal.py          # rewrite docs/index.html
    python scripts/build_docs_portal.py --check   # exit 1 if it is out of date

A document is added by adding one entry to DOCS, in the order it should appear
in the sidebar. `docs` in the table maps a category to its documents; every
listed file must exist (the script refuses to run otherwise, so a renamed doc
cannot silently disappear from the portal).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = REPO_ROOT / "docs"
PORTAL = DOCS_DIR / "index.html"

SIDEBAR_BEGIN = "<!-- BEGIN GENERATED SIDEBAR (scripts/build_docs_portal.py) -->"
SIDEBAR_END = "<!-- END GENERATED SIDEBAR -->"
META_BEGIN = "/* BEGIN GENERATED DOCS_META (scripts/build_docs_portal.py) */"
META_END = "/* END GENERATED DOCS_META */"
CONTENT_BEGIN = "/* BEGIN GENERATED DOCS_CONTENT (scripts/build_docs_portal.py) */"
CONTENT_END = "/* END GENERATED DOCS_CONTENT */"

# (category, sidebar title, [(id, file, title, short sidebar label, description)])
#
# The category order here is the sidebar order. Descriptions are one sentence and
# are shown as the document's standfirst, so they are part of the docs surface:
# keep them honest about what is shipped versus planned.
DOCS: list[tuple[str, list[tuple[str, str, str, str, str]]]] = [
    (
        "Specifications",
        [
            (
                "specifications",
                "SPECIFICATIONS.md",
                "Protocol Specifications",
                "Protocol Specs",
                "Formal frame structures, ChaCha20-Poly1305 packet envelopes, "
                "Reed-Solomon RS(2,1) encoding, and replay sliding window specifications.",
            ),
            (
                "sota",
                "SOTA.md",
                "State of the Art (SOTA) Architectural Benchmark",
                "SOTA Benchmark Matrix",
                "Definitive architectural and cryptographic benchmark matrix comparing "
                "Vantablack against WireGuard, Tailscale, Tor, and commercial VPN systems.",
            ),
        ],
    ),
    (
        "Architecture",
        [
            (
                "crypto",
                "CRYPTOGRAPHY_DEEP_DIVE.md",
                "Cryptography Deep Dive",
                "Cryptography Deep Dive",
                "Mathematical proofs, ML-KEM-768 (Kyber) + X25519 hybrid KEM, Ed25519 "
                "signing, and RAM-locked volatile zeroization.",
            ),
            (
                "onion",
                "ONION_ARCHITECTURE.md",
                "Clean-Room Onion Routing",
                "Clean-Room Onion Routing",
                "Datagram-native onion encapsulation over UDP without TCP circuit stalls "
                "or centralized directory authority bottlenecks.",
            ),
        ],
    ),
    (
        "Networking &amp; VPN",
        [
            (
                "lan-over-wan",
                "LAN_OVER_WAN.md",
                "LAN over WAN (VPN Layer)",
                "LAN over WAN (VPN Layer)",
                "Cross-datacenter virtual Ethernet and L2/L3 tunneling across heterogeneous "
                "public internet connections with transparent packet sharding.",
            ),
        ],
    ),
]


def _flatten() -> list[tuple[str, str, str, str, str, str]]:
    """`DOCS` as a flat list of (category, id, file, title, label, desc)."""
    out = []
    for category, entries in DOCS:
        for doc_id, file_name, title, label, desc in entries:
            out.append((category, doc_id, file_name, title, label, desc))
    return out


def _js_literal(text: str) -> str:
    """`text` as a JavaScript string literal.

    `json.dumps` escaping is valid JavaScript, and `ensure_ascii=False` keeps the
    documents readable; only the two characters JSON leaves literal but which are
    illegal inside a `<script>` block need neutralising.
    """
    return (
        json.dumps(text, ensure_ascii=False)
        .replace("</script", "<\\/script")
        .replace("<!--", "<\\!--")
    )


def build_sidebar() -> str:
    lines: list[str] = []
    for category, entries in DOCS:
        lines.append('        <div class="sidebar-group">')
        lines.append(f'          <div class="sidebar-title">{category}</div>')
        lines.append('          <ul class="sidebar-menu">')
        for i, (doc_id, _file, _title, label, _desc) in enumerate(entries):
            active = " active" if (category, i) == ("Specifications", 0) else ""
            lines.append("            <li>")
            lines.append(
                f'              <a href="#{doc_id}" class="doc-link{active}" '
                f'data-id="{doc_id}">{label}</a>'
            )
            lines.append("            </li>")
        lines.append("          </ul>")
        lines.append("        </div>")
    return "\n".join(lines)


def build_meta() -> str:
    meta = {}
    for _category, doc_id, file_name, title, _label, desc in _flatten():
        meta[doc_id] = {
            "id": doc_id,
            "file": file_name,
            "title": title,
            "category": next(
                c
                for c, entries in DOCS
                if any(e[0] == doc_id for e in entries)
            )
            # The sidebar label already carries the HTML entity for "&"; the
            # category string is injected via textContent, which would show the
            # entity literally, so strip it back to a plain ampersand.
            .replace("&amp;", "&"),
            "desc": desc,
        }
    # `JSON.parse("…")` rather than a bare object literal: the documents contain
    # every quote, newline and backslash imaginable, and parsing one JSON string
    # is far harder to get subtly wrong than emitting JavaScript.
    return (
        "    const DOCS_META = JSON.parse("
        + _js_literal(json.dumps(meta, ensure_ascii=False))
        + ");"
    )


def build_content() -> str:
    content = {}
    for _category, doc_id, file_name, _title, _label, _desc in _flatten():
        path = DOCS_DIR / file_name
        if not path.is_file():
            raise SystemExit(f"docs/{file_name} is listed in the portal but does not exist")
        content[doc_id] = _read_markdown(path)
    return (
        "    const DOCS_CONTENT = JSON.parse("
        + _js_literal(json.dumps(content, ensure_ascii=False))
        + ");"
    )


def _read_markdown(path: Path) -> str:
    """Markdown with a BOM stripped and CRLF normalised (marked.js prefers LF)."""
    text = path.read_text(encoding="utf-8-sig")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _replace_region(text: str, begin: str, end: str, body: str) -> str:
    """Replace what is between two marker comments, keeping their indentation."""
    start = text.index(begin)
    stop = text.index(end)
    if stop < start:
        raise SystemExit(f"portal markers are out of order: {begin!r} after {end!r}")
    begin_line = text.rfind("\n", 0, start) + 1
    end_line = text.rfind("\n", 0, stop) + 1
    return (
        text[:begin_line]
        + text[begin_line:start]
        + begin
        + "\n"
        + body.rstrip("\n")
        + "\n"
        + text[end_line:stop]
        + text[stop:]
    )


def render(portal: str) -> str:
    portal = _replace_region(portal, SIDEBAR_BEGIN, SIDEBAR_END, build_sidebar())
    portal = _replace_region(portal, META_BEGIN, META_END, build_meta())
    return _replace_region(portal, CONTENT_BEGIN, CONTENT_END, build_content())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="do not write; exit 1 when docs/index.html is out of date",
    )
    args = parser.parse_args()

    original = PORTAL.read_text(encoding="utf-8")
    updated = render(original)

    if args.check:
        if original != updated:
            print("docs/index.html is out of date — run scripts/build_docs_portal.py")
            return 1
        print("docs/index.html is up to date")
        return 0

    if original == updated:
        print("docs/index.html already up to date")
        return 0
    PORTAL.write_text(updated, encoding="utf-8")
    print(f"wrote {PORTAL.relative_to(REPO_ROOT)} ({len(updated)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
