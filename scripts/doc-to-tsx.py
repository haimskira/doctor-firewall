#!/usr/bin/env python3
"""Convert a static HTML document into a React component (no raw HTML at runtime).

    python scripts/doc-to-tsx.py <input.html> <output.tsx> <ComponentName>

The UI forbids ``dangerouslySetInnerHTML`` (XSS), so in-app documents are compiled into JSX.
Only a fixed set of tags and attributes is accepted; anything else (scripts, styles, event
handlers, links, inline styles) stops the conversion. Text becomes JSON string literals, so
no character of the source can turn into code. ``class`` names are prefixed with ``doc-``.
"""

from __future__ import annotations

import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path

TAGS = {
    "div", "header", "p", "h1", "h2", "h3", "h4", "ul", "ol", "li", "table", "thead", "tbody",
    "tr", "th", "td", "code", "strong", "em", "pre", "br",
    "svg", "defs", "marker", "g", "path", "rect", "line", "text", "circle", "polyline", "tspan",
}
SKIP = {"html", "head", "body", "meta", "title", "style"}  # document shell: dropped
VOID = {"br", "meta"}
ATTRS = {
    "class": "className", "viewbox": "viewBox", "role": "role", "aria-label": "aria-label",
    "font-size": "fontSize", "font-weight": "fontWeight", "text-anchor": "textAnchor",
    "id": "id", "refx": "refX", "refy": "refY", "markerwidth": "markerWidth",
    "markerheight": "markerHeight", "orient": "orient", "d": "d", "fill": "fill",
    "stroke": "stroke", "stroke-width": "strokeWidth", "stroke-dasharray": "strokeDasharray",
    "marker-end": "markerEnd", "marker-start": "markerStart", "x": "x", "y": "y",
    "x1": "x1", "y1": "y1", "x2": "x2", "y2": "y2", "width": "width", "height": "height",
    "rx": "rx", "ry": "ry", "cx": "cx", "cy": "cy", "r": "r", "points": "points",
    "dominant-baseline": "dominantBaseline", "opacity": "opacity", "dx": "dx", "dy": "dy",
    "fill-opacity": "fillOpacity", "stroke-opacity": "strokeOpacity",
    "stroke-linecap": "strokeLinecap", "stroke-linejoin": "strokeLinejoin", "colspan": "colSpan", "rowspan": "rowSpan", "transform": "transform",
}
SAFE_VALUE = re.compile(r"^[^<>{}`\\]*$")


class Converter(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.stack: list[str] = []
        self.skipping = 0  # inside <head>/<style>/<title>
        self.pre = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("head", "style", "title", "script"):
            if tag == "script":
                raise SystemExit("refusing <script>")
            self.skipping += 1
            return
        if self.skipping or tag in SKIP:
            return
        if tag not in TAGS:
            raise SystemExit(f"tag <{tag}> is not allowed")
        parts = [tag]
        for name, value in attrs:
            jsx = ATTRS.get(name)
            if jsx is None:
                raise SystemExit(f"attribute {name!r} on <{tag}> is not allowed")
            value = value or ""
            if not SAFE_VALUE.match(value) or value.lower().startswith("javascript"):
                raise SystemExit(f"unsafe attribute value {value!r}")
            if name == "class":
                value = " ".join(f"doc-{c}" for c in value.split())
            parts.append(f"{jsx}={json.dumps(value, ensure_ascii=False)}")
        if tag in VOID:
            self.out.append("<" + " ".join(parts) + " />")
            return
        if tag == "pre":
            self.pre += 1
        self.out.append("<" + " ".join(parts) + ">")
        self.stack.append(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag in ("head", "style", "title"):
            self.skipping -= 1
            return
        if self.skipping or tag in SKIP or tag in VOID:
            return
        if not self.stack or self.stack[-1] != tag:
            raise SystemExit(f"unbalanced </{tag}> (open: {self.stack[-3:]})")
        self.stack.pop()
        if tag == "pre":
            self.pre -= 1
        self.out.append(f"</{tag}>")

    def handle_data(self, data: str) -> None:
        if self.skipping or not self.stack:
            return
        if not self.pre:
            data = re.sub(r"\s+", " ", data)
            if data.strip() == "" and self.stack[-1] not in ("p", "li", "td", "th", "strong", "em", "code", "h1", "h2", "h3", "h4", "text", "tspan"):
                return
        if data:
            self.out.append("{" + json.dumps(data, ensure_ascii=False) + "}")


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    source, target, name = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    if not re.fullmatch(r"[A-Z][A-Za-z0-9]{1,40}", name):
        raise SystemExit("component name must be PascalCase")
    conv = Converter()
    conv.feed(source.read_text(encoding="utf-8"))
    conv.close()
    if conv.stack:
        raise SystemExit(f"unclosed tags: {conv.stack}")
    body = "\n".join(conv.out)
    target.write_text(
        f"// Generated by scripts/doc-to-tsx.py from {source.as_posix()} — edit the source, not this file.\n"
        f"export function {name}() {{\n  return (\n    <>\n{body}\n    </>\n  );\n}}\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"{target}: {len(body)} chars")


if __name__ == "__main__":
    main()
