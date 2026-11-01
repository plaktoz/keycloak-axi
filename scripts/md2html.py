"""Stdlib-only Markdown to HTML for README.md (subset used by that file)."""
import html
import re
import sys

SRC, DST = sys.argv[1], sys.argv[2]

CSS = """
:root{--bg:#ffffff;--fg:#1b1f24;--muted:#57606a;--line:#d0d7de;--code-bg:#f6f8fa;--accent:#0b5cad;--quote:#eef4fb}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){--bg:#0d1117;--fg:#e6edf3;--muted:#9aa4b0;--line:#30363d;--code-bg:#161b22;--accent:#58a6ff;--quote:#12202f}}
:root[data-theme="dark"]{--bg:#0d1117;--fg:#e6edf3;--muted:#9aa4b0;--line:#30363d;--code-bg:#161b22;--accent:#58a6ff;--quote:#12202f}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px 64px}
h1,h2,h3{line-height:1.25}
h2{border-bottom:1px solid var(--line);padding-bottom:.3em;margin-top:2em}
a{color:var(--accent)}
code{background:var(--code-bg);padding:.1em .3em;border-radius:4px;font:0.9em ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}
td code,th code{overflow-wrap:break-word;white-space:normal}
pre{background:var(--code-bg);padding:12px;border-radius:6px;overflow-x:auto}
pre code{padding:0;background:none}
blockquote{margin:1em 0;padding:.5em 1em;background:var(--quote);border-left:4px solid var(--accent)}
table{border-collapse:collapse;display:block;overflow-x:auto;margin:1em 0}
th,td{border:1px solid var(--line);padding:6px 10px;vertical-align:top;text-align:left}
th{background:var(--code-bg)}
hr{border:0;border-top:1px solid var(--line)}
nav.toc{background:var(--code-bg);padding:8px 16px;border-radius:6px;margin:1em 0}
nav.toc ol{margin:.3em 0;padding-left:1.4em}
"""


def slug(text, seen):
    s = re.sub(r"`", "", text).lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-") or "section"
    base, i = s, 2
    while s in seen:
        s = f"{base}-{i}"
        i += 1
    seen.add(s)
    return s


def inline(t):
    codes = []

    def keep(m):
        codes.append(m.group(1))
        return f"\x00{len(codes)-1}\x00"

    t = re.sub(r"`([^`]+)`", keep, t)
    t = html.escape(t, quote=False)
    t = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", t)
    t = re.sub(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])", r"<em>\1</em>", t)

    def link(m):
        href = m.group(2)
        if href.startswith("#"):
            pass
        return f'<a href="{href}">{m.group(1)}</a>'

    t = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", link, t)
    t = re.sub(r"\x00(\d+)\x00", lambda m: f"<code>{html.escape(codes[int(m.group(1))], quote=False)}</code>", t)
    return t


def split_row(line):
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    line = line.replace("\\|", "\x01")
    cells, cur, in_code = [], "", False
    for ch in line:
        if ch == "`":
            in_code = not in_code
        if ch == "\x01":
            cur += "|"
        elif ch == "|" and not in_code:
            cells.append(cur.strip())
            cur = ""
        else:
            cur += ch
    cells.append(cur.strip())
    return cells


LIST_RE = re.compile(r"^(\s*)([-*]|\d+\.)\s+(.*)$")


def render_list(lines, i):
    """Render a (possibly nested) list starting at lines[i]. Returns (html, next_i)."""
    m = LIST_RE.match(lines[i])
    base = len(m.group(1))
    ordered = m.group(2)[0].isdigit()
    tag = "ol" if ordered else "ul"
    out = [f"<{tag}>"]
    while i < len(lines):
        m = LIST_RE.match(lines[i])
        if not m or len(m.group(1)) < base:
            break
        if len(m.group(1)) > base:
            break
        item = m.group(3)
        i += 1
        extra = []
        while i < len(lines):
            nxt = lines[i]
            nm = LIST_RE.match(nxt)
            if nm and len(nm.group(1)) > base:
                sub, i = render_list(lines, i)
                extra.append(sub)
            elif nxt.strip() and not nm and (len(nxt) - len(nxt.lstrip())) > base:
                item += " " + nxt.strip()
                i += 1
            else:
                break
        out.append(f"<li>{inline(item)}{''.join(extra)}</li>")
    out.append(f"</{tag}>")
    return "".join(out), i


def main():
    lines = open(SRC, encoding="utf-8").read().splitlines()
    seen, toc, body = set(), [], []
    title = "kc-axi"
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            lang = line[3:].strip()
            i += 1
            buf = []
            while i < len(lines) and not lines[i].startswith("```"):
                buf.append(lines[i])
                i += 1
            i += 1
            body.append(f'<pre><code class="lang-{html.escape(lang)}">{html.escape(chr(10).join(buf), quote=False)}</code></pre>')
            continue
        m = re.match(r"^(#{1,3})\s+(.*)$", line)
        if m:
            level, text = len(m.group(1)), m.group(2)
            hid = slug(text, seen)
            if level == 2:
                toc.append((hid, text))
            body.append(f'<h{level} id="{hid}">{inline(text)}</h{level}>')
            i += 1
            continue
        if line.strip() == "---":
            body.append("<hr>")
            i += 1
            continue
        if line.startswith(">"):
            buf = []
            while i < len(lines) and lines[i].startswith(">"):
                buf.append(lines[i][1:].strip())
                i += 1
            body.append("<blockquote>" + "".join(f"<p>{inline(b)}</p>" for b in buf if b) + "</blockquote>")
            continue
        if line.startswith("|") and i + 1 < len(lines) and re.match(r"^\|[\s:|-]+\|\s*$", lines[i + 1]):
            head = split_row(line)
            i += 2
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append(split_row(lines[i]))
                i += 1
            t = ["<table><thead><tr>" + "".join(f"<th>{inline(c)}</th>" for c in head) + "</tr></thead><tbody>"]
            for r in rows:
                t.append("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in r) + "</tr>")
            t.append("</tbody></table>")
            body.append("".join(t))
            continue
        if LIST_RE.match(line):
            h, i = render_list(lines, i)
            body.append(h)
            continue
        if not line.strip():
            i += 1
            continue
        buf = [line.strip()]
        i += 1
        while i < len(lines) and lines[i].strip() and not re.match(r"^(#|```|>|\||---$)", lines[i]) and not LIST_RE.match(lines[i]):
            buf.append(lines[i].strip())
            i += 1
        body.append(f"<p>{inline(' '.join(buf))}</p>")

    toc_html = '<nav class="toc" aria-label="Contents"><strong>Contents</strong><ol>' + "".join(
        f'<li><a href="#{h}">{inline(t)}</a></li>' for h, t in toc
    ) + "</ol></nav>"
    # insert the contents after the first blockquote block
    idx = next((k for k, b in enumerate(body) if b.startswith("<blockquote>")), 0)
    body.insert(idx + 1, toc_html)
    doc = (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{title}</title><style>{CSS}</style></head><body><main>\n"
        + "\n".join(body)
        + "\n</main></body></html>\n"
    )
    open(DST, "w", encoding="utf-8").write(doc)


main()
