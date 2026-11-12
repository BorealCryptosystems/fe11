#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Render trusted repository documentation and attach a Rustdoc tree.

Requires Python 3.11+ and rustdoc. Writes a new output directory only. Markdown
rendering does not execute examples. Deployment uses the separate Pages workflow.
"""
import argparse
import html
import os
from pathlib import Path
import re
import shutil
import subprocess
from urllib.parse import unquote, urlsplit

VERSION = "0.1.0"
SITE = "https://borealcryptosystems.github.io/fe11/"
STYLE = """<style>
:root{color-scheme:light dark;--accent:#176e69;--border:#c5d5d3}
*{box-sizing:border-box}body{max-width:1120px;margin:auto;padding:24px;
font:17px/1.65 system-ui,sans-serif;color:#203738;background:#f7faf9}
a{color:#075e83;text-underline-offset:3px}a:hover{color:#157563}
nav{display:flex;flex-wrap:wrap;gap:12px 28px;border-bottom:1px solid var(--border);
padding:12px 0 22px;margin-bottom:36px}nav strong{margin-right:auto;color:var(--accent)}
h1,h2,h3{line-height:1.25;letter-spacing:-.025em}h1{font-size:2.4rem}
h2{margin-top:2.3rem}p,li{max-width:90ch}pre{overflow:auto;padding:20px;
background:#eaf0ef;border:1px solid var(--border);border-radius:8px;line-height:1.5}
code{font-size:.89em}table{border-collapse:collapse;display:block;overflow:auto;
margin:20px 0}th,td{text-align:left;padding:10px 14px;border:1px solid var(--border)}
th{background:#e4efec}footer{margin-top:48px;padding-top:20px;border-top:1px solid
var(--border);font-size:.9rem}.section-header a{color:inherit}
@media(prefers-color-scheme:dark){body{background:#152226;color:#e5eeee}
a{color:#8bd2e7}nav strong{color:#88d4c5}pre,th{background:#203337}}
@media(max-width:650px){body{padding:16px;font-size:16px}h1{font-size:2rem}}
</style>"""


def relative(target, origin):
    return os.path.relpath(target, origin).replace(os.sep, "/")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rustdoc", default="rustdoc")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    api = args.api_dir.resolve()
    if (output.exists() or output.is_relative_to(repo) or repo.is_relative_to(output) or
            output.is_relative_to(api) or api.is_relative_to(output)):
        parser.error("Output must be new and disjoint from the source and API trees")
    for crate in ("fe11", "fe11_sys", "fe11_verify_engine_api", "fe11_verify_engine"):
        if not (api / crate / "index.html").is_file():
            parser.error("API tree must contain all four crate indexes")
    if any(p.is_symlink() for p in api.rglob("*")):
        parser.error("API tree must contain regular files and directories")
    version = output / VERSION
    version.mkdir(parents=True)
    shutil.copytree(api, version / "api")
    shutil.copytree(repo / "library/examples/how_to", version / "library/examples/how_to")
    shutil.copyfile(repo / "library/examples/how_to.rs", version / "library/examples/how_to.rs")
    docs = sorted(set(repo.glob("*.md")) | set((repo / "library/docs").rglob("*.md")) |
                  {repo / "verify-engine/README.md", repo / "verify-engine-api/README.md"})
    if any(p.is_symlink() or not p.resolve().is_relative_to(repo) for p in docs):
        parser.error("Documentation inputs must be regular files inside the repository")
    mapping = {p.resolve(): version / p.relative_to(repo).with_suffix(".html") for p in docs}
    work = output / "_render"
    work.mkdir()
    header = work / "header.html"
    header.write_text(STYLE, encoding="utf8")
    before = work / "before.html"
    after = work / "after.html"
    after.write_text("<footer>Fe11 0.1.0 · Boreal Cryptosystems · Apache-2.0</footer>", encoding="utf8")

    def resolve_link(value, source, destination):
        if value.startswith(SITE):
            site_path = value[len(SITE):].split("#")[0]
            if not site_path or site_path.endswith("/"):
                site_path += "index.html"
            return relative(output / site_path, destination.parent) + (
                "#" + value.split("#", 1)[1] if "#" in value else "")
        parts = urlsplit(value)
        if parts.scheme or parts.netloc or not parts.path:
            return value
        target = (source.parent / unquote(parts.path)).resolve()
        if not target.is_relative_to(repo) or not target.is_file():
            raise ValueError(f"Unresolved or external local link: {source}: {value}")
        if target in mapping:
            result = mapping[target]
        else:
            result = version / target.relative_to(repo)
            result.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(target, result)
        return relative(result, destination.parent) + ("#" + parts.fragment if parts.fragment else "")

    for source in docs:
        destination = mapping[source.resolve()]
        destination.parent.mkdir(parents=True, exist_ok=True)
        links = [("Home", version / "index.html"),
                 ("How To", version / "library/docs/how-to/index.html"),
                 ("API reference", version / "api/index.html"),
                 ("Verification engine", version / "verify-engine/README.html")]
        before.write_text('<nav aria-label="Documentation"><strong>Fe11 / 0.1.0</strong>' +
                          ''.join(f'<a href="{relative(p, destination.parent)}">{name}</a>'
                                  for name, p in links) + '</nav>', encoding="utf8")
        # Included API fragments may have no standalone document title.
        markdown = source.read_text(encoding="utf8")
        if not markdown.startswith(("# ", "%")):
            markdown = "# " + source.stem.replace("-", " ") + "\n\n" + markdown
        rendered_input = work / source.name
        rendered_input.write_text(markdown, encoding="utf8")
        # Rustdoc owns Markdown parsing and code highlighting; no example executes.
        subprocess.run([args.rustdoc, str(rendered_input), "--markdown-no-toc",
                        "--html-in-header", str(header), "--html-before-content", str(before),
                        "--html-after-content", str(after), "-o", str(destination.parent)],
                       check=True)
        rendered = destination.read_text(encoding="utf8")
        # Rewrite only source-content links: navigation already targets the site.
        start = rendered.index('</nav>') + len('</nav>')
        prefix, body = rendered[:start], rendered[start:]
        body = re.sub(r'\b(href|src)="([^"]+)"',
                      lambda m: m[1] + '="' + html.escape(resolve_link(
                          html.unescape(m[2]), source, destination), quote=True) + '"', body)
        destination.write_text(prefix + body, encoding="utf8")
    landing = mapping[(repo / "README.md").resolve()].read_text(encoding="utf8")
    (version / "index.html").write_text(landing, encoding="utf8")
    (output / "index.html").write_text(
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>Fe11 documentation</title>' + STYLE + '<body><h1>Fe11 documentation</h1>'
        '<p>Rust PKCS#11 interfaces, usage recipes and API reference.</p>'
        '<p><a href="0.1.0/index.html">Fe11 0.1.0 documentation</a></p>'
        '<p><a href="0.1.0/library/docs/how-to/index.html">How To</a> · '
        '<a href="0.1.0/api/index.html">API reference</a></p></body></html>', encoding="utf8")
    # Only the known, newly-created renderer scratch directory is removed.
    if work.resolve().parent != output:
        raise ValueError("Unexpected scratch location")
    shutil.rmtree(work)
    print(f"Rendered {len(docs)} guides; HTML entry: {output / 'index.html'}")


if __name__ == "__main__":
    main()
