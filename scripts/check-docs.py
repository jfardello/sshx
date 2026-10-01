#!/usr/bin/env python3
"""Check local Markdown navigation, anchors, assets, and publication boundaries."""
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / 'docs'
errors = []


def fail(path, message):
    errors.append(f'{path.relative_to(ROOT)}: {message}')


def prose(path):
    lines = []
    fence = None
    for line in path.read_text().splitlines():
        mark = re.match(r'^\s*(`{3,}|~{3,})', line)
        if mark:
            run = mark[1]
            if fence is None:
                fence = run
            elif run[0] == fence[0] and len(run) >= len(fence):
                fence = None
            continue
        if fence is None:
            lines.append(line)
    if fence:
        fail(path, 'unclosed code fence')
    return '\n'.join(lines)


def anchors(text):
    counts = Counter()
    result = set()
    for heading in re.findall(r'^#{1,6}\s+(.+?)\s*#*$', text, re.M):
        heading = re.sub(r'\[([^]]+)\]\([^)]*\)', r'\1', heading)
        slug = re.sub(r'[^\w\- ]', '', heading.lower()).replace(' ', '-')
        n = counts[slug]
        counts[slug] += 1
        result.add(slug if n == 0 else f'{slug}-{n}')
    return result


files = [ROOT / 'README.md', *sorted(DOCS.rglob('*.md'))]
texts = {p: prose(p) for p in files}
links = re.compile(r'!?\[[^\]\n]*\]\(([^\s)]+)(?:\s+"[^"]*")?\)')
for path, text in texts.items():
    if re.search(r'\b(?:you|your|yours|yourself)\b', text, re.I):
        fail(path, 'direct address; impersonal wording required')
    if re.search(r'\.docs_wip|\bAGENT-\d+\b|\bissue\s*#?\s*\d+\b|github-issues|Implementation validation passed', path.read_text(), re.I):
        fail(path, 'development history in published documentation')
    for target in links.findall(text):
        url = urlsplit(target)
        if url.scheme or url.netloc:
            continue
        if url.path.startswith('/'):
            fail(path, f'root-relative link is not portable to GitHub: {target}')
            continue
        dest = (path.parent / unquote(url.path)).resolve() if url.path else path
        if not dest.is_relative_to(ROOT):
            fail(path, f'link outside repository: {target}')
        elif not dest.is_file():
            fail(path, f'missing link: {target}')
        elif url.fragment and dest.suffix == '.md':
            if unquote(url.fragment) not in anchors(texts.get(dest, prose(dest))):
                fail(path, f'missing anchor: {target}')

sidebar = (DOCS / '_sidebar.md').read_text()
listed = {(DOCS / urlsplit(t).path).resolve() for t in links.findall(sidebar) if not urlsplit(t).scheme}
for path in texts:
    if path.is_relative_to(DOCS) and not path.name.startswith('_') and path not in listed:
        fail(path, 'page missing from sidebar')


class Assets(HTMLParser):
    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        value = attrs.get('src') if tag == 'script' else attrs.get('href') if tag == 'link' else None
        if value and not urlsplit(value).scheme:
            if not (DOCS / value).is_file():
                fail(DOCS / 'index.html', f'missing asset: {value}')


Assets().feed((DOCS / 'index.html').read_text())
for path in DOCS.rglob('*'):
    if path.is_symlink():
        fail(path, 'Pages artifact must not contain symlinks')
if not (DOCS / '.nojekyll').is_file():
    fail(DOCS, 'missing .nojekyll')
if errors:
    print('\n'.join(errors), file=sys.stderr)
    sys.exit(1)
print(f'Documentation checks passed ({len(files)} Markdown files).')
