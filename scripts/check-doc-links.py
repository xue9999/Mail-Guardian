#!/usr/bin/env python3
"""Check repository-relative Markdown file links without making network calls."""
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

root = Path(__file__).resolve().parents[1]
errors = []
for file in sorted(root.rglob('*.md')):
    relative = file.relative_to(root)
    if any(part in {'.git', '.build', 'bin', 'dist', '__pycache__'} for part in relative.parts):
        continue
    text = re.sub(r'```.*?```', '', file.read_text(), flags=re.S)
    for match in re.finditer(r'\]\((<[^>]+>|[^\s)]+)(?:\s+"[^"]*")?\)', text):
        raw = match.group(1).strip('<>')
        parsed = urlsplit(raw)
        if parsed.scheme or parsed.netloc or not parsed.path:
            continue
        target = (file.parent / unquote(parsed.path)).resolve()
        if not target.is_relative_to(root) or not target.exists():
            errors.append(f'{relative}: missing repository link {raw}')
if errors:
    print('\n'.join(errors), file=sys.stderr)
    raise SystemExit(1)
print('Repository-relative documentation links passed.')
