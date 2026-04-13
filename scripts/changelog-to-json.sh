#!/bin/bash
# Convert CHANGELOG.md (cocogitto format) to changelog.json for the client app.
# Input: CHANGELOG.md in repo root
# Output: JSON to stdout (pipe to file)
#
# Format expected by ChangelogService.fetchChangelog():
#   { "versions": [ { "title": "...", "entries": ["...", "..."] } ] }

set -euo pipefail

CHANGELOG="${1:-CHANGELOG.md}"

if [ ! -f "$CHANGELOG" ]; then
  echo '{"versions":[]}'
  exit 0
fi

python3 -c "
import json, re, sys

with open('$CHANGELOG') as f:
    content = f.read()

versions = []
# Split on version headers: ## vX.Y.Z - YYYY-MM-DD
parts = re.split(r'^## (v[\d.]+ - \d{4}-\d{2}-\d{2})', content, flags=re.MULTILINE)

# parts[0] is before first version header, skip it
# parts[1], parts[2] = title, body; parts[3], parts[4] = title, body; etc.
for i in range(1, len(parts) - 1, 2):
    title = parts[i].strip()
    body = parts[i + 1].strip()

    entries = []
    current_section = ''

    for line in body.split('\n'):
        line = line.strip()
        if line.startswith('####'):
            current_section = line.replace('####', '').strip()
        elif line.startswith('- ') and line != '- - -':
            # Extract the meaningful part: remove commit hash and author
            entry = line[2:].strip()
            if entry == '- -' or entry == '-' or not entry:
                continue
            # Remove trailing ' - (hash) - author' pattern
            entry = re.sub(r'\s*-\s*\([a-f0-9]+\)\s*-\s*.*$', '', entry)
            if entry and entry != '-':
                if current_section:
                    entries.append(f'{current_section}: {entry}')
                else:
                    entries.append(entry)

    if entries:
        versions.append({
            'title': title,
            'entries': entries
        })

json.dump({'versions': versions}, sys.stdout, indent=2, ensure_ascii=False)
"
