#!/usr/bin/env bash
set -euo pipefail

# Called by cocogitto pre_bump_hooks with {{version}} as $1.
# Updates ALL version references:
#   1. pubspec.yaml  → version: X.Y.Z+BUILD
#   2. pubspec.yaml  → msix_version: X.Y.Z.BUILD
#   3. update_service.dart → currentVersion = 'X.Y.Z'
#   4. flatpak/de.icd360s.mailclient.metainfo.xml → prepend <release>.
#      Without this the AppStream `<releases>` block lags behind the
#      pubspec version, so GNOME Software / KDE Discover think the
#      latest available version is whatever was last listed there —
#      which is what caused the "Update Issue" / "the file detects
#      2.138.7" symptom on 2.140.0 installs.

NEW_VERSION="$1"

# Build number = total commits + 1 (for the upcoming bump commit).
# Monotonically increasing — required by Android versionCode and iOS CFBundleVersion.
BUILD_NUMBER=$(( $(git rev-list --count HEAD) + 1 ))

# Parse semver components
IFS='.' read -r MAJOR MINOR PATCH <<< "$NEW_VERSION"

# 1. pubspec.yaml main version
sed -i "s/^version: .*/version: ${NEW_VERSION}+${BUILD_NUMBER}/" pubspec.yaml

# 2. pubspec.yaml msix_version
sed -i "s/^  msix_version: .*/  msix_version: ${MAJOR}.${MINOR}.${PATCH}.${BUILD_NUMBER}/" pubspec.yaml

# 3. update_service.dart hardcoded currentVersion
sed -i "s/static const String currentVersion = '.*'/static const String currentVersion = '${NEW_VERSION}'/" lib/services/update_service.dart

# 4. flatpak/de.icd360s.mailclient.metainfo.xml — prepend a new <release>
# block under <releases> with today's date. Skipped if the version is
# already declared (idempotent — safe to re-run).
METAINFO="flatpak/de.icd360s.mailclient.metainfo.xml"
TODAY=$(date -u +%Y-%m-%d)
if [ -f "$METAINFO" ] && ! grep -q "version=\"${NEW_VERSION}\"" "$METAINFO"; then
  # Use a Python heredoc instead of sed — preserves indentation and
  # avoids sed-quoting hell on the multi-line replacement.
  python3 - "$METAINFO" "$NEW_VERSION" "$TODAY" <<'PYEOF'
import sys, re
path, version, date = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, 'r', encoding='utf-8') as f:
    xml = f.read()
new_release = (
    f'    <release version="{version}" date="{date}">\n'
    f'      <description>\n'
    f'        <p>Maintenance release. See the GitHub release notes for details.</p>\n'
    f'      </description>\n'
    f'    </release>\n'
)
xml2 = re.sub(r'(<releases>\s*\n)', r'\g<1>' + new_release, xml, count=1)
if xml2 == xml:
    sys.stderr.write(f'WARN: could not find <releases> opening tag in {path}\n')
else:
    with open(path, 'w', encoding='utf-8') as f:
        f.write(xml2)
PYEOF
fi

echo "Updated: version ${NEW_VERSION}+${BUILD_NUMBER}, msix ${MAJOR}.${MINOR}.${PATCH}.${BUILD_NUMBER}, currentVersion '${NEW_VERSION}', metainfo release ${NEW_VERSION}"
