#!/usr/bin/env bash
set -euo pipefail

# Called by cocogitto pre_bump_hooks with {{version}} as $1.
# Updates ALL version references:
#   1. pubspec.yaml  → version: X.Y.Z+BUILD
#   2. pubspec.yaml  → msix_version: X.Y.Z.BUILD
#   3. update_service.dart → currentVersion = 'X.Y.Z'

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

echo "Updated: version ${NEW_VERSION}+${BUILD_NUMBER}, msix ${MAJOR}.${MINOR}.${PATCH}.${BUILD_NUMBER}, currentVersion '${NEW_VERSION}'"
