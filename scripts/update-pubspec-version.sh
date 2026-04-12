#!/usr/bin/env bash
set -euo pipefail

# Called by cocogitto pre_bump_hooks with {{version}} as $1.
# Updates pubspec.yaml version + build number + msix_version.

NEW_VERSION="$1"

# Build number = total commits + 1 (for the upcoming bump commit).
# Monotonically increasing — required by Android versionCode and iOS CFBundleVersion.
BUILD_NUMBER=$(( $(git rev-list --count HEAD) + 1 ))

# Parse semver components
IFS='.' read -r MAJOR MINOR PATCH <<< "$NEW_VERSION"

# Update main version line: version: X.Y.Z+BUILD
sed -i "s/^version: .*/version: ${NEW_VERSION}+${BUILD_NUMBER}/" pubspec.yaml

# Update msix_version: W.X.Y.Z (Windows MSIX format)
sed -i "s/^  msix_version: .*/  msix_version: ${MAJOR}.${MINOR}.${PATCH}.${BUILD_NUMBER}/" pubspec.yaml

echo "pubspec.yaml updated: version ${NEW_VERSION}+${BUILD_NUMBER}, msix_version ${MAJOR}.${MINOR}.${PATCH}.${BUILD_NUMBER}"
