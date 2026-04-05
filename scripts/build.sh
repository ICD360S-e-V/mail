#!/usr/bin/env bash
#
# ICD360S Mail Client - Multi-Platform Build Script
# Usage: ./scripts/build.sh [platform] [options]
#
# Platforms:
#   all          Build everything (all platforms + all Android flavors)
#   android      All Android flavors (universal, fdroid, googleplay, huawei, samsung)
#   android:universal   Universal APK (fat, all ABIs) - direct distribution
#   android:fdroid      F-Droid APK (no proprietary deps)
#   android:googleplay  Google Play AAB (Android App Bundle)
#   android:huawei      Huawei AppGallery APK
#   android:samsung     Samsung Galaxy Store APK
#   ios          iOS build (requires macOS + Xcode)
#   macos        macOS build (requires macOS)
#   windows      Windows build (requires Windows)
#   linux        Linux build (requires Linux)
#
# Options:
#   --split-abi        Split APKs per ABI (arm64, armv7, x86_64) - Android only
#   --clean            Run flutter clean before building
#   --verbose          Verbose output
#   --output DIR       Custom output directory (default: build/dist)
#   --version VER      Override version (reads from pubspec.yaml by default)
#
# Examples:
#   ./scripts/build.sh all
#   ./scripts/build.sh android
#   ./scripts/build.sh android:googleplay
#   ./scripts/build.sh linux macos
#   ./scripts/build.sh android --split-abi
#

set -euo pipefail

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$PROJECT_DIR/build/dist"
FLUTTER="${FLUTTER_BIN:-flutter}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Defaults
SPLIT_ABI=false
DO_CLEAN=false
VERBOSE=false
VERSION=""
PLATFORMS=()

# ──────────────────────���───────────────────────
# Helpers
# ───────────────────��──────────────────────────
log()   { echo -e "${BLUE}[BUILD]${NC} $*"; }
ok()    { echo -e "${GREEN}[  OK ]${NC} $*"; }
warn()  { echo -e "${YELLOW}[ WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
step()  { echo -e "\n${CYAN}━━━ $* ━━━${NC}"; }

get_version() {
    if [[ -n "$VERSION" ]]; then
        echo "$VERSION"
    else
        grep '^version:' "$PROJECT_DIR/pubspec.yaml" | head -1 | sed 's/version: //' | cut -d'+' -f1
    fi
}

get_build_number() {
    grep '^version:' "$PROJECT_DIR/pubspec.yaml" | head -1 | sed 's/.*+//'
}

check_platform() {
    local os
    os="$(uname -s)"
    case "$1" in
        macos|ios)
            if [[ "$os" != "Darwin" ]]; then
                err "$1 builds require macOS. Current OS: $os"
                return 1
            fi
            ;;
        windows)
            if [[ "$os" != "MINGW"* && "$os" != "MSYS"* && "$os" != "CYGWIN"* && "$os" != "Windows"* ]]; then
                warn "Windows builds typically require Windows. Current OS: $os (may work in CI)"
            fi
            ;;
        linux)
            if [[ "$os" != "Linux" ]]; then
                err "Linux builds require Linux. Current OS: $os"
                return 1
            fi
            ;;
    esac
    return 0
}

flutter_cmd() {
    if $VERBOSE; then
        $FLUTTER "$@"
    else
        $FLUTTER "$@" 2>&1
    fi
}

# ───────────────��──────────────────────────────
# Parse arguments
# ───���───────────────────���──────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --split-abi)  SPLIT_ABI=true; shift ;;
        --clean)      DO_CLEAN=true; shift ;;
        --verbose)    VERBOSE=true; shift ;;
        --output)     OUTPUT_DIR="$2"; shift 2 ;;
        --version)    VERSION="$2"; shift 2 ;;
        --help|-h)
            head -35 "$0" | tail -33
            exit 0
            ;;
        *)  PLATFORMS+=("$1"); shift ;;
    esac
done

# Default to showing help if no platforms specified
if [[ ${#PLATFORMS[@]} -eq 0 ]]; then
    echo "Usage: $0 [platform...] [options]"
    echo "Run '$0 --help' for full usage."
    exit 1
fi

# Expand 'all' and 'android'
EXPANDED=()
for p in "${PLATFORMS[@]}"; do
    case "$p" in
        all)
            EXPANDED+=(linux windows macos ios android:universal android:fdroid android:googleplay android:huawei android:samsung)
            ;;
        android)
            EXPANDED+=(android:universal android:fdroid android:googleplay android:huawei android:samsung)
            ;;
        *)
            EXPANDED+=("$p")
            ;;
    esac
done
PLATFORMS=("${EXPANDED[@]}")

# ─���────────────────────────────────────────────
# Pre-build
# ─────���─────────────────────���──────────────────
cd "$PROJECT_DIR"
VER="$(get_version)"
BUILD_NUM="$(get_build_number)"

step "ICD360S Mail Client - Build v$VER+$BUILD_NUM"
log "Platforms: ${PLATFORMS[*]}"
log "Output: $OUTPUT_DIR"

mkdir -p "$OUTPUT_DIR"

# Ensure enough_mail_fork dependencies are installed
if [[ -d "$PROJECT_DIR/enough_mail_fork" ]]; then
    log "Installing enough_mail_fork dependencies..."
    (cd "$PROJECT_DIR/enough_mail_fork" && flutter_cmd pub get) || true
fi

# Install main project dependencies
log "Installing project dependencies..."
flutter_cmd pub get

if $DO_CLEAN; then
    log "Cleaning build artifacts..."
    flutter_cmd clean
    flutter_cmd pub get
fi

# Track results
declare -A RESULTS

# ───���──────────────────────────────────────────
# Build functions
# ──────────��─────────��─────────────────────────

build_android_flavor() {
    local flavor="$1"
    local display_name="$2"
    local format="$3"  # apk or appbundle

    step "Android: $display_name ($format)"

    local output_file
    local build_args=("build" "$format" "--release" "--flavor" "$flavor")

    if [[ "$format" == "apk" && "$SPLIT_ABI" == "true" ]]; then
        build_args+=("--split-per-abi")
    fi

    log "Running: flutter ${build_args[*]}"
    if flutter_cmd "${build_args[@]}"; then
        # Copy artifacts to dist
        if [[ "$format" == "apk" ]]; then
            if $SPLIT_ABI; then
                # Multiple APKs per ABI
                for abi_apk in "$PROJECT_DIR/build/app/outputs/flutter-apk/app-${flavor}-"*"-release.apk"; do
                    if [[ -f "$abi_apk" ]]; then
                        local abi_name
                        abi_name="$(basename "$abi_apk" | sed "s/app-${flavor}-//" | sed 's/-release.apk//')"
                        local dest="$OUTPUT_DIR/ICD360S_MailClient_v${VER}_${flavor}_${abi_name}.apk"
                        cp "$abi_apk" "$dest"
                        ok "$display_name ($abi_name): $dest"
                    fi
                done
            else
                local src="$PROJECT_DIR/build/app/outputs/flutter-apk/app-${flavor}-release.apk"
                if [[ -f "$src" ]]; then
                    local dest="$OUTPUT_DIR/ICD360S_MailClient_v${VER}_${flavor}.apk"
                    cp "$src" "$dest"
                    ok "$display_name: $dest ($(du -h "$dest" | cut -f1))"
                    RESULTS["android:$flavor"]="OK"
                else
                    err "$display_name: APK not found at $src"
                    RESULTS["android:$flavor"]="FAIL"
                fi
            fi
        elif [[ "$format" == "appbundle" ]]; then
            local src="$PROJECT_DIR/build/app/outputs/bundle/${flavor}Release/app-${flavor}-release.aab"
            if [[ -f "$src" ]]; then
                local dest="$OUTPUT_DIR/ICD360S_MailClient_v${VER}_${flavor}.aab"
                cp "$src" "$dest"
                ok "$display_name: $dest ($(du -h "$dest" | cut -f1))"
                RESULTS["android:$flavor"]="OK"
            else
                err "$display_name: AAB not found at $src"
                RESULTS["android:$flavor"]="FAIL"
            fi
        fi
    else
        err "$display_name: Build failed"
        RESULTS["android:$flavor"]="FAIL"
    fi
}

build_linux() {
    step "Linux"
    check_platform linux || { RESULTS[linux]="SKIP"; return; }

    log "Running: flutter build linux --release"
    if flutter_cmd build linux --release; then
        local src_dir="$PROJECT_DIR/build/linux/x64/release/bundle"
        local dest="$OUTPUT_DIR/ICD360S_MailClient_v${VER}_linux"
        rm -rf "$dest"
        cp -r "$src_dir" "$dest"

        # Create tar.gz archive
        local archive="$OUTPUT_DIR/ICD360S_MailClient_v${VER}_linux.tar.gz"
        (cd "$OUTPUT_DIR" && tar -czf "$(basename "$archive")" "$(basename "$dest")")
        ok "Linux: $archive"
        RESULTS[linux]="OK"
    else
        err "Linux: Build failed"
        RESULTS[linux]="FAIL"
    fi
}

build_windows() {
    step "Windows"
    check_platform windows || { RESULTS[windows]="SKIP"; return; }

    log "Running: flutter build windows --release"
    if flutter_cmd build windows --release; then
        local src_dir="$PROJECT_DIR/build/windows/x64/runner/Release"
        local dest="$OUTPUT_DIR/ICD360S_MailClient_v${VER}_windows"
        rm -rf "$dest"
        cp -r "$src_dir" "$dest"

        # Create zip archive
        local archive="$OUTPUT_DIR/ICD360S_MailClient_v${VER}_windows.zip"
        (cd "$OUTPUT_DIR" && zip -r -q "$(basename "$archive")" "$(basename "$dest")")
        ok "Windows: $archive"

        # Inno Setup installer (if iscc is available)
        if command -v iscc &>/dev/null; then
            log "Building Inno Setup installer..."
            iscc "$PROJECT_DIR/windows/installer.iss"
            local installer="$PROJECT_DIR/build/installer/ICD360S_MailClient_Setup_v${VER}.exe"
            if [[ -f "$installer" ]]; then
                cp "$installer" "$OUTPUT_DIR/"
                ok "Windows Installer: $OUTPUT_DIR/$(basename "$installer")"
            fi
        else
            warn "iscc not found - skipping Inno Setup installer"
        fi
        RESULTS[windows]="OK"
    else
        err "Windows: Build failed"
        RESULTS[windows]="FAIL"
    fi
}

build_macos() {
    step "macOS"
    check_platform macos || { RESULTS[macos]="SKIP"; return; }

    log "Running: flutter build macos --release"
    if flutter_cmd build macos --release; then
        local app="$PROJECT_DIR/build/macos/Build/Products/Release/icd360s_mail_client.app"
        local dmg="$OUTPUT_DIR/ICD360S_MailClient_v${VER}_macos.dmg"

        # Create DMG
        if command -v hdiutil &>/dev/null && [[ -d "$app" ]]; then
            hdiutil create -volname "ICD360S Mail Client" \
                -srcfolder "$app" -ov -format UDZO "$dmg" 2>/dev/null
            ok "macOS DMG: $dmg"
        else
            # Fallback: copy .app bundle
            local dest="$OUTPUT_DIR/ICD360S_MailClient_v${VER}_macos.app"
            cp -r "$app" "$dest"
            ok "macOS App: $dest"
        fi
        RESULTS[macos]="OK"
    else
        err "macOS: Build failed"
        RESULTS[macos]="FAIL"
    fi
}

build_ios() {
    step "iOS"
    check_platform ios || { RESULTS[ios]="SKIP"; return; }

    log "Running: flutter build ios --release --no-codesign"
    if flutter_cmd build ios --release --no-codesign; then
        local app="$PROJECT_DIR/build/ios/iphoneos/Runner.app"
        if [[ -d "$app" ]]; then
            local dest="$OUTPUT_DIR/ICD360S_MailClient_v${VER}_ios.app"
            cp -r "$app" "$dest"
            ok "iOS: $dest (unsigned - sign with Xcode for distribution)"
        fi
        RESULTS[ios]="OK"
    else
        err "iOS: Build failed"
        RESULTS[ios]="FAIL"
    fi
}

# ──��───────────────────────────────────────────
# Execute builds
# ────���───────────────��─────────────────────────

for platform in "${PLATFORMS[@]}"; do
    case "$platform" in
        android:universal)
            build_android_flavor "universal" "Universal (Direct Distribution)" "apk"
            ;;
        android:fdroid)
            build_android_flavor "fdroid" "F-Droid" "apk"
            ;;
        android:googleplay)
            build_android_flavor "googleplay" "Google Play" "appbundle"
            ;;
        android:huawei)
            build_android_flavor "huawei" "Huawei AppGallery" "apk"
            ;;
        android:samsung)
            build_android_flavor "samsung" "Samsung Galaxy Store" "apk"
            ;;
        linux)    build_linux ;;
        windows)  build_windows ;;
        macos)    build_macos ;;
        ios)      build_ios ;;
        *)
            err "Unknown platform: $platform"
            ;;
    esac
done

# ��─────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────
step "Build Summary - v$VER"

HAS_FAIL=false
for platform in "${!RESULTS[@]}"; do
    status="${RESULTS[$platform]}"
    case "$status" in
        OK)   echo -e "  ${GREEN}✓${NC} $platform" ;;
        SKIP) echo -e "  ${YELLOW}⊘${NC} $platform (skipped - wrong OS)" ;;
        FAIL) echo -e "  ${RED}✗${NC} $platform (FAILED)"; HAS_FAIL=true ;;
    esac
done | sort

echo ""
log "Artifacts in: $OUTPUT_DIR"

if [[ -d "$OUTPUT_DIR" ]]; then
    ls -lh "$OUTPUT_DIR"/ 2>/dev/null | tail -n +2
fi

if $HAS_FAIL; then
    err "Some builds failed!"
    exit 1
fi

ok "All builds completed successfully!"
