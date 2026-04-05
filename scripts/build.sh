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
#   ios          iOS IPA (requires macOS + Xcode)
#   macos        macOS DMG (requires macOS)
#   windows      Windows ZIP + Inno Setup installer (requires Windows)
#   linux        Linux tar.gz + .deb + .rpm + AppImage (requires Linux)
#
# Options:
#   --split-abi        Split APKs per ABI (arm64, armv7, x86_64) - Android only
#   --clean            Run flutter clean before building
#   --verbose          Verbose output
#   --output DIR       Custom output directory (default: build/dist)
#   --version VER      Override version (reads from pubspec.yaml by default)
#   --codesign ID      macOS codesign identity (e.g. "Developer ID Application: ...")
#
# Examples:
#   ./scripts/build.sh all
#   ./scripts/build.sh android
#   ./scripts/build.sh android:googleplay
#   ./scripts/build.sh linux macos
#   ./scripts/build.sh android --split-abi
#   ./scripts/build.sh macos --codesign "Apple Development: icd360s@icloud.com"
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
NC='\033[0m'

# Defaults
SPLIT_ABI=false
DO_CLEAN=false
VERBOSE=false
VERSION=""
CODESIGN_ID=""
PLATFORMS=()

# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────
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

# ──────────────────────────────────────────────
# Parse arguments
# ──────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --split-abi)    SPLIT_ABI=true; shift ;;
        --clean)        DO_CLEAN=true; shift ;;
        --verbose)      VERBOSE=true; shift ;;
        --output)       OUTPUT_DIR="$2"; shift 2 ;;
        --version)      VERSION="$2"; shift 2 ;;
        --codesign)     CODESIGN_ID="$2"; shift 2 ;;
        --help|-h)
            head -38 "$0" | tail -36
            exit 0
            ;;
        *)  PLATFORMS+=("$1"); shift ;;
    esac
done

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

# ──────────────────────────────────────────────
# Pre-build
# ──────────────────────────────────────────────
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

log "Installing project dependencies..."
flutter_cmd pub get

if $DO_CLEAN; then
    log "Cleaning build artifacts..."
    flutter_cmd clean
    flutter_cmd pub get
fi

# Track results
declare -A RESULTS

# ──────────────────────────────────────────────
# Android build
# ──────────────────────────────────────────────
build_android_flavor() {
    local flavor="$1"
    local display_name="$2"
    local format="$3"  # apk or appbundle

    step "Android: $display_name ($format)"

    local build_args=("build" "$format" "--release" "--flavor" "$flavor")

    if [[ "$format" == "apk" && "$SPLIT_ABI" == "true" ]]; then
        build_args+=("--split-per-abi")
    fi

    log "Running: flutter ${build_args[*]}"
    if flutter_cmd "${build_args[@]}"; then
        if [[ "$format" == "apk" ]]; then
            if $SPLIT_ABI; then
                for abi_apk in "$PROJECT_DIR/build/app/outputs/flutter-apk/app-${flavor}-"*"-release.apk"; do
                    if [[ -f "$abi_apk" ]]; then
                        local abi_name
                        abi_name="$(basename "$abi_apk" | sed "s/app-${flavor}-//" | sed 's/-release.apk//')"
                        local dest="$OUTPUT_DIR/ICD360S_MailClient_v${VER}_android_${flavor}_${abi_name}.apk"
                        cp "$abi_apk" "$dest"
                        ok "$display_name ($abi_name): $(du -h "$dest" | cut -f1)"
                    fi
                done
                RESULTS["android:$flavor"]="OK"
            else
                local src="$PROJECT_DIR/build/app/outputs/flutter-apk/app-${flavor}-release.apk"
                if [[ -f "$src" ]]; then
                    local dest="$OUTPUT_DIR/ICD360S_MailClient_v${VER}_android_${flavor}.apk"
                    cp "$src" "$dest"
                    ok "$display_name: $(du -h "$dest" | cut -f1)"
                    RESULTS["android:$flavor"]="OK"
                else
                    err "$display_name: APK not found at $src"
                    RESULTS["android:$flavor"]="FAIL"
                fi
            fi
        elif [[ "$format" == "appbundle" ]]; then
            local src="$PROJECT_DIR/build/app/outputs/bundle/${flavor}Release/app-${flavor}-release.aab"
            if [[ -f "$src" ]]; then
                local dest="$OUTPUT_DIR/ICD360S_MailClient_v${VER}_android_${flavor}.aab"
                cp "$src" "$dest"
                ok "$display_name: $(du -h "$dest" | cut -f1)"
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

# ──────────────────────────────────────────────
# Linux: tar.gz + .deb + .rpm + AppImage
# ──────────────────────────────────────────────
build_linux() {
    step "Linux (tar.gz + deb + rpm + AppImage)"
    check_platform linux || { RESULTS[linux]="SKIP"; return; }

    log "Running: flutter build linux --release"
    if ! flutter_cmd build linux --release; then
        err "Linux: Build failed"
        RESULTS[linux]="FAIL"
        return
    fi

    local src_dir="$PROJECT_DIR/build/linux/x64/release/bundle"

    # ── tar.gz ──
    log "Packaging tar.gz..."
    (cd "$PROJECT_DIR/build/linux/x64/release" && \
        tar -czf "$OUTPUT_DIR/ICD360S_MailClient_v${VER}_linux_x64.tar.gz" bundle/)
    ok "tar.gz: $(du -h "$OUTPUT_DIR/ICD360S_MailClient_v${VER}_linux_x64.tar.gz" | cut -f1)"

    # ── .deb ──
    if command -v dpkg-deb &>/dev/null; then
        log "Building .deb package..."
        local pkg_dir="$PROJECT_DIR/build/deb/icd360s-mail_${VER}_amd64"
        rm -rf "$pkg_dir"
        mkdir -p "$pkg_dir/DEBIAN"
        mkdir -p "$pkg_dir/usr/lib/icd360s-mail"
        mkdir -p "$pkg_dir/usr/bin"
        mkdir -p "$pkg_dir/usr/share/applications"
        mkdir -p "$pkg_dir/usr/share/icons/hicolor/256x256/apps"

        cp -r "$src_dir"/* "$pkg_dir/usr/lib/icd360s-mail/"
        ln -sf /usr/lib/icd360s-mail/icd360s_mail_client "$pkg_dir/usr/bin/icd360s-mail"

        cat > "$pkg_dir/usr/share/applications/icd360s-mail.desktop" << 'DESKTOP'
[Desktop Entry]
Type=Application
Name=ICD360S Mail Client
Comment=Modern email client with mTLS security
Exec=icd360s-mail
Icon=icd360s-mail
Terminal=false
Categories=Network;Email;
MimeType=x-scheme-handler/mailto;
DESKTOP

        [[ -f "$PROJECT_DIR/assets/logo.png" ]] && \
            cp "$PROJECT_DIR/assets/logo.png" "$pkg_dir/usr/share/icons/hicolor/256x256/apps/icd360s-mail.png"

        cat > "$pkg_dir/DEBIAN/control" << CTRL
Package: icd360s-mail
Version: ${VER}
Architecture: amd64
Maintainer: ICD360S e.V. <dev@icd360s.de>
Description: ICD360S Mail Client
 Modern cross-platform email client with mTLS mutual authentication,
 threat detection, and end-to-end security for mail.icd360s.de.
Section: mail
Priority: optional
Depends: libgtk-3-0, libblkid1, liblzma5
CTRL

        dpkg-deb --build "$pkg_dir" "$OUTPUT_DIR/ICD360S_MailClient_v${VER}_linux_amd64.deb"
        ok ".deb: $(du -h "$OUTPUT_DIR/ICD360S_MailClient_v${VER}_linux_amd64.deb" | cut -f1)"
    else
        warn "dpkg-deb not found - skipping .deb"
    fi

    # ── .rpm ──
    if command -v rpmbuild &>/dev/null; then
        log "Building .rpm package..."
        local rpm_dir="$PROJECT_DIR/build/rpmbuild"
        rm -rf "$rpm_dir"
        mkdir -p "$rpm_dir"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

        local tar_dir="$rpm_dir/SOURCES/icd360s-mail-${VER}"
        mkdir -p "$tar_dir"
        cp -r "$src_dir"/* "$tar_dir/"
        (cd "$rpm_dir/SOURCES" && tar -czf "icd360s-mail-${VER}.tar.gz" "icd360s-mail-${VER}")
        rm -rf "$tar_dir"

        cat > "$rpm_dir/SPECS/icd360s-mail.spec" << SPEC
Name: icd360s-mail
Version: ${VER}
Release: 1
Summary: ICD360S Mail Client
License: Proprietary
URL: https://icd360s.de
Source0: icd360s-mail-${VER}.tar.gz

%description
Modern cross-platform email client with mTLS mutual authentication.

%install
mkdir -p %{buildroot}/usr/lib/icd360s-mail
mkdir -p %{buildroot}/usr/bin
tar -xzf %{SOURCE0} -C %{buildroot}/usr/lib/icd360s-mail --strip-components=1
ln -sf /usr/lib/icd360s-mail/icd360s_mail_client %{buildroot}/usr/bin/icd360s-mail

%files
/usr/lib/icd360s-mail/
/usr/bin/icd360s-mail
SPEC

        rpmbuild --define "_topdir $rpm_dir" -bb "$rpm_dir/SPECS/icd360s-mail.spec" && \
            find "$rpm_dir/RPMS" -name "*.rpm" -exec cp {} "$OUTPUT_DIR/ICD360S_MailClient_v${VER}_linux_x86_64.rpm" \; && \
            ok ".rpm: $(du -h "$OUTPUT_DIR/ICD360S_MailClient_v${VER}_linux_x86_64.rpm" 2>/dev/null | cut -f1)" || \
            warn "rpmbuild failed - skipping .rpm"
    else
        warn "rpmbuild not found - skipping .rpm"
    fi

    # ── AppImage ──
    log "Building AppImage..."
    local appimage_tool="$PROJECT_DIR/build/appimagetool"
    if [[ ! -f "$appimage_tool" ]]; then
        wget -q "https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage" \
            -O "$appimage_tool" 2>/dev/null && chmod +x "$appimage_tool" || true
    fi

    if [[ -x "$appimage_tool" ]]; then
        local app_dir="$PROJECT_DIR/build/ICD360S_Mail.AppDir"
        rm -rf "$app_dir"
        mkdir -p "$app_dir/usr/bin"

        cp -r "$src_dir"/* "$app_dir/usr/bin/"

        cat > "$app_dir/icd360s-mail.desktop" << 'DESKTOP'
[Desktop Entry]
Type=Application
Name=ICD360S Mail Client
Exec=icd360s_mail_client
Icon=icd360s-mail
Terminal=false
Categories=Network;Email;
DESKTOP

        [[ -f "$PROJECT_DIR/assets/logo.png" ]] && \
            cp "$PROJECT_DIR/assets/logo.png" "$app_dir/icd360s-mail.png"

        cat > "$app_dir/AppRun" << 'APPRUN'
#!/bin/bash
SELF=$(readlink -f "$0")
HERE=${SELF%/*}
export LD_LIBRARY_PATH="${HERE}/usr/bin/lib:${LD_LIBRARY_PATH}"
exec "${HERE}/usr/bin/icd360s_mail_client" "$@"
APPRUN
        chmod +x "$app_dir/AppRun"

        ARCH=x86_64 "$appimage_tool" "$app_dir" \
            "$OUTPUT_DIR/ICD360S_MailClient_v${VER}_linux_x86_64.AppImage" 2>/dev/null && \
            ok "AppImage: $(du -h "$OUTPUT_DIR/ICD360S_MailClient_v${VER}_linux_x86_64.AppImage" | cut -f1)" || \
            warn "AppImage build failed"
    else
        warn "appimagetool not available - skipping AppImage"
    fi

    RESULTS[linux]="OK"
}

# ──────────────────────────────────────────────
# Windows: ZIP portable + Inno Setup installer
# ──────────────────────────────────────────────
build_windows() {
    step "Windows (ZIP + Inno Setup installer)"
    check_platform windows || { RESULTS[windows]="SKIP"; return; }

    log "Running: flutter build windows --release"
    if ! flutter_cmd build windows --release; then
        err "Windows: Build failed"
        RESULTS[windows]="FAIL"
        return
    fi

    local src_dir="$PROJECT_DIR/build/windows/x64/runner/Release"

    # ── ZIP (portable) ──
    log "Packaging portable ZIP..."
    local zip_file="$OUTPUT_DIR/ICD360S_MailClient_v${VER}_windows_x64_portable.zip"
    (cd "$src_dir/.." && zip -r -q "$zip_file" Release/)
    ok "ZIP portable: $(du -h "$zip_file" | cut -f1)"

    # ── Inno Setup installer ──
    if command -v iscc &>/dev/null; then
        log "Building Inno Setup installer..."
        iscc "$PROJECT_DIR/windows/installer.iss"
        local installer="$PROJECT_DIR/build/installer/ICD360S_MailClient_Setup_v${VER}.exe"
        if [[ -f "$installer" ]]; then
            cp "$installer" "$OUTPUT_DIR/ICD360S_MailClient_v${VER}_windows_x64_setup.exe"
            ok "Installer: $(du -h "$OUTPUT_DIR/ICD360S_MailClient_v${VER}_windows_x64_setup.exe" | cut -f1)"
        fi
    else
        warn "iscc (Inno Setup) not found - skipping installer"
        warn "Install: choco install innosetup -y"
    fi

    RESULTS[windows]="OK"
}

# ──────────────────────────────────────────────
# macOS: DMG + optional codesign + notarize
# ──────────────────────────────────────────────
build_macos() {
    step "macOS (DMG + codesign)"
    check_platform macos || { RESULTS[macos]="SKIP"; return; }

    log "Running: flutter build macos --release"
    if ! flutter_cmd build macos --release; then
        err "macOS: Build failed"
        RESULTS[macos]="FAIL"
        return
    fi

    local app="$PROJECT_DIR/build/macos/Build/Products/Release/icd360s_mail_client.app"

    # ── Codesign (if identity provided) ──
    if [[ -n "$CODESIGN_ID" ]]; then
        log "Codesigning with: $CODESIGN_ID"
        local entitlements="$PROJECT_DIR/macos/Runner/Release.entitlements"
        if [[ -f "$entitlements" ]]; then
            codesign --force --deep --options runtime \
                --sign "$CODESIGN_ID" \
                --entitlements "$entitlements" \
                "$app"
        else
            codesign --force --deep --options runtime \
                --sign "$CODESIGN_ID" \
                "$app"
        fi
        ok "Codesigned: $CODESIGN_ID"
    else
        warn "No --codesign identity provided - DMG will be unsigned"
    fi

    # ── DMG ──
    log "Creating DMG..."
    local dmg="$OUTPUT_DIR/ICD360S_MailClient_v${VER}_macos.dmg"
    local dmg_dir="$PROJECT_DIR/build/dmg_contents"
    rm -rf "$dmg_dir"
    mkdir -p "$dmg_dir"
    cp -r "$app" "$dmg_dir/"
    ln -s /Applications "$dmg_dir/Applications"

    hdiutil create -volname "ICD360S Mail Client" \
        -srcfolder "$dmg_dir" -ov -format UDZO "$dmg" 2>/dev/null
    rm -rf "$dmg_dir"

    ok "DMG: $(du -h "$dmg" | cut -f1)"
    RESULTS[macos]="OK"
}

# ──────────────────────────────────────────────
# iOS: IPA
# ──────────────────────────────────────────────
build_ios() {
    step "iOS (IPA)"
    check_platform ios || { RESULTS[ios]="SKIP"; return; }

    # Install CocoaPods if needed
    if [[ -f "$PROJECT_DIR/ios/Podfile" ]]; then
        log "Installing CocoaPods dependencies..."
        (cd "$PROJECT_DIR/ios" && pod install 2>&1) || true
    fi

    log "Running: flutter build ios --release --no-codesign"
    if ! flutter_cmd build ios --release --no-codesign; then
        err "iOS: Build failed"
        RESULTS[ios]="FAIL"
        return
    fi

    # ── Create IPA from .app ──
    local app="$PROJECT_DIR/build/ios/iphoneos/Runner.app"
    if [[ -d "$app" ]]; then
        local ipa="$OUTPUT_DIR/ICD360S_MailClient_v${VER}_ios.ipa"
        local payload_dir="$PROJECT_DIR/build/Payload"
        rm -rf "$payload_dir"
        mkdir -p "$payload_dir"
        cp -r "$app" "$payload_dir/"
        (cd "$PROJECT_DIR/build" && zip -r -q "$ipa" Payload/)
        rm -rf "$payload_dir"
        ok "IPA (unsigned): $(du -h "$ipa" | cut -f1)"
        warn "Sign with Xcode or Transporter before uploading to App Store / TestFlight"
    fi

    RESULTS[ios]="OK"
}

# ──────────────────────────────────────────────
# Execute builds
# ──────────────────────────────────────────────
for platform in "${PLATFORMS[@]}"; do
    case "$platform" in
        android:universal)  build_android_flavor "universal" "Universal (Direct Distribution)" "apk" ;;
        android:fdroid)     build_android_flavor "fdroid" "F-Droid" "apk" ;;
        android:googleplay) build_android_flavor "googleplay" "Google Play" "appbundle" ;;
        android:huawei)     build_android_flavor "huawei" "Huawei AppGallery" "apk" ;;
        android:samsung)    build_android_flavor "samsung" "Samsung Galaxy Store" "apk" ;;
        linux)              build_linux ;;
        windows)            build_windows ;;
        macos)              build_macos ;;
        ios)                build_ios ;;
        *)                  err "Unknown platform: $platform" ;;
    esac
done

# ──────────────────────────────────────────────
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
    echo ""
    ls -lhS "$OUTPUT_DIR"/ 2>/dev/null | tail -n +2
fi

# ── SHA-256 checksums ──
echo ""
log "SHA-256 Checksums:"
for f in "$OUTPUT_DIR"/ICD360S_MailClient_*; do
    [[ -f "$f" ]] && sha256sum "$f" | sed "s|$OUTPUT_DIR/||"
done

if $HAS_FAIL; then
    err "Some builds failed!"
    exit 1
fi

echo ""
ok "All builds completed successfully!"
