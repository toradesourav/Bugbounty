#!/usr/bin/env bash
#
# Recon Toolkit Installer
# --------------------------
# Installs 3 widely-used, publicly available security tools:
#   - jadx       : APK -> Java decompiler        (Android bug bounty)
#   - apktool    : APK unpack/repack, manifest    (Android bug bounty)
#   - subfinder  : subdomain enumeration          (ProjectDiscovery)
#   - httpx      : fast HTTP probing of live hosts (ProjectDiscovery)
#
# This script does not embed any tool's source — it installs the
# official releases from each project's own distribution channel
# (apt, or the project's official GitHub releases / go install).
#
# Usage:
#   chmod +x install_recon_toolkit.sh
#   ./install_recon_toolkit.sh
#
# Tested on: Debian/Ubuntu. Best-effort on other distros (see notes).

set -uo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
log_info() { echo -e "${YELLOW}[*]${NC} $1"; }
log_err()  { echo -e "${RED}[!]${NC} $1"; }

INSTALL_DIR="${HOME}/.local/bin"
mkdir -p "$INSTALL_DIR"

command_exists() { command -v "$1" >/dev/null 2>&1; }

check_prereqs() {
    log_info "Checking prerequisites..."
    for cmd in curl unzip; do
        if ! command_exists "$cmd"; then
            log_err "'$cmd' is required but not installed. Install it first (e.g. sudo apt install $cmd)."
            exit 1
        fi
    done
}

install_jadx() {
    if command_exists jadx; then
        log_ok "jadx already installed: $(jadx --version 2>&1 | head -1)"
        return
    fi
    log_info "Installing jadx..."
    if command_exists apt-get; then
        sudo apt-get update -qq && sudo apt-get install -y jadx && { log_ok "jadx installed via apt"; return; }
    fi
    log_info "apt install unavailable/failed — falling back to GitHub release."
    if ! command_exists java; then
        log_err "jadx requires a JRE. Install one first (e.g. sudo apt install default-jre) then re-run this script."
        return
    fi
    JADX_VERSION="1.5.0"
    JADX_URL="https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip"
    TMP_ZIP="$(mktemp).zip"
    if curl -fsSL "$JADX_URL" -o "$TMP_ZIP"; then
        unzip -oq "$TMP_ZIP" -d "${HOME}/.local/jadx"
        ln -sf "${HOME}/.local/jadx/bin/jadx" "${INSTALL_DIR}/jadx"
        ln -sf "${HOME}/.local/jadx/bin/jadx-gui" "${INSTALL_DIR}/jadx-gui"
        rm -f "$TMP_ZIP"
        log_ok "jadx installed to ${INSTALL_DIR}/jadx (check GitHub for the latest version if this one 404s)"
    else
        log_err "Failed to download jadx. Check https://github.com/skylot/jadx/releases for the latest version."
    fi
}

install_apktool() {
    if command_exists apktool; then
        log_ok "apktool already installed: $(apktool --version 2>&1 | head -1)"
        return
    fi
    log_info "Installing apktool..."
    if command_exists apt-get; then
        sudo apt-get update -qq && sudo apt-get install -y apktool && { log_ok "apktool installed via apt"; return; }
    fi
    log_info "apt install unavailable/failed — falling back to official wrapper script + jar."
    if ! command_exists java; then
        log_err "apktool requires a JRE. Install one first (e.g. sudo apt install default-jre) then re-run this script."
        return
    fi
    APKTOOL_WRAPPER="https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool"
    APKTOOL_JAR_PAGE="https://bitbucket.org/iBotPeaches/apktool/downloads/"
    if curl -fsSL "$APKTOOL_WRAPPER" -o "${INSTALL_DIR}/apktool"; then
        chmod +x "${INSTALL_DIR}/apktool"
        log_info "Wrapper script installed. You still need the apktool.jar:"
        log_info "  Download the latest apktool_X.X.X.jar from: $APKTOOL_JAR_PAGE"
        log_info "  Save it as: ${INSTALL_DIR}/apktool.jar"
    else
        log_err "Failed to download apktool wrapper script."
    fi
}

install_go_tool() {
    local tool_name="$1"
    local module_path="$2"
    if command_exists "$tool_name"; then
        log_ok "$tool_name already installed: $($tool_name -version 2>&1 | head -1)"
        return
    fi
    if ! command_exists go; then
        log_err "$tool_name requires Go. Install it first: https://go.dev/doc/install"
        return
    fi
    log_info "Installing $tool_name via 'go install'..."
    if GOBIN="$INSTALL_DIR" go install "$module_path@latest"; then
        log_ok "$tool_name installed to ${INSTALL_DIR}/${tool_name}"
    else
        log_err "Failed to install $tool_name. Check https://github.com/projectdiscovery/${tool_name} for manual instructions."
    fi
}

main() {
    echo "=== Recon Toolkit Installer: jadx, apktool, subfinder, httpx ==="
    check_prereqs

    install_jadx
    install_apktool
    install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx"

    echo
    echo "-------------------------------------------------------"
    log_info "Make sure ${INSTALL_DIR} is on your PATH:"
    echo "    export PATH=\"\$PATH:${INSTALL_DIR}\""
    echo "    (add that line to your ~/.bashrc or ~/.zshrc to persist it)"
    echo
    log_info "Verify installs with:"
    echo "    jadx --version"
    echo "    apktool --version"
    echo "    subfinder -version"
    echo "    httpx -version"
    echo
    log_info "Example combo workflow:"
    echo "    subfinder -d target.com -silent | httpx -silent -title -status-code"
    echo "-------------------------------------------------------"
}

main
