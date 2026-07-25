#!/bin/sh
# Build script for FiSH_11 : Linux, BSD (macOS untested)
# POSIX compliant => works with sh, dash, etc.

set -e

# Colors for messages (disable if not in terminal)
if [ -t 1 ]; then
    RED='\033[31m'
    GREEN='\033[32m'
    YELLOW='\033[33m'
    BLUE='\033[34m'
    RESET='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    RESET=''
fi

# Utility functions
log_info() {
    printf "${BLUE}[INFO]${RESET} %s\n" "$1"
}

log_success() {
    printf "${GREEN}[SUCCESS]${RESET} %s\n" "$1"
}

log_warning() {
    printf "${YELLOW}[WARNING]${RESET} %s\n" "$1" >&2
}

log_error() {
    printf "${RED}[ERROR]${RESET} %s\n" "$1" >&2
}

detect_os() {
    case "$(uname -s)" in
        Linux*)    echo "linux";;
        Darwin*)   echo "macos";;
        FreeBSD*)  echo "freebsd";;
        OpenBSD*)  echo "openbsd";;
        NetBSD*)   echo "netbsd";;
        DragonFly*) echo "dragonfly";;
        *)         echo "unknown";;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo "x86_64";;
        aarch64|arm64) echo "aarch64";;
        i386|i686) echo "i686";;
        *) echo "$(uname -m)";;
    esac
}

check_command() {
    command -v "$1" >/dev/null 2>&1
}

check_rust_toolchain() {
    log_info "Checking Rust toolchain..."

    if ! check_command rustc; then
        log_error "Rust (rustc) is not installed."
        return 1
    fi

    if ! check_command cargo; then
        log_error "Cargo is not installed."
        return 1
    fi

    RUSTC_VERSION=$(rustc --version)
    CARGO_VERSION=$(cargo --version)

    log_info "Rust version: $RUSTC_VERSION"
    log_info "Cargo version: $CARGO_VERSION"

    # Check minimum version (1.60+ recommended)
    # Extract major.minor version numbers
    RUST_VERSION_LINE=$(echo "$RUSTC_VERSION" | cut -d' ' -f2)
    RUST_MAJOR=$(echo "$RUST_VERSION_LINE" | cut -d'.' -f1)
    RUST_MINOR=$(echo "$RUST_VERSION_LINE" | cut -d'.' -f2)

    # Calculate combined version number for comparison (major * 100 + minor)
    COMBINED_VERSION=$((RUST_MAJOR * 100 + RUST_MINOR))

    if [ $COMBINED_VERSION -lt 160 ]; then
        log_warning "Old Rust version ($RUST_MAJOR.$RUST_MINOR < 1.60). Some features may not be available."
    fi

    return 0
}

check_linker() {
    OS=$(detect_os)

    case "$OS" in
        linux)
            if ! check_command gcc && ! check_command clang; then
                log_error "No linker available (gcc or clang required)."
                return 1
            fi
            ;;
        freebsd|openbsd|netbsd|dragonfly)
            if ! check_command cc; then
                log_error "System linker (cc) not found."
                return 1
            fi
            ;;
        macos)
            if ! check_command clang; then
                log_error "Clang not found (required for macOS)."
                return 1
            fi
            ;;
        *)
            log_error "Unsupported OS for linker detection."
            return 1
            ;;
    esac

    return 0
}

install_rust() {
    log_info "Installing Rust via rustup..."

    if ! check_command curl; then
        log_error "curl is required to install Rust."
        return 1
    fi

    # Installation of rustup
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

    # Add to PATH for current session
    if [ -d "$HOME/.cargo/bin" ]; then
        PATH="$HOME/.cargo/bin:$PATH"
        export PATH
    fi

    if ! check_rust_toolchain; then
        log_error "Failed to install Rust."
        return 1
    fi

    log_success "Rust installed successfully."
    return 0
}

setup_target() {
    OS=$(detect_os)
    ARCH=$(detect_arch)

    case "$OS" in
        linux)    TARGET="${ARCH}-unknown-linux-gnu";;
        macos)    TARGET="${ARCH}-apple-darwin";;
        freebsd)  TARGET="${ARCH}-unknown-freebsd";;
        openbsd)  TARGET="${ARCH}-unknown-openbsd";;
        netbsd)   TARGET="${ARCH}-unknown-netbsd";;
        dragonfly) TARGET="${ARCH}-unknown-dragonfly";;
        *)
            log_error "Unsupported OS: $OS"
            return 1
            ;;
    esac

    
    echo "$TARGET"
    return 0
}

build_project() {
    TARGET=$1

    log_info "Starting build for $TARGET..."

    
    cargo build --release --target "$TARGET" --color never

    if [ $? -ne 0 ]; then
        log_error "Build failed."
        return 1
    fi

    echo "[SUCCESS] Build successful!"
    echo "[INFO] Binary available in: target/$TARGET/release/"

    return 0
}

show_help() {
    cat <<EOF
Usage: $0 [OPTIONS]

This script is designed for Linux/BSD/macOS builds.
For Windows, simply use: cargo build --workspace

Options:
  -h, --help       Show this help
  -i, --install    Install Rust if not present
  -c, --check      Check environment only
  -t, --target     Specify target manually (e.g., x86_64-unknown-linux-gnu)

Examples:
  $0                    # Normal build for current platform
  $0 -i                 # Install Rust if needed then build
  $0 -c                 # Check environment only
  $0 -t aarch64-unknown-linux-gnu  # Build for specific target
EOF
}

# Parse arguments
INSTALL_RUST=false
CHECK_ONLY=false
CUSTOM_TARGET=""

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        -i|--install)
            INSTALL_RUST=true
            shift
            ;;
        -c|--check)
            CHECK_ONLY=true
            shift
            ;;
        -t|--target)
            CUSTOM_TARGET="$2"
            shift 2
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Windows detection (this script is for Unix-like only)
if [ "$(expr substr $(uname -s) 1 5)" = "MINGW" ] || [ "$(expr substr $(uname -s) 1 6)" = "CYGWIN" ]; then
    log_error "This script is designed for Linux/BSD/macOS only."
    log_error "On Windows, simply use: cargo build --workspace"
    exit 1
fi

# Main program
# Log without colors for these messages to avoid cargo issues
echo "=== FiSH_11 build script (Linux/BSD/macOS) ==="
echo "Detected OS: $(uname -s)"
echo "Architecture: $(uname -m)"

# Check environment
if ! check_linker; then
    exit 1
fi

if ! check_rust_toolchain; then
    if [ "$INSTALL_RUST" = true ]; then
        if ! install_rust; then
            exit 1
        fi
    else
        log_error "Rust is not installed. Use -i option to install it."
        exit 1
    fi
fi

if [ "$CHECK_ONLY" = true ]; then
    log_success "Environment checked successfully."
    exit 0
fi

# Determine target
if [ -n "$CUSTOM_TARGET" ]; then
    TARGET="$CUSTOM_TARGET"
else
    TARGET=$(setup_target)
    if [ $? -ne 0 ]; then
        exit 1
    fi
fi

# Build
if ! build_project "$TARGET"; then
    exit 1
fi

log_success "Build completed successfully!"
exit 0