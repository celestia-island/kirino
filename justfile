# Kirino Build System
#
# Usage:
#   just <recipe>        - Run specified recipe
#   just --list          - List all available recipes
#
# Main tasks:
#   just check           - Check compilation
#   just clippy          - Run Clippy lints
#   just fmt             - Format code
#   just fmt-check       - Check formatting
#   just enforce-groups  - Enforce use statement group layout
#   just test            - Run unit tests
#   just ci              - Run all CI checks

<<<<<<< HEAD
<<<<<<< HEAD
set windows-shell := ["pwsh.exe", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; $PSDefaultParameterValues['*:Encoding'] = 'utf8';"]

python := if os_family() == "windows" { "python" } else { "python3" }

=======
=======
>>>>>>> dev
set shell := ["bash", "-c"]
set windows-shell := ["bash.exe", "-c"]
set unstable
set lists

# Shared celestia-devtools recipes — NOT in git. Stage with: just fetch.
# `import?` silently skips when absent, so this justfile parses pre-fetch.
import? "./.just/git-bash-interop.just"
import? "./.just/celestia-devtools.just"

# Stage shared celestia-devtools recipes into .just/ (gitignored).
# Source order: explicit URL arg → local pip bundle (offline) → GitHub raw.
# curl honors HTTP_PROXY/HTTPS_PROXY/ALL_PROXY env vars automatically.
[script('bash')]
fetch URL='':
    #!/usr/bin/env bash
    set -euo pipefail
    out=.just/celestia-devtools.just
    mkdir -p .just
    if [ -n "{{URL}}" ]; then
      echo "[fetch] {{URL}} -> $out"
      curl -fsSL "{{URL}}" -o "$out"
    elif command -v celestia-devtools >/dev/null 2>&1; then
      src=$(celestia-devtools include-path)
      echo "[fetch] local bundle ($src) -> $out"
      cp "$src" "$out"
    else
      echo "[fetch] github raw -> $out"
      curl -fsSL "https://raw.githubusercontent.com/celestia-island/celestia-devtools/dev/src/celestia_devtools/common.just" -o "$out"
    fi
    echo "[fetch] wrote $out"

python := if os_family() == "windows" { "python" } else { "python3" }


<<<<<<< HEAD
>>>>>>> origin/dev
=======
>>>>>>> dev
default:
    @just --list

# ============================================================================
# Build tasks
# ============================================================================

<<<<<<< HEAD
<<<<<<< HEAD
# Build everything (Debug mode)
build-dev:
    @echo "Building all (Debug mode)..."
    cargo build --all

# Build everything (Release mode)
build:
    @echo "Building all (Release mode)..."
    cargo build --release --all
=======
# Build all crates. Release by default; `--dev` for debug, `--clean` to clean first.
build *FLAGS='':
    just _build ":" "cargo build --all" "cargo build --release --all" {{FLAGS}}
>>>>>>> origin/dev
=======
# Build all crates. Release by default; `--dev` for debug, `--clean` to clean first.
build *FLAGS='':
    just _build ":" "cargo build --all" "cargo build --release --all" {{FLAGS}}
>>>>>>> dev

# ============================================================================
# Code quality checks
# ============================================================================

# Check compilation
check:
    @echo "Checking compilation..."
    cargo check --all-targets --all-features

# Run Clippy linter
clippy:
    @echo "Running Clippy..."
    cargo clippy --all-targets --all-features -- -D warnings

# Format all code
fmt:
    just fmt-toml
<<<<<<< HEAD
<<<<<<< HEAD
    @echo "Formatting all code..."
    cargo fmt --all
=======
    cargo fmt --all
    python3 scripts/enforce_use_groups.py
>>>>>>> origin/dev
=======
    cargo fmt --all
    python3 scripts/enforce_use_groups.py
>>>>>>> dev

# Check formatting without modifying files
fmt-check:
    @echo "Checking code formatting..."
    cargo fmt --all -- --check

# Enforce use statement group layout (imports grouping)
enforce-groups:
    @echo "Enforcing use statement group layout..."
    {{python}} scripts/enforce_use_groups.py

# ============================================================================
# Test tasks
# ============================================================================

# Run unit tests
test:
    @echo "Running unit tests..."
    cargo test --lib --all-features

# ============================================================================
# CI
# ============================================================================

# Run all CI checks (check + clippy + fmt-check + enforce-groups + test)
ci: check clippy fmt-check enforce-groups test
    @echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    @echo "All CI checks passed!"
    @echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ============================================================================
# Cleanup
# ============================================================================

# Clean all build artifacts
clean:
    cargo clean
