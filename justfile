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

set windows-shell := ["pwsh.exe", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; $PSDefaultParameterValues['*:Encoding'] = 'utf8';"]

python := if os_family() == "windows" { "python" } else { "python3" }

default:
    @just --list

# ============================================================================
# Build tasks
# ============================================================================

# Build all crates. Release by default; `--dev` for debug, `--clean` to clean first.
#   just build            # release
#   just build --dev      # debug
#   just build --clean    # clean then release
build *FLAGS='':
    #!/usr/bin/env bash
    set -euo pipefail
    profile=release
    for a in {{FLAGS}}; do
      case "$a" in
        --dev)   profile=dev ;;
        --clean) cargo clean ;;
      esac
    done
    if [ "$profile" = dev ]; then
      echo "Building all (Debug)..."
      cargo build --all
    else
      echo "Building all (Release)..."
      cargo build --release --all
    fi

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
    @echo "Formatting all code..."
    cargo fmt --all

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
