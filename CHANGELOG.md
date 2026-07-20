# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.1] - 2026-07-20

### Added — kirino-session 0.6.1

- `OneShotStore`: in-memory JTI replay protection with automatic expiry cleanup.
- `TokenManager::verify_lenient()`: verify JWT signature without rejecting expired tokens (session restore flow).
- `SessionStore`: real PostgreSQL-backed session persistence (create, revoke, validate, prune).
- `MultiJwt`: multi-source JWT extractor for axum — Bearer header, cookie, query parameter, with configurable source order.
- Examples: `axum_ws_one_shot` (full WS auth chain), `session_restore` (lenient verify + reissue).

### Added — kirino 0.5.1

- `WorkspaceGuard`: three-dimensional RBAC — Subject, Group, Workspace — with scoped permission checks.
- `WorkspaceStore` trait with `InMemoryWorkspaceStore` for testing.
- `WorkspaceRole` enum (Viewer / Operator / Owner) with capability mapping.
- `ScopedPermission` trait with optional workspace scope.

### Fixed

- Restored missing `use anyhow::Result` in `identity_subject.rs` (compile error on master).
- Cleaned up merge-conflict `#[cfg]` debris in `store/mod.rs`.
- Ungated `SimpleRole` from stray `#[cfg(feature = "rbac-hierarchy")]`.

## [0.5.0] - 2025-06-09

### Added

- Feature flags: `rbac-core`, `rbac-inmemory`, `rbac-hierarchy`, `rbac-constraints`, `rbac-dynamic`, `rbac-full`, `auth-password`, `auth-jwt`
- JWT permissions and session integration (`login_with_session`, `logout`)
- Persistence traits (`PersistentAssignmentStore`, `PersistentRoleStore`, `PersistentConstraintStore`, `PersistentAuditStore`, `PersistentTrustStore`)
- `IdentitySubject` with `Delegatable` trait for identity-based authorization

### Changed

- Separated `UserRecord` from `UserInfo` to prevent password hash leakage
- Replaced `std::sync::RwLock` with `tokio::sync::RwLock` in async stores

### Fixed

- Added memory bounds to prevent unbounded growth
- Added login rate limiting to prevent brute-force attacks
- Added JWT token revocation on password change and user deletion
- Enforced stronger password policy (min 8 chars, 3/4 categories)
- Added username validation and prevented username enumeration
- Disabled auto-admin for first user by default
- Added resilient trust decay with auto-restart

## [0.4.0] - 2025-06-08

### Added

- Security hardening: memory bounds, trust decay, rate limiting
- Clippy pedantic warnings resolved across codebase

### Changed

- Applied `cargo fmt` and enforced use-group layout

## [0.3.0] - 2025-06-07

### Added

- Dynamic authorization layer: `AuthorizationArbiter` with 5-dimension risk scoring
- Trust scoring with exponential decay and background worker
- Anomaly detection with sliding-window z-score analysis
- DO-178C inspired autonomy levels (L0–L4)
- `Shared<T>` Arc wrapper for zero-cost engine cloning
- `PermissionCache` with TTL-based LRU eviction
- `AuditLogger` with composable sink + policy engine + analyzer pipeline

### Changed

- Refactored RBAC to `Shared<T>` wrapper, eliminated caller-side `Arc::new()`

## [0.2.0] - 2025-06-05

### Added

- RBAC1 role inheritance with cycle detection (`HierarchyNode`, `HierarchicalRole`)
- RBAC2 constraint models: SSD, DSD, Cardinality, Prerequisite, Temporal
- `ConstraintValidator` for enforcing separation of duty
- `InMemoryConstraintStore` reference implementation
- `SessionManager` with DSD enforcement on role activation
- Multilingual documentation (8 languages: EN, ZHS, ZHT, JA, KO, RU, ES, FR)

## [0.1.2] - 2025-06-04

### Added

- Permissions field in JWT claims

## [0.1.1] - 2025-06-03

### Added

- Session management
- Audit logging subsystem

## [0.1.0] - 2025-06-02

### Added

- Initial release
- Zero-trust authentication: Anonymous, Basic, Temporary, Service identity types
- Multi-credential support: One-time tokens, JWT, service tokens
- Passport challenges: Static password (Argon2), key pair, OAuth, TOTP/HOTP, captcha, biometric
- Generic RBAC engine implementing ANSI INCITS 359-2004 (RBAC0)
- `AuthService` for complete registration, login, and token verification
- In-memory reference implementations for all stores
- CI/CD pipeline with 3-OS x 2-toolchain matrix
- Automated crates.io publishing

[0.5.0]: https://github.com/celestia-island/kirino/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/celestia-island/kirino/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/celestia-island/kirino/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/celestia-island/kirino/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/celestia-island/kirino/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/celestia-island/kirino/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/celestia-island/kirino/releases/tag/v0.1.0
