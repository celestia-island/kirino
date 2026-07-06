//! Criterion benchmarks for kirino RBAC hot paths.
//!
//! Each group is gated behind the feature that provides its types, so the file
//! compiles under any feature combination:
//!   - `permission_check`         -> default (`rbac-inmemory` + engine)
//!   - `hierarchical_resolution`  -> `rbac-hierarchy`
//!   - `constraint_validation`    -> `rbac-constraints`
//!   - `dynamic_auth`             -> `rbac-dynamic`
//!
//! Build/run examples:
//!   cargo bench --no-run                       # default-feature checks
//!   cargo bench --all-features --no-run        # compile every group
//!   cargo bench --all-features                 # run them

use std::collections::HashSet;

use criterion::{black_box, Criterion};

// The crate's own `test_utils` is `#[cfg(test)]`-gated and therefore invisible
// to the benchmark target, so we define local fixtures with the same shape.
mod fixtures {
    use kirino::rbac::traits::{Permission, Subject};

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub struct BenchSubject(pub String);

    impl Subject for BenchSubject {
        fn subject_id(&self) -> &str {
            &self.0
        }

        fn from_subject_id(id: &str) -> Self {
            Self(id.to_string())
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum BenchPerm {
        Read,
        Write,
        Delete,
        Admin,
    }

    impl Permission for BenchPerm {
        fn name(&self) -> &str {
            match self {
                Self::Read => "read",
                Self::Write => "write",
                Self::Delete => "delete",
                Self::Admin => "admin",
            }
        }

        fn domain(&self) -> &'static str {
            "bench"
        }
    }
}

use fixtures::{BenchPerm, BenchSubject};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("failed to build tokio runtime")
}

/// Permission-check hot path: a role holding several permissions, checking both
/// an allowed and an explicitly-denied permission. Measures the steady-state
/// (cached) decision path that dominates in production.
fn bench_permission_check(c: &mut Criterion) {
    use kirino::rbac::engine::RbacEngine;
    use kirino::rbac::store::memory::InMemoryAssignmentStore;
    use kirino::rbac::store::registry::{SimpleRole, StaticPermissionRegistry, StaticRoleRegistry};
    use kirino::rbac::traits::AssignmentStore;

    let rt = runtime();

    let mut role_reg = StaticRoleRegistry::new();
    let admin_perms: HashSet<BenchPerm> = [
        BenchPerm::Read,
        BenchPerm::Write,
        BenchPerm::Delete,
        BenchPerm::Admin,
    ]
    .into_iter()
    .collect();
    role_reg.register(SimpleRole::new("admin", admin_perms));
    let perm_reg = StaticPermissionRegistry::new(
        [
            BenchPerm::Read,
            BenchPerm::Write,
            BenchPerm::Delete,
            BenchPerm::Admin,
        ]
        .into_iter()
        .collect(),
    );

    let engine = RbacEngine::new(role_reg, perm_reg, InMemoryAssignmentStore::new());

    let admin = BenchSubject("admin-user".to_string());
    rt.block_on(engine.assignment_store().assign_role(&admin, "admin"))
        .unwrap();

    // Second subject: holds the admin role but has `Admin` explicitly denied,
    // exercising the deny-override path.
    let denied = BenchSubject("denied-user".to_string());
    rt.block_on(engine.assignment_store().assign_role(&denied, "admin"))
        .unwrap();
    rt.block_on(
        engine
            .assignment_store()
            .set_denied_permissions(&denied, std::iter::once(BenchPerm::Admin).collect()),
    )
    .unwrap();

    let mut group = c.benchmark_group("permission_check");
    group.bench_function("allow", |b| {
        b.iter(|| {
            black_box(rt.block_on(engine.check(black_box(&admin), black_box(&BenchPerm::Read))))
        });
    });
    group.bench_function("deny", |b| {
        b.iter(|| {
            black_box(rt.block_on(engine.check(black_box(&denied), black_box(&BenchPerm::Admin))))
        });
    });
    group.finish();
}

/// Hierarchical role resolution over a deep inheritance chain
/// (level0 -> level1 -> ... -> level9). Benchmarks both the pure resolver and
/// the engine's hierarchical check (cold path, cache invalidated per iter).
#[cfg(feature = "rbac-hierarchy")]
fn bench_hierarchical_resolution(c: &mut Criterion) {
    use kirino::rbac::engine::RbacEngine;
    use kirino::rbac::hierarchy::{resolve_role_chain, HierarchyNode};
    use kirino::rbac::store::memory::InMemoryAssignmentStore;
    use kirino::rbac::store::registry::{StaticPermissionRegistry, StaticRoleRegistry};
    use kirino::rbac::traits::AssignmentStore;

    const DEPTH: usize = 10;

    fn deep_registry() -> StaticRoleRegistry<HierarchyNode<BenchPerm>, BenchPerm> {
        let mut reg = StaticRoleRegistry::new();
        for i in 0..DEPTH {
            // level0 owns Admin; every deeper level owns Read, so resolving
            // level0 must walk the whole chain to find Read at level9.
            let perms: HashSet<BenchPerm> = if i == 0 {
                std::iter::once(BenchPerm::Admin).collect()
            } else {
                std::iter::once(BenchPerm::Read).collect()
            };
            let parents: Vec<String> = if i + 1 < DEPTH {
                vec![format!("level{}", i + 1)]
            } else {
                Vec::new()
            };
            reg.register_hierarchical(
                HierarchyNode::new(format!("level{i}"), perms).with_parents(parents),
            );
        }
        reg
    }

    let rt = runtime();

    let perm_reg =
        StaticPermissionRegistry::new([BenchPerm::Read, BenchPerm::Admin].into_iter().collect());
    let engine = RbacEngine::new(deep_registry(), perm_reg, InMemoryAssignmentStore::new());

    let subject = BenchSubject("hier-user".to_string());
    rt.block_on(engine.assignment_store().assign_role(&subject, "level0"))
        .unwrap();

    let mut group = c.benchmark_group("hierarchical_resolution");
    group.bench_function("resolve_chain", |b| {
        b.iter(|| {
            black_box(resolve_role_chain(
                black_box("level0"),
                &*engine.role_registry(),
            ))
        });
    });
    group.bench_function("check_inherited_cold", |b| {
        b.iter(|| {
            black_box(rt.block_on(async {
                engine.invalidate_subject_cache(&subject).await;
                engine.check_hierarchical(&subject, &BenchPerm::Read).await
            }))
        });
    });
    group.finish();
}

/// Constraint validation over a store carrying every supported policy kind:
/// SSD, DSD, prerequisite, cardinality, and temporal (time-window). The store
/// is seeded so that the `validate_assignment` hot path actually walks each
/// policy family, and individual `validate_*` entry points are exercised
/// directly.
#[cfg(feature = "rbac-constraints")]
fn bench_constraint_validation(c: &mut Criterion) {
    use kirino::rbac::constraints::{
        CardinalityConstraint, ConstraintStore, ConstraintValidator, DsdPolicy,
        InMemoryConstraintStore, PrerequisiteConstraint, SsdPolicy, TemporalConstraint,
    };

    let rt = runtime();

    let store = InMemoryConstraintStore::new();
    rt.block_on(store.add_ssd_policy(SsdPolicy::new(
        "admin_auditor_exclusive",
        ["admin".to_string(), "auditor".to_string()].into(),
        2,
    )))
    .unwrap();
    rt.block_on(store.add_dsd_policy(DsdPolicy::new(
        "operator_auditor_session",
        ["operator".to_string(), "auditor".to_string()].into(),
        2,
    )))
    .unwrap();
    rt.block_on(
        store.add_prerequisite_constraint(PrerequisiteConstraint::new("admin", "operator")),
    )
    .unwrap();
    rt.block_on(store.add_cardinality_constraint(CardinalityConstraint::new("admin", 5)))
        .unwrap();
    // Valid (current-time) window so the temporal validator does real work
    // rather than short-circuiting on an empty constraint list.
    let now = chrono::Utc::now();
    rt.block_on(
        store.add_temporal_constraint(
            TemporalConstraint::new(
                "admin",
                now - chrono::Duration::hours(1),
                now + chrono::Duration::hours(1),
            )
            .unwrap(),
        ),
    )
    .unwrap();

    let validator = ConstraintValidator::new(store);

    let pass_roles = vec!["operator".to_string()];
    let violation_roles = vec!["auditor".to_string()];

    let mut group = c.benchmark_group("constraint_validation");
    group.bench_function("validate_assignment_pass", |b| {
        b.iter(|| {
            black_box(rt.block_on(validator.validate_assignment(
                black_box(&pass_roles),
                black_box("viewer"),
                black_box(0_usize),
            )))
        });
    });
    group.bench_function("validate_assignment_violation", |b| {
        b.iter(|| {
            black_box(rt.block_on(validator.validate_assignment(
                black_box(&violation_roles),
                black_box("admin"),
                black_box(0_usize),
            )))
        });
    });
    group.bench_function("validate_temporal", |b| {
        b.iter(|| black_box(rt.block_on(validator.validate_temporal(black_box("admin")))));
    });
    group.bench_function("validate_dsd", |b| {
        b.iter(|| {
            black_box(rt.block_on(
                validator.validate_dsd(black_box(&["operator".to_string()]), black_box("viewer")),
            ))
        });
    });
    group.finish();
}

/// Dynamic authorization scoring: the 5-dimension risk score and the full
/// authorize() verdict for an agent action.
#[cfg(feature = "rbac-dynamic")]
fn bench_dynamic_auth(c: &mut Criterion) {
    use kirino::rbac::dynamic::arbiter::AuthorizationArbiter;
    use kirino::rbac::dynamic::delegator::Delegator;
    use kirino::rbac::dynamic::metrics::{ActionCategory, ActionRequest};
    use kirino::rbac::dynamic::policy::default_dynamic_policy;
    use kirino::rbac::dynamic::trust::{InMemoryTrustScoreStore, TrustScore};

    let rt = runtime();

    let arbiter =
        AuthorizationArbiter::new(InMemoryTrustScoreStore::new(), default_dynamic_policy());

    let mut trust = TrustScore::new(0.9);
    trust.confidence = 0.8;
    trust.evidence_count = 100;
    rt.block_on(arbiter.trust_store().set("agent-1", trust))
        .unwrap();

    let req = ActionRequest::simple(
        Delegator::agent("agent-1", "#bench"),
        "file.write",
        ActionCategory::FileWrite,
    );

    let mut group = c.benchmark_group("dynamic_auth");
    group.bench_function("risk_score", |b| {
        b.iter(|| black_box(rt.block_on(arbiter.risk_score(black_box(&req)))));
    });
    group.bench_function("authorize", |b| {
        b.iter(|| black_box(rt.block_on(arbiter.authorize(black_box(&req)))));
    });
    group.finish();
}

fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_permission_check(&mut criterion);
    #[cfg(feature = "rbac-hierarchy")]
    bench_hierarchical_resolution(&mut criterion);
    #[cfg(feature = "rbac-constraints")]
    bench_constraint_validation(&mut criterion);
    #[cfg(feature = "rbac-dynamic")]
    bench_dynamic_auth(&mut criterion);
    criterion.final_summary();
}
