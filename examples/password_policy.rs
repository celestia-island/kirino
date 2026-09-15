//! How a service wires the kernel's password policy: bootstrap the first account with a
//! temporary password, then ask the policy at login whether the password must change.
//!
//! Run with `cargo run --example password_policy`. The temporary password printed below is
//! random on every run — a bootstrap password is never a fixed literal.

use chrono::{Duration, Utc};
use uuid::Uuid;

use kirino::{
    auth::passport::static_password::hash_password,
    rbac::policy::{
        bootstrap_credential, InMemoryPasswordStateStore, PasswordPolicy, PasswordState,
        PasswordStateStore,
    },
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    // Configuration in: the policy applies, a bootstrap password must be changed on first
    // login, and every password expires after 90 days.
    let policy = PasswordPolicy::from_config(true, true, Some(90))?;

    let store = InMemoryPasswordStateStore::new();
    let account = Uuid::now_v7();

    // First run: mint the temporary password, store its hash plus the initial state next to the
    // account, and print the one-time line the operator reads. `emit_log` does the same through
    // `tracing` for services that already have a subscriber.
    let credential = bootstrap_credential("admin", Utc::now());
    let _password_hash = hash_password(credential.password())?;
    store.put(&account, credential.state()).await?;
    println!("{}", credential.log_line());

    // First login: the account may do nothing but change its password.
    let state = store.get(&account).await?.expect("state was just stored");
    println!(
        "first login: {:?}",
        policy
            .change_requirement(&state, Utc::now())
            .map(|r| r.as_str())
    );

    // Change password: the user-chosen password resets the clock.
    let chosen = PasswordState::rotated(Utc::now());
    store.put(&account, chosen).await?;
    println!(
        "right after the change: {:?}",
        policy
            .change_requirement(&chosen, Utc::now())
            .map(|r| r.as_str())
    );

    // Ninety days later the same password is stale and must be rotated again.
    let later = Utc::now() + Duration::days(90);
    println!(
        "ninety days later: {:?}",
        policy
            .change_requirement(&chosen, later)
            .map(|r| r.as_str())
    );

    Ok(())
}
