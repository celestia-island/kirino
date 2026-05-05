# PLAN.md — kirino 通用 RBAC 体系设计

> **目标**：将 kirino 从当前硬编码于 entelecheia 领域的 RBAC 实现，演进为通用的、可被任意下游项目按需实例化的 RBAC 框架。
>
> **现状**：`src/rbac.rs` 中的 `Role`/`Permission` 枚举直接建模 entelecheia 的 4 角色 13 权限，`RbacStore` 是内存 HashMap。entelecheia 已在 `packages/shared/src/domain/auth/rbac.rs` 中 fork 并修改了这份代码（Agent 角色权限更宽、缺少去重、serde default 不同）。这不是可持续的做法——kirino 应当成为单一事实来源。
>
> **与 entelecheia PLAN.md 的关系**：entelecheia §24 将 RBAC 标记为「已完成」，但那是指 entelecheia 侧的中间件/API/持久层集成。本 PLAN 关注的是 **kirino 作为库本身**如何提供通用的 RBAC 能力，让 entelecheia 和其他项目都能基于 trait 实例化各自领域模型。

---

## 1. 目标架构总览

```
┌──────────────────────────────────────────────────────────┐
│                   kirino (this crate)                     │
│                                                          │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐   │
│  │ rbac/core   │  │ rbac/hier    │  │ rbac/constraint│   │
│  │ RBAC0       │  │ RBAC1        │  │ RBAC2          │   │
│  │ 基础模型     │  │ 继承/层级     │  │ 约束/互斥      │   │
│  └──────┬──────┘  └──────┬───────┘  └───────┬────────┘   │
│         │                │                   │            │
│         └────────────────┼───────────────────┘            │
│                          │                                │
│  ┌───────────────────────┴───────────────────────────┐    │
│  │ rbac/traits.rs  — 核心抽象层                        │    │
│  │   Subject, Permission, Role, PermissionRegistry,   │    │
│  │   RoleStore, AssignmentStore, SessionManager       │    │
│  └───────────────────────┬───────────────────────────┘    │
│                          │                                │
│  ┌───────────────────────┴───────────────────────────┐    │
│  │ rbac/store.rs    — 内存实现（零依赖参考实现）        │    │
│  │ rbac/cache.rs    — 权限缓存层                       │    │
│  └───────────────────────────────────────────────────┘    │
│                                                          │
│  ─────────────────── 与现有模块的关系 ──────────────────   │
│                                                          │
│  auth/identity/*  ──→ Subject trait                       │
│  auth/credential/ ──→ Session + JWT claims 集成           │
│  database/*       ──→ RoleStore / AssignmentStore 持久化  │
│  service/login    ──→ 登录后 RBAC 角色注入                 │
│                                                          │
└──────────────────────────────────────────────────────────┘

消费方（如 entelecheia）：
   impl Permission for MyPermission { ... }
   impl Subject for MySubject { ... }
   定义自己的 Role / Permission 枚举
   注入自己的 RoleStore 后端（SeaORM / 内存）
```

---

## 2. 核心抽象层设计（`src/rbac/traits.rs`）

### 2.1 原子类型标记 Trait

```rust
/// 权限的单位粒度。下游项目通过枚举实现此 trait。
pub trait Permission: Eq + Hash + Clone + Send + Sync + 'static {
    /// 唯一标识名，用于序列化/日志/审计
    fn name(&self) -> &str;
    /// 可选：权限所属的资源域（如 "agent", "config", "system"）
    fn domain(&self) -> &str { "" }
}

/// 被授权的主体——可以是用户、服务账户、匿名访客、Agent。
pub trait Subject: Eq + Hash + Clone + Send + Sync + 'static {
    /// 主体唯一标识（通常对应 Identity 的 UUID 字符串）
    fn subject_id(&self) -> &str;
    /// 主体类型标签（如 "user", "service", "anonymous", "agent"）
    fn subject_type(&self) -> &str { "user" }
}
```

### 2.2 角色与权限集合

```rust
/// 一个角色是权限的命名集合。
pub trait Role<P: Permission>: Clone + Send + Sync + 'static {
    fn role_name(&self) -> &str;
    fn permissions(&self) -> &HashSet<P>;
}

/// 权限注册表：维护「系统中存在哪些权限」的权威列表。
pub trait PermissionRegistry<P: Permission>: Send + Sync {
    fn all_permissions(&self) -> HashSet<P>;
    fn get_permission(&self, name: &str) -> Option<P>;
}
```

### 2.3 分配存储后端 Trait

```rust
/// 主体↔角色 分配 的持久化接口。
#[async_trait]
pub trait AssignmentStore<S: Subject, R, P: Permission>: Send + Sync
where
    R: Role<P>,
{
    /// 为主体分配一个角色
    async fn assign_role(&self, subject: &S, role_name: &str) -> Result<()>;
    /// 撤销角色分配
    async fn revoke_role(&self, subject: &S, role_name: &str) -> Result<()>;
    /// 查询主体的所有角色名
    async fn roles_of(&self, subject: &S) -> Result<Vec<String>>;
    /// 列出拥有某角色的所有主体 ID
    async fn subjects_with_role(&self, role_name: &str) -> Result<Vec<String>>;
    /// 主体的额外（临时）权限
    async fn extra_permissions(&self, subject: &S) -> Result<HashSet<P>>;
    async fn set_extra_permissions(&self, subject: &S, perms: HashSet<P>) -> Result<()>;
    /// 主体的拒绝权限（黑名单，优先级高于 allow）
    async fn denied_permissions(&self, subject: &S) -> Result<HashSet<P>>;
    async fn set_denied_permissions(&self, subject: &S, perms: HashSet<P>) -> Result<()>;
}

/// 角色定义 的持久化接口（可选——如果项目有动态角色需求）。
#[async_trait]
pub trait RoleStore<P: Permission>: Send + Sync {
    /// 注册一个新角色定义
    async fn create_role(&self, role_name: &str, permissions: HashSet<P>) -> Result<()>;
    /// 删除角色定义
    async fn delete_role(&self, role_name: &str) -> Result<bool>;
    /// 获取角色的权限集合
    async fn get_role_permissions(&self, role_name: &str) -> Result<Option<HashSet<P>>>;
    /// 列出所有已注册角色
    async fn list_roles(&self) -> Result<Vec<String>>;
}
```

### 2.4 核心决策引擎

```rust
/// RBAC 决策引擎：输入 Subject + Permission → 输出 bool。
pub struct RbacEngine<S: Subject, P: Permission, R: Role<P>, A: AssignmentStore<S, R, P>> {
    role_registry: Arc<dyn RoleRegistry<R, P>>,
    permission_registry: Arc<dyn PermissionRegistry<P>>,
    assignment_store: Arc<A>,
    cache: Arc<PermissionCache<S, P>>,
    _phantom: PhantomData<(S, R)>,
}

impl<S, P, R, A> RbacEngine<S, P, R, A>
where
    S: Subject,
    P: Permission,
    R: Role<P>,
    A: AssignmentStore<S, R, P>,
{
    /// 检查主体是否拥有某权限。
    /// 检查顺序：denied → extra → role permissions → role hierarchy
    pub async fn check(&self, subject: &S, permission: &P) -> bool {
        // 1. 检查缓存（bypass 拒绝缓存或命中允许缓存）
        // 2. 检查 denied_permissions（拒绝优先）
        // 3. 检查 extra_permissions（临时提权）
        // 4. 遍历 assigned roles，含角色继承链
        // 5. 写入缓存
        todo!()
    }

    /// 批量检查，返回 (permission → granted) 映射
    pub async fn check_batch(&self, subject: &S, permissions: &HashSet<P>) -> HashMap<P, bool>;

    /// 获取主体的有效权限全集
    pub async fn effective_permissions(&self, subject: &S) -> HashSet<P>;
}
```

---

## 3. RBAC0 — 用户-角色-权限基础模型（Phase 1）

### 3.1 内容

- 定义并实现 §2 的所有 trait
- 提供 `InMemoryAssignmentStore` 和 `InMemoryRoleStore` 作为默认后端
- 提供 `StaticPermissionRegistry`（从枚举/静态列表构建）
- 提供 `StaticRoleRegistry`（从枚举/配置构建，支持硬编码角色）
- 实现 `RbacEngine` 的核心决策逻辑（deny-override 语义）
- 实现 `PermissionCache`（基于 LRU 的内存缓存，支持 TTL）

### 3.2 与现有代码的对应

| 现有 | → 演变为 |
|------|----------|
| `src/rbac.rs::Permission` 枚举 | 删除。改为 `Permission` trait |
| `src/rbac.rs::Role` 枚举 | 删除。改为 `Role<P>` trait |
| `src/rbac.rs::UserRole` | → `AssignmentStore` trait 的数据载体 |
| `src/rbac.rs::RbacStore` | → `RbacEngine` + `InMemoryAssignmentStore` |

### 3.3 向后兼容策略

~~保留 `src/rbac.rs` 中的具体类型但将其标记为 `#[deprecated]`~~ → **已在 v0.1.2 中移除 compat 层**，具体类型改由下游项目自行定义。kirino 内置 `KirinoPermission`（`service::login`）仅作为参考实现。

同时，把 entelecheia 中 fork 版本的额外修改（Agent 额外权限、serde default 等）合并回这个 compat 模块，确保 entelecheia 平滑迁移。

### 3.4 消费方使用示例

```rust
// 在 entelecheia 或其他下游项目中：
use kirino::rbac::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
enum MyPermission {
    AgentRead, AgentWrite, // ...
}

impl Permission for MyPermission {
    fn name(&self) -> &str { /* serde rename */ }
}

// 定义角色（静态或从配置加载）
fn build_role_registry() -> StaticRoleRegistry<SimpleRole<MyPermission>> {
    let mut reg = StaticRoleRegistry::new();
    reg.register(SimpleRole::new("admin", MyPermission::all()));
    reg.register(SimpleRole::new("viewer", [MyPermission::AgentRead, ...].into()));
    reg
}

// 使用引擎
let engine = RbacEngine::new(role_registry, permission_registry, assignment_store);
let can_deploy = engine.check(&subject, &MyPermission::DeployExecute).await;
```

---

## 4. RBAC1 — 角色继承 / 层级模型（Phase 2）

### 4.1 内容

- 扩展 `Role<P>` trait，新增 `parent_roles(&self) -> Vec<String>` 方法
- `RbacEngine::resolve_role_chain()` — 递归展开角色继承树，合并权限，带循环检测
- 支持多重继承（一个角色可继承多个父角色）
- 支持角色激活/停用（会话级临时裁剪继承链）
- 提供 `HierarchicalRoleRegistry` 封装

### 4.2 继承语义

```
         Admin
        /      \
   Operator   Auditor
      |
   Viewer
```

- Viewer < Operator < Admin：权限累积
- Auditor 与 Operator 无继承关系，可能互斥（见 RBAC2）

### 4.3 关键实现细节

- **循环检测**：BFS/DFS 展开时维护 `visited` 集合，遇循环立即报错
- **权限合并**：父角色权限 ∪ 自身权限，深度优先展开
- **重写语义**：子角色可通过 `denied_permissions` 覆盖父角色授予的某权限

---

## 5. RBAC2 — 约束与互斥模型（Phase 3）

### 5.1 静态职责分离 (SSD — Static Separation of Duty)

- 定义：某些角色对**不能同时分配给同一主体**
- 实现：`SsdPolicy { roles: HashSet<String>, cardinality: usize }`
  - `cardinality = 2` 且 `roles = {A, B}` 表示 A 和 B 不能同时分配给同一人
  - `cardinality = 1` 且 `roles = {A, B, C}` 表示三者中最多只能分配一个
- 检查时机：`assign_role()` 执行前，`RbacEngine` 调用 `SsdValidator::validate()`

### 5.2 动态职责分离 (DSD — Dynamic Separation of Duty)

- 定义：某些角色对**可以同时分配，但不能在同一会话中同时激活**
- 实现：`DsdPolicy { roles: HashSet<String>, cardinality: usize }`
- 检查时机：会话创建时 (`SessionManager::create_session`)，角色激活时

### 5.3 其他约束

| 约束类型 | 说明 | 实现 |
|---------|------|------|
| **基数约束** | 某角色最多 N 个主体持有 | `CardinalityConstraint { role, max }` → 分配时检查 `count_subjects_with_role()` |
| **前提约束** | 获得角色 B 前必须先有角色 A | `PrerequisiteConstraint { role, requires }` → 分配 B 时检查是否已持有 A |
| **时间约束** | 某角色仅在时间段内有效 | `TemporalConstraint { role, valid_from, valid_until }` → 权限检查时验证当前时间 |

### 5.4 约束存储

```rust
#[async_trait]
pub trait ConstraintStore: Send + Sync {
    async fn list_ssd_policies(&self) -> Result<Vec<SsdPolicy>>;
    async fn add_ssd_policy(&self, policy: SsdPolicy) -> Result<()>;
    async fn remove_ssd_policy(&self, roles: &HashSet<String>) -> Result<bool>;

    async fn list_dsd_policies(&self) -> Result<Vec<DsdPolicy>>;
    async fn add_dsd_policy(&self, policy: DsdPolicy) -> Result<()>;
    async fn remove_dsd_policy(&self, roles: &HashSet<String>) -> Result<bool>;

    async fn list_cardinality_constraints(&self) -> Result<Vec<CardinalityConstraint>>;
    async fn add_cardinality_constraint(&self, c: CardinalityConstraint) -> Result<()>;
}
```

---

## 6. 主体模型与 kirino 现有 Identity 体系对接（Phase 4）

### 6.1 当前 Identity 类型

kirino 已定义了四种身份（`src/models/identity.rs`）：

| Identity 变体 | RBAC 对应行为 |
|--------------|--------------|
| `Anonymous` | 最小权限，通常仅 `Viewer` 或自定义的只读角色 |
| `Basic` | 标准用户，注册后默认最小权限，通过临时提权获得更多 |
| `Temporary` | 限时账户，过期后自动撤销所有角色分配 |
| `Service` | 服务账户，用于"借用"权限给 Basic 用户；自身持有特定权限集合 |

### 6.2 实现计划

- 为每种 Identity 变体实现 `Subject` trait
- `Service` 类型的 Subject 实现 `Delegatable` trait（权限委托）
- 临时提权流程：Basic 用户请求提权 → 系统查找关联的 Service 账户 → 将 Service 账户的角色**临时**添加到 Basic 用户的会话中 → 限时自动撤销
- 与 `src/auth/passport/temporary_whitelist.rs` 中的白名单机制对接

```rust
/// 可委托权限的主体
pub trait Delegatable: Subject {
    /// 此主体可被哪些其他主体"借用"权限
    fn can_be_delegated_to(&self, delegate: &dyn Subject) -> bool;
}
```

---

## 7. 数据库持久化（Phase 5）

### 7.1 SQL 后端

- 基于 `AssignmentStore` trait 实现 `SqlAssignmentStore`
- 表设计（与 entelecheia 现有 schema 对齐）：

```sql
-- 主体-角色分配表（兼容 entelecheia rbac_user_roles）
CREATE TABLE rbac_assignments (
    subject_id   TEXT NOT NULL,
    role_name    TEXT NOT NULL,
    extra_permissions  TEXT[] DEFAULT '{}',   -- 序列化的权限名列表
    denied_permissions TEXT[] DEFAULT '{}',
    assigned_at  TIMESTAMPTZ DEFAULT NOW(),
    expires_at   TIMESTAMPTZ,                 -- NULL = 永不过期
    PRIMARY KEY (subject_id, role_name)
);

-- 角色定义表（新增——支持动态角色管理）
CREATE TABLE rbac_roles (
    role_name    TEXT PRIMARY KEY,
    parent_roles TEXT[] DEFAULT '{}',         -- RBAC1 继承
    permissions  TEXT[] NOT NULL,              -- 关联的权限名
    created_at   TIMESTAMPTZ DEFAULT NOW()
);

-- 约束表（新增——RBAC2）
CREATE TABLE rbac_constraints (
    id           SERIAL PRIMARY KEY,
    constraint_type TEXT NOT NULL,             -- 'ssd' | 'dsd' | 'cardinality' | 'prerequisite'
    config       JSONB NOT NULL,               -- 约束的序列化配置
    created_at   TIMESTAMPTZ DEFAULT NOW()
);

-- 审计日志（兼容 entelecheia rbac_audit_log）
CREATE TABLE rbac_audit_log (
    id           SERIAL PRIMARY KEY,
    subject_id   TEXT NOT NULL,
    permission   TEXT NOT NULL,
    endpoint     TEXT DEFAULT '',
    granted      BOOLEAN NOT NULL,
    created_at   TIMESTAMPTZ DEFAULT NOW()
);
```

- 支持 `sea-orm`（通过 feature flag `rbac-sea-orm`）和原生 `sqlx`（feature flag `rbac-sqlx`）
- 自动迁移能力（可选，由 `rbac-migrate` feature 控制）

### 7.2 NoSQL 后端

- 基于 `AssignmentStore` trait 实现 `NoSqlAssignmentStore`
- 主体-角色作为文档存储，支持嵌入权限缓存
- 实验性支持（低优先级），先完成 trait 定义和文档

### 7.3 缓存层

- `PermissionCache` trait，默认 `LruPermissionCache` 实现
- 支持 `redis` 作为分布式缓存后端（feature flag `rbac-redis`）
- 缓存失效策略：角色变更时主动失效受影响主体

---

## 8. 会话管理（Phase 6）

### 8.1 与现有 JWT 凭据集成

kirino 已有 JWT 签发/验证（`src/auth/credential/basic.rs`）。需要扩展：

- JWT claims 中嵌入角色列表和权限（当前已有 `roles: Vec<String>`）
- 会话级角色激活：用户可能拥有 5 个角色，但本次会话只激活其中 3 个
- 会话过期后自动回收临时提权

```rust
pub struct Session<S: Subject> {
    pub id: Uuid,
    pub subject: S,
    pub active_roles: HashSet<String>,   // 本次会话激活的角色（默认全部）
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[async_trait]
pub trait SessionManager<S: Subject, P: Permission>: Send + Sync {
    async fn create_session(&self, subject: &S, active_roles: HashSet<String>) -> Result<Session<S>>;
    async fn activate_role(&self, session_id: Uuid, role_name: &str) -> Result<()>;
    async fn deactivate_role(&self, session_id: Uuid, role_name: &str) -> Result<()>;
    async fn check(&self, session_id: Uuid, permission: &P) -> Result<bool>;
    async fn destroy_session(&self, session_id: Uuid) -> Result<()>;
}
```

---

## 9. kirino 内部重构步骤（实施顺序）

### Phase 0 — 基础设施准备（1-2 天）

- [x] 创建 `src/rbac/` 目录结构
- [x] 编写 `src/rbac/traits.rs`（Permission, Subject, Role, AssignmentStore, RoleStore 等 trait）
- [x] 编写 `src/rbac/engine.rs`（RbacEngine 核心逻辑，含 deny-override）
- [x] 编写 `src/rbac/cache.rs`（PermissionCache trait + TtlPermissionCache）
- [x] 编写 `src/rbac/store/`（InMemoryAssignmentStore, InMemoryRoleStore, StaticPermissionRegistry, StaticRoleRegistry, SimpleRole）
- [x] 将现有 `src/rbac.rs` 移至 `src/rbac/compat.rs` 并标记 `#[deprecated]`
- [x] 确保所有现有测试通过（`cargo test`）

### Phase 1 — RBAC0 基础模型（2-3 天）

- [x] 实现 `SimpleRole<P>` — 通用角色实现
- [x] 实现 `RbacEngine::check()` 和 `RbacEngine::check_batch()`
- [x] 实现 `RbacEngine::effective_permissions()`
- [x] 实现 `PermissionCache` with TTL
- [x] 将 `src/service/login/mod.rs` 中的 `AuthService` 与 `RbacEngine` 集成（替代直接使用 `RbacStore`）
- [x] 迁移测试：将 `src/service/register/mod.rs` 中的测试改为使用新 trait

### Phase 2 — RBAC1 层级模型（2-3 天）

- [x] 扩展 `Role<P>` trait 增加 `parent_roles()`（`HierarchicalRole<P>` trait）
- [x] 实现 `resolve_role_chain()` 含循环检测（DFS + `detect_cycle()`）
- [x] 实现 `HierarchyNode<P>` + `check_hierarchical()` / `effective_permissions_hierarchical()`
- [x] 测试：多层继承、循环检测、权限累积

### Phase 3 — RBAC2 约束模型（2 天）

- [x] 实现 `SsdPolicy` / `DsdPolicy` / `CardinalityConstraint` / `PrerequisiteConstraint`
- [x] 实现 `ConstraintStore` trait 和 `InMemoryConstraintStore`
- [x] 实现 `ConstraintValidator`（`validate_assignment()` 统一校验 SSD/Cardinality/Prerequisite）
- [x] 实现 `TemporalConstraint` 时间约束

### Phase 4 — Identity 体系对接（2 天）

- [x] 为 `Anonymous`/`Basic`/`Temporary`/`Service` 实现 `Subject` trait（`IdentitySubject` wrapper）
- [x] 实现临时提权（Basic ↔ Service 委托）（`Delegatable` trait）
- [ ] 与现有的 credential / passport 体系对接（JWT claims 包含 permission 集合）

### Phase 5 — 数据库持久化（3-4 天）

- [ ] 实现 `SqlAssignmentStore`（feature flag: `rbac-sql`）
- [ ] 实现 `SqlRoleStore` + `SqlConstraintStore`
- [ ] 提供 sea-orm 实体（feature flag: `rbac-sea-orm`）
- [ ] 编写迁移脚本（SQL schema）
- [ ] 测试：`SqlAssignmentStore` 的 CRUD + 权限检查

### Phase 6 — 会话管理（2 天）

- [x] 实现 `Session` 结构体
- [x] 实现 `SessionManager` trait + InMemory 实现
- [ ] 集成到 `AuthService`（login 时创建 session，logout 时销毁）
- [x] DSD 约束在会话激活时的检查

---

## 10. entelecheia 迁移路径

### 10.1 当前问题

| 问题 | 影响 |
|------|------|
| `packages/shared/src/domain/auth/rbac.rs` 是 kirino `src/rbac.rs` 的 fork 且已 diverged | 两个事实来源，不一致 |
| Agent 角色的权限集合不同（kirino: 3 perms, entelecheia: 5 perms） | 语义漂移 |
| entelecheia 直接在代码中硬编码了 Permission 枚举 | 无法扩展到新场景 |

### 10.2 迁移步骤

1. **kirino 侧**：完成 Phase 1（RBAC0 trait 系统）后发布 `v0.2.0-alpha`
2. **entelecheia 侧**：
   - 定义 `EntelecheiaPermission` 枚举（替换当前 fork 的 `Permission`）
   - `impl kirino::rbac::traits::Permission for EntelecheiaPermission`
   - 定义 `EntelecheiaRole` 类型并注册角色
   - 使用 `kirino::rbac::engine::RbacEngine` 替换 `RbacStore`
   - 将 `RbacPersistence` 改为实现 `AssignmentStore` trait
   - 中间件 `rbac_middleware.rs` 改为调用 `RbacEngine::check()`
3. **kirino 侧**：删除 `compat.rs`（正式版 `v0.2.0`）

### 10.3 entelecheia 定制需求清单（由kirino满足）

| entelecheia 需求 | kirino 对应能力 |
|-----------------|----------------|
| 4 角色 13 权限 | `Permission` trait + 自定义枚举实例化 |
| JWT + API Key 双通道 | 现有 `auth/credential` 模块 + `SessionManager` |
| 路由→权限映射中间件 | entelecheia 侧实现，调用 `RbacEngine::check()` |
| 环境变量配置 RBAC_ENABLED 等 | entelecheia 侧配置层，不进入 kirino |
| 超级管理员 API Key | entelecheia 侧特化逻辑，kirino 提供 bypass hook |
| 第一个用户自动 Admin | `AuthService::register()` 中保留此逻辑 |
| MCP 工具级权限 | `ToolPermissions` 独立于 RBAC，但可调用 `RbacEngine` |
| 审计日志 | kirino 提供 `AuditLogger` trait，entelecheia 实现 sea-orm 版本 |
| 多 Agent 各自持有 RbacStore | `RbacEngine` 支持多实例，每个 Agent 独立配置 |

---

## 11. Feature Flags 规划

```toml
[features]
default = ["rbac-inmemory"]

# RBAC 核心（零依赖 trait + engine）
rbac-core = []

# 内存存储后端
rbac-inmemory = ["rbac-core"]

# RBAC1 层级模型
rbac-hierarchy = ["rbac-core"]

# RBAC2 约束模型
rbac-constraints = ["rbac-core"]

# SQL 持久化（sqlx 原生）
rbac-sql = ["rbac-core", "dep:sqlx"]

# SeaORM 持久化
rbac-sea-orm = ["rbac-core", "dep:sea-orm"]

# Redis 缓存
rbac-redis = ["rbac-core", "dep:redis"]

# 全功能
rbac-full = ["rbac-inmemory", "rbac-hierarchy", "rbac-constraints", "rbac-sql", "rbac-sea-orm", "rbac-redis"]
```

---

## 12. 测试策略

### 12.1 单元测试

- `rbac-core`：trait 的 InMemory 实现全覆盖（check / batch / effective_permissions / deny-override / extra / cache hit/miss）
- `rbac-hierarchy`：继承链展开、循环检测、权限合并、多层继承 O(√n) 性能
- `rbac-constraints`：SSD/DSD 策略校验、基数溢出、前提缺失、时间窗口边界

### 12.2 集成测试

- `AuthService` + `RbacEngine` 端到端：注册→登录→权限检查→提权→过期
- `SqlAssignmentStore` + 真实 PostgreSQL（testcontainers 或 CI 中的 pg 服务）

### 12.3 性能基准

- `RbacEngine::check()` 在 1000 角色 × 100 权限的层级结构下 < 1μs
- `check_batch(50 permissions)` < 50μs
- 缓存命中率 > 95% 的典型场景

---

## 13. API 稳定性承诺

| 模块 | 稳定性 | 说明 |
|------|--------|------|
| `rbac::traits` | **stable (v0.2.0+)** | trait 定义一旦稳定将长期不变 |
| `rbac::engine` | **stable** | RbacEngine 公共 API |
| `rbac::store` (InMemory) | **stable** | 参考实现 |
| `rbac::hierarchy` | **beta** | RBAC1 相关可能微调 |
| `rbac::constraints` | **beta** | RBAC2 约束模型可能扩展 |
| `rbac::sql` | **beta** | 数据库 schema 可能演进 |
| `rbac::compat` | **deprecated** | 旧版兼容层，v0.3.0 移除 |

---

## 14. 参考标准

- ANSI INCITS 359-2004 — RBAC 标准（定义了 RBAC0/1/2/3 的正式语义）
- NIST RBAC 模型 — Sandhu et al. 1996 原始论文
- OASIS XACML — 用于属性级访问控制的策略语言（作为未来 ABAC 扩展的参考）

---

## 附录 A: 目录结构目标

```
kirino/src/rbac/
├── mod.rs                  # pub mod traits; pub mod engine; pub mod cache; pub mod store;
├── traits.rs               # Permission, Subject, Role, AssignmentStore, RoleStore, ConstraintStore
├── engine.rs               # RbacEngine 实现
├── cache.rs                # PermissionCache trait + LruPermissionCache
├── store/
│   ├── mod.rs
│   ├── memory.rs           # InMemoryAssignmentStore, InMemoryRoleStore
│   ├── registry.rs         # StaticPermissionRegistry, StaticRoleRegistry, SimpleRole
│   └── sql.rs              # SqlAssignmentStore (feature gated)
├── hierarchy/
│   ├── mod.rs
│   ├── chain.rs            # Role chain resolution
│   └── registry.rs         # HierarchicalRoleRegistry
├── constraints/
│   ├── mod.rs
│   ├── policies.rs         # SsdPolicy, DsdPolicy, CardinalityConstraint 等
│   └── validator.rs        # ConstraintValidator
├── session/
│   ├── mod.rs
│   └── manager.rs          # Session, SessionManager
├── audit.rs                # AuditLogger trait
└── compat.rs               # [deprecated] 旧版 Role/Permission/RbacStore 兼容
```
