# 系统架构总览

Kirino 是一个分层的认证与授权框架。每一层都建立在下一层之上，并通过清晰的 trait 边界支持定制。

```mermaid
graph TD
    subgraph SERVICE["服务层"]
        AUTH["AuthService<br/>注册 / 登录 / 验证"]
        SESSION["SessionManager<br/>创建 / 激活 / 销毁"]
    end

    subgraph AUTHN["认证层"]
        IDENTITY["Identity（身份）<br/>匿名 / 基本 / 临时 / 服务"]
        CREDENTIAL["Credential（凭证）<br/>一次性 / JWT / 服务令牌"]
        PASSPORT["Passport（凭据）<br/>静态密码 / 密钥对 / OAuth / 动态密码 / 验证码 / 生物识别"]
    end

    subgraph AUTHZ["授权层 (RBAC)"]
        ENGINE["RbacEngine<br/>check / check_batch / check_hierarchical"]
        STORE["AssignmentStore<br/>RoleStore"]
        CONSTRAINTS["ConstraintValidator<br/>SSD / DSD / 基数 / 前提"]
        CACHE["PermissionCache<br/>TTL 基础的 LRU"]
        AUDIT["AuditLogger"]
    end

    subgraph DB["数据库层"]
        MEMORY["InMemory Stores<br/>（零依赖参考实现）"]
        SQL["SQL Backend<br/>（功能: rbac-sql）"]
        REDIS["Redis Cache<br/>（功能: rbac-redis）"]
    end

    IDENTITY --> CREDENTIAL
    CREDENTIAL --> PASSPORT
    PASSPORT --> AUTH
    AUTH --> SESSION
    SESSION --> ENGINE
    ENGINE --> STORE
    ENGINE --> CONSTRAINTS
    ENGINE --> CACHE
    ENGINE --> AUDIT
    STORE --> MEMORY
    STORE --> SQL
    CACHE --> REDIS
```

## 认证层

Kirino 通过三步管道对用户进行认证：

```mermaid
flowchart LR
    I["Identity<br/>你是谁？"]
    C["Credential<br/>证明它"]
    P["Passport<br/>挑战通过"]

    I --> C --> P
```

### 身份类型

| 类型 | 描述 |
|------|-------------|
| **Anonymous（匿名）** | 未认证访客，最小权限 |
| **Basic（基本）** | 标准用户，初始仅有最小权限 |
| **Temporary（临时）** | 限时账户，自动过期 |
| **Service（服务）** | 用于权限委托的服务账户 |

### 凭证类型

| 类型 | 描述 |
|------|-------------|
| **OneTimeToken** | 一次性令牌，首次使用即消耗 |
| **Basic (JWT)** | 带有声明和过期时间的 JSON Web Token |
| **ServiceToken** | 服务账户的长期令牌 |

### 凭据（挑战）类型

| 类型 | 描述 |
|------|-------------|
| **StaticPassword** | 通过 argon2 验证的密码 |
| **KeyPair** | SSH 密钥或 TLS 证书验证 |
| **OAuth** | 第三方 OAuth 提供方 |
| **DynamicPassword** | TOTP/HOTP、邮箱验证码、短信验证码 |
| **Captcha** | reCAPTCHA 或类似机器人检测 |
| **Biological** | 指纹、声纹、面部识别 |
| **TemporaryWhitelist** | 限时白名单条目 |

## 授权层

RBAC 引擎遵循 ANSI INCITS 359-2004 标准，实现了全部三个 RBAC 层级：

```mermaid
graph TD
    subgraph RBAC0["RBAC0 — 基础"]
        B0["主体 ↔ 角色 ↔ 权限"]
    end
    subgraph RBAC1["RBAC1 — 层级"]
        B1["带循环检测的角色继承"]
    end
    subgraph RBAC2["RBAC2 — 约束"]
        B2["SSD / DSD / 基数 / 前提 / 时间"]
    end
    RBAC0 --> RBAC1 --> RBAC2
```

### 核心设计原则

1. **完全泛型**：下游项目通过 trait 定义自己的 `Permission` 和 `Subject` 类型。
2. **拒绝优先语义**：被拒绝的权限始终优先。
3. **内存优先**：所有后端都有零依赖参考实现。
4. **分层设计**：RBAC0/1/2 作为 `RbacEngine` 上的不同 impl 块分层实现。
5. **缓存感知**：权限检查通过 TTL 进行缓存以提升性能。

## 会话管理

会话连接认证与授权：

```mermaid
sequenceDiagram
    participant U as 用户
    participant A as AuthService
    participant SM as SessionManager
    participant E as RbacEngine

    U->>A: login(credentials)
    A->>A: 验证凭证
    A->>SM: create_session(subject, roles)
    SM->>SM: 验证 DSD 约束
    SM-->>A: Session
    A-->>U: JWT token
    U->>E: check(permission)
    E->>E: 解析角色 → 层级 → 约束
    E-->>U: 允许 / 拒绝
```

## 你应该从哪里开始

- **快速开始**：参见 [快速开始指南](../guides/quick-start.md) 了解最小配置。
- **RBAC 概念**：参见 [RBAC 核心概念](../guides/concepts.md) 了解详细的 RBAC 理论。
- **安装**：参见 [安装指南](../guides/installation.md) 了解功能标志和依赖。
- **术语表**：参见 [术语表](../guides/glossary.md) 了解关键术语定义。
