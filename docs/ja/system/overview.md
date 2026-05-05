# システム概要

Kirino は階層化された認証・認可フレームワークです。各レイヤーは下位レイヤーの上に構築され、明確な trait 境界によるカスタマイズを可能にします。

```mermaid
graph TD
    subgraph SERVICE["サービス層"]
        AUTH["AuthService<br/>登録 / ログイン / 検証"]
        SESSION["SessionManager<br/>作成 / アクティブ化 / 破棄"]
    end

    subgraph AUTHN["認証層"]
        IDENTITY["Identity<br/>匿名 / 基本 / 一時 / サービス"]
        CREDENTIAL["Credential<br/>ワンタイム / JWT / サービストークン"]
        PASSPORT["Passport<br/>静的パスワード / キーペア / OAuth / 動的パスワード / CAPTCHA / 生体認証"]
    end

    subgraph AUTHZ["認可層 (RBAC)"]
        ENGINE["RbacEngine<br/>check / check_batch / check_hierarchical"]
        STORE["AssignmentStore<br/>RoleStore"]
        CONSTRAINTS["ConstraintValidator<br/>SSD / DSD / 基数 / 前提"]
        CACHE["PermissionCache<br/>TTL ベース LRU"]
        AUDIT["AuditLogger"]
    end

    subgraph DB["データベース層"]
        MEMORY["InMemory Stores<br/>（ゼロ依存リファレンス実装）"]
        SQL["SQL Backend<br/>（フィーチャー: rbac-sql）"]
        REDIS["Redis Cache<br/>（フィーチャー: rbac-redis）"]
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

## 認証層

Kirino は 3 ステップのパイプラインでユーザーを認証します：

```mermaid
flowchart LR
    I["Identity<br/>あなたは誰？"]
    C["Credential<br/>証明する"]
    P["Passport<br/>チャレンジ通過"]

    I --> C --> P
```

### アイデンティティタイプ

| タイプ | 説明 |
|------|-------------|
| **Anonymous（匿名）** | 未認証の訪問者、最小限のパーミッション |
| **Basic（基本）** | 標準ユーザー、最小限のパーミッションから開始 |
| **Temporary（一時）** | 期間限定アカウント、自動失効 |
| **Service（サービス）** | パーミッション委譲用のサービスアカウント |

### クレデンシャルタイプ

| タイプ | 説明 |
|------|-------------|
| **OneTimeToken** | ワンタイムトークン、初回使用で消費 |
| **Basic (JWT)** | クレームと有効期限付きの JSON Web Token |
| **ServiceToken** | サービスアカウント用の長期トークン |

### パスポート（チャレンジ）タイプ

| タイプ | 説明 |
|------|-------------|
| **StaticPassword** | argon2 で検証されるパスワード |
| **KeyPair** | SSH キーまたは TLS 証明書検証 |
| **OAuth** | サードパーティ OAuth プロバイダー |
| **DynamicPassword** | TOTP/HOTP、メールコード、SMS コード |
| **Captcha** | reCAPTCHA または類似のボット検出 |
| **Biological** | 指紋、声紋、顔認識 |
| **TemporaryWhitelist** | 期間限定ホワイトリストエントリ |

## 認可層

RBAC エンジンは ANSI INCITS 359-2004 標準に従い、3 つの RBAC レベルすべてを実装しています：

```mermaid
graph TD
    subgraph RBAC0["RBAC0 — 基本"]
        B0["サブジェクト ↔ ロール ↔ パーミッション"]
    end
    subgraph RBAC1["RBAC1 — 階層"]
        B1["循環検出付きロール継承"]
    end
    subgraph RBAC2["RBAC2 — 制約"]
        B2["SSD / DSD / 基数 / 前提 / 時間"]
    end
    RBAC0 --> RBAC1 --> RBAC2
```

### コアデザイン原則

1. **完全にジェネリック**：下流プロジェクトが trait を通じて独自の `Permission` と `Subject` 型を定義。
2. **拒否優先セマンティクス**：拒否されたパーミッションが常に優先。
3. **インメモリファースト**：すべてのバックエンドにゼロ依存のリファレンス実装を提供。
4. **階層化**：RBAC0/1/2 を `RbacEngine` 上の個別の impl ブロックとして階層化。
5. **キャッシュ対応**：パーミッションチェックは TTL でキャッシュされパフォーマンスを向上。

## セッション管理

セッションは認証と認可をつなぎます：

```mermaid
sequenceDiagram
    participant U as ユーザー
    participant A as AuthService
    participant SM as SessionManager
    participant E as RbacEngine

    U->>A: login(credentials)
    A->>A: クレデンシャルを検証
    A->>SM: create_session(subject, roles)
    SM->>SM: DSD 制約を検証
    SM-->>A: Session
    A-->>U: JWT token
    U->>E: check(permission)
    E->>E: ロール解決 → 階層 → 制約
    E-->>U: 許可 / 拒否
```

## どこから始めるか

- **クイックスタート**：最小構成は [クイックスタートガイド](../guides/quick-start.md) を参照。
- **RBAC 概念**：詳細な RBAC 理論は [RBAC コアコンセプト](../guides/concepts.md) を参照。
- **インストール**：フィーチャーフラグと依存関係は [インストールガイド](../guides/installation.md) を参照。
- **用語集**：主要用語の定義は [用語集](../guides/glossary.md) を参照。
