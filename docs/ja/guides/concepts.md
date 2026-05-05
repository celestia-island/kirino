# RBAC コアコンセプト

## RBAC とは？

ロールベースアクセス制御（RBAC）は、パーミッションをロールに割り当て、ロールをユーザー（サブジェクト）に割り当てる認可モデルです。この間接的なマッピングにより、大規模なパーミッション管理が簡素化されます——各ユーザーに個別にパーミッションを付与する代わりに、ロールに割り当てます。

## コアエンティティ

### サブジェクト (Subject)

**サブジェクト** は、パーミッションを付与できる任意のエンティティです——通常はユーザー、サービスアカウント、または自動化エージェントです。kirino では、サブジェクトは `Subject` trait を実装します：

| Trait | 目的 |
|-------|---------|
| `Subject` | 認可可能なエンティティの基本 trait |
| `Delegatable` | 自身のパーミッションを他のサブジェクトに委譲できるサブジェクト |

### パーミッション (Permission)

**パーミッション** は認可の最小単位です——リソースドメインに対する名前付き操作：

| Trait | 目的 |
|-------|---------|
| `Permission` | `name() -> &str`（シリアライゼーション用）、`domain() -> &str`（グループ化用） |

### ロール (Role)

**ロール** はパーミッションの名前付きコレクションです：

| Trait | 目的 |
|-------|---------|
| `Role<P>` | 基本ロール：パーミッションのセットを保持 |
| `HierarchicalRole<P>` | `Role<P>` を拡張し、継承のための `parent_roles()` を追加 |

## RBAC レベル

Kirino は ANSI INCITS 359-2004 標準の 3 つのレベルを実装しています：

```mermaid
graph TD
    subgraph RBAC0["RBAC0 — 基本モデル"]
        S0["サブジェクト"] --> A0["割り当て"]
        A0 --> R0["ロール"]
        R0 --> P0["パーミッション"]
    end
    subgraph RBAC1["RBAC1 — 階層モデル"]
        R1["親ロール"] -->|継承| R1C["子ロール"]
        R1C --> P1["パーミッション（和集合）"]
    end
    subgraph RBAC2["RBAC2 — 制約モデル"]
        SSD["SSD：静的職務分離"]
        DSD["DSD：動的職務分離"]
        CARD["基数制約"]
        PREQ["前提制約"]
        TEMP["時間制約"]
    end
    RBAC0 --> RBAC1
    RBAC1 --> RBAC2
```

### RBAC0 — 基本モデル

基盤：ユーザーはロールに割り当てられ、ロールはパーミッションを保持します。

```
サブジェクト ──割り当て──→ ロール ──含む──→ パーミッション
```

- "editor" ロールを持つユーザーは、"editor" ロール内のすべてのパーミッションを取得します。
- 拒否優先セマンティクス：`denied_permissions` は付与されたパーミッションより優先されます。
- 追加パーミッション：ロール割り当てを変更せずに一時的な権限昇格が可能です。

### RBAC1 — 階層モデル

ロールは親ロールから**継承**でき、パーミッションツリーを形成します：

```mermaid
graph TD
    ADMIN["admin<br/>（全パーミッション）"] --> OPERATOR["operator<br/>（読み取り + 書き込み + デプロイ）"]
    ADMIN --> AUDITOR["auditor<br/>（読み取り + 監査）"]
    OPERATOR --> VIEWER["viewer<br/>（読み取り専用）"]
```

- 子ロールは親ロールのすべてのパーミッションを継承します（和集合セマンティクス）。
- 循環検出が継承解決時の無限ループを防止します。
- 多重継承をサポート：1 つのロールが複数の親を持つことができます。

### RBAC2 — 制約モデル

制約は職務分離やその他のビジネスルールを強制します：

#### 静的職務分離 (SSD)

競合するロールは**同じユーザーに割り当てられません**。

```
SsdPolicy { roles: {"billing", "auditor"}, cardinality: 2 }
→ ユーザーは "billing" と "auditor" を同時に保持できません。
```

#### 動的職務分離 (DSD)

競合するロールは**割り当て可能**ですが、**同じセッションでアクティブにできません**。

```
DsdPolicy { roles: {"author", "reviewer"}, cardinality: 2 }
→ ユーザーは author と reviewer の両方になれますが、セッションごとに 1 つだけアクティブにできます。
```

#### 基数制約

特定のロールを保持できるユーザー数を制限します。

```
CardinalityConstraint { role: "admin", max: 3 }
→ 最大 3 ユーザーが管理者になれます。
```

#### 前提制約

ユーザーはロール B を割り当てられる前にロール A を保持している必要があります。

```
PrerequisiteConstraint { role: "operator", requires: "viewer" }
→ 既存の viewer のみが operator に昇格できます。
```

#### 時間制約

ロールは時間枠内でのみ有効です。

```
TemporalConstraint { role: "temp-admin", valid_from: ..., valid_until: ... }
→ 自動失効；valid_until を過ぎると自動的に取り消されます。
```

## 決定フロー

`RbacEngine::check(subject, permission)` が呼び出されたとき：

```mermaid
flowchart TD
    START(["check(subject, permission)"]) --> CACHE{"キャッシュヒット？"}
    CACHE -->|はい| RETURN_CACHED(["キャッシュ結果を返す"])
    CACHE -->|いいえ| DENIED{"denied_permissions に含まれる？"}
    DENIED -->|はい| RETURN_DENY(["拒否 — キャッシュに保存"])
    DENIED -->|いいえ| EXTRA{"extra_permissions に含まれる？"}
    EXTRA -->|はい| RETURN_ALLOW(["許可 — キャッシュに保存"])
    EXTRA -->|いいえ| ROLES["割り当てられたロールを解決"]
    ROLES --> HIER["ロール階層を展開"]
    HIER --> CHECK["パーミッションがロール権限に含まれるか確認"]
    CHECK -->|はい| RETURN_ALLOW2(["許可 — キャッシュに保存"])
    CHECK -->|いいえ| RETURN_DENY2(["拒否 — キャッシュに保存"])
```

重要なセマンティクス：**拒否優先**。拒否されたパーミッションはロールや追加パーミッションによって付与できません。

## 主要 Trait 概要

```mermaid
classDiagram
    class Subject {
        +subject_id() &str
        +subject_type() &str
    }
    class Permission {
        +name() &str
        +domain() &str
    }
    class Role~P~ {
        +role_name() &str
        +permissions() HashSet~P~
    }
    class HierarchicalRole~P~ {
        +parent_roles() Vec~String~
    }
    class AssignmentStore~S,R,P~ {
        +assign_role() Result
        +revoke_role() Result
        +roles_of() Vec~String~
        +extra_permissions() HashSet~P~
        +denied_permissions() HashSet~P~
    }
    class ConstraintStore {
        +list_ssd_policies() Vec~SsdPolicy~
        +list_dsd_policies() Vec~DsdPolicy~
        +list_cardinality_constraints() Vec~CardinalityConstraint~
    }
    class RbacEngine~S,P,R,A~ {
        +check() bool
        +check_batch() HashMap~P,bool~
        +effective_permissions() HashSet~P~
        +check_hierarchical() bool
    }

    Subject --> AssignmentStore : 割り当て経由
    Role~P~ <|-- HierarchicalRole~P~
    AssignmentStore --> Role~P~ : 参照
    RbacEngine~S,P,R,A~ --> AssignmentStore
    RbacEngine~S,P,R,A~ --> ConstraintStore
```
