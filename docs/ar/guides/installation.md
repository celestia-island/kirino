# التثبيت

## Cargo.toml

```toml
[dependencies]
kirino = "0.1"
```

## أعلام الميزات (Feature Flags)

| الميزة | الوصف | التبعيات |
|---------|-------------|--------------|
| (الافتراضية) | نواة RBAC + المخازن في الذاكرة | — |
| `rbac-core` | سمات ومحرّك RBAC فقط | — |
| `rbac-inmemory` | مخازن الإسناد/الأدوار في الذاكرة | `rbac-core` |
| `rbac-hierarchy` | وراثة الأدوار الهرمية وفق RBAC1 | `rbac-core` |
| `rbac-constraints` | نماذج القيود وفق RBAC2 (SSD/DSD) | `rbac-core` |
| `rbac-sql` | مخازن دائمة قائمة على SQL | `sqlx` |
| `rbac-sea-orm` | نماذج كيانات SeaORM | `sea-orm` |
| `rbac-redis` | ذاكرة صلاحيات مؤقتة عبر Redis | `redis` |
| `rbac-full` | تفعيل جميع الميزات | كل ما سبق |

### مثال: إعداد بكامل الميزات

```toml
[dependencies]
kirino = { version = "0.1", features = ["rbac-full"] }
```

### مثال: إعداد أدنى

```toml
[dependencies]
kirino = { version = "0.1", default-features = false, features = ["rbac-core"] }
```

## التحقق من التثبيت

```bash
cargo build
cargo test
```

يجب أن تمرّ جميع الاختبارات دون أخطاء.

## المتطلبات

- Rust 1.75+ (الإصدار 2021)
- اختياري: PostgreSQL (من أجل `rbac-sql`)، Redis (من أجل `rbac-redis`)، SeaORM CLI (من أجل `rbac-sea-orm`)
