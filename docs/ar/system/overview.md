# نظرة عامة على النظام

kirino هو إطار مُصادقة وتخويل متعدّد الطبقات. تبني كل طبقة على ما تحتها، مع حدود سمات (trait) واضحة تتيح التخصيص.

```mermaid
graph TD
    subgraph SERVICE["Service Layer"]
        AUTH["AuthService<br/>register / login / verify"]
        SESSION["SessionManager<br/>create / activate / destroy"]
    end

    subgraph AUTHN["Authentication Layer"]
        IDENTITY["Identity<br/>Anonymous / Basic / Temporary / Service"]
        CREDENTIAL["Credential<br/>OneTime / JWT / ServiceToken"]
        PASSPORT["Passport<br/>StaticPassword / KeyPair / OAuth / DynamicPassword / Captcha / Biometric"]
    end

    subgraph AUTHZ["Authorization Layer (RBAC)"]
        ENGINE["RbacEngine<br/>check / check_batch / check_hierarchical"]
        STORE["AssignmentStore<br/>RoleStore"]
        CONSTRAINTS["ConstraintValidator<br/>SSD / DSD / Cardinality / Prerequisite"]
        CACHE["PermissionCache<br/>TTL-based LRU"]
        AUDIT["AuditLogger"]
    end

    subgraph DB["Database Layer"]
        MEMORY["InMemory Stores<br/>(zero-dependency reference impl)"]
        SQL["SQL Backend<br/>(feature: rbac-sql)"]
        REDIS["Redis Cache<br/>(feature: rbac-redis)"]
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

## طبقة المصادقة

يُصادِق kirino المستخدمين عبر خط أنابيب من ثلاث خطوات:

```mermaid
flowchart LR
    I["Identity<br/>Who are you?"]
    C["Credential<br/>Prove it"]
    P["Passport<br/>Challenge accepted"]

    I --> C --> P
```

### أنواع الهوية (Identity Types)

| النوع | الوصف |
|------|-------------|
| **Anonymous** | زائر غير مُصادَق، صلاحيات محدودة |
| **Basic** | مستخدم اعتيادي، يبدأ بصلاحيات محدودة |
| **Temporary** | حساب محدود زمنياً، ينتهي تلقائياً |
| **Service** | حساب خدمة لتفويض الصلاحيات |

### أنواع البيان الاعتمادي (Credential Types)

| النوع | الوصف |
|------|-------------|
| **OneTimeToken** | رمز يُستخدم مرة واحدة، يُستهلك عند أول استخدام |
| **Basic (JWT)** | JSON Web Token يحوي مطالبات (claims) وانتهاء صلاحية |
| **ServiceToken** | رمز طويل الأمد لحسابات الخدمة |

### أنواع جواز المرور / التحدّي (Passport Types)

| النوع | الوصف |
|------|-------------|
| **StaticPassword** | كلمة مرور تُتحقّق عبر argon2 |
| **KeyPair** | تحقّق مفتاح SSH أو شهادة TLS |
| **OAuth** | مزوّد OAuth من طرف ثالث |
| **DynamicPassword** | TOTP/HOTP، رمز بريد إلكتروني، رمز SMS |
| **Captcha** | reCAPTCHA أو ما يشبهها لكشف البوتّات |
| **Biological** | بصمة إصبع، صوت، التعرّف على الوجه |
| **TemporaryWhitelist** | إدراج في القائمة البيضاء محدود زمنياً |

## طبقة التخويل

يتبع محرّك RBAC معيار ANSI INCITS 359-2004 ويُطبّق مستويات RBAC الثلاثة كافةً:

```mermaid
graph TD
    subgraph RBAC0["RBAC0 — Base"]
        B0["Subject ↔ Role ↔ Permission"]
    end
    subgraph RBAC1["RBAC1 — Hierarchy"]
        B1["Role inheritance with cycle detection"]
    end
    subgraph RBAC2["RBAC2 — Constraints"]
        B2["SSD / DSD / Cardinality / Prerequisite / Temporal"]
    end
    RBAC0 --> RBAC1 --> RBAC2
```

### مبادئ التصميم الأساسية

1. **عام بالكامل**: تُعرّف المشاريع النهائية أنواع `Permission` و`Subject` الخاصة بها عبر السمات.
2. **دلالات تجاوز الرفض**: تأخذ الصلاحيات المرفوضة الأولوية دائماً.
3. **الذاكرة أولاً**: لكل المخازن الخلفية تطبيقات مرجعية صفرية التبعية.
4. **متعدّد الطبقات**: تُطبَّق RBAC0/1/2 ككتل impl منفصلة على `RbacEngine`.
5. **مدرك للذاكرة المؤقتة**: تُخزَّن فحوصات الصلاحيات مؤقتاً مع TTL للأداء.

## إدارة الجلسات

تربط الجلسات بين المصادقة والتخويل:

```mermaid
sequenceDiagram
    participant U as User
    participant A as AuthService
    participant SM as SessionManager
    participant E as RbacEngine

    U->>A: login(credentials)
    A->>A: verify credentials
    A->>SM: create_session(subject, roles)
    SM->>SM: validate DSD constraints
    SM-->>A: Session
    A-->>U: JWT token
    U->>E: check(permission)
    E->>E: resolve roles → hierarchy → constraints
    E-->>U: allow / deny
```

## من أين تبدأ

- **البدء السريع**: راجع [دليل البدء السريع](../guides/quick-start.md) لإعداد أدنى.
- **مفاهيم RBAC**: راجع [المفاهيم الأساسية لـ RBAC](../guides/concepts.md) لنظرية RBAC بالتفصيل.
- **التثبيت**: راجع [دليل التثبيت](../guides/installation.md) لأعلام الميزات والتبعيات.
- **المصطلحات**: راجع [المصطلحات](../guides/glossary.md) لتعريفات المصطلحات الأساسية.
