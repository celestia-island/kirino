# Обзор системы

Kirino — это многоуровневый фреймворк аутентификации и авторизации. Каждый уровень строится на нижележащем, с чёткими границами trait для настройки.

```mermaid
graph TD
    subgraph SERVICE["Сервисный уровень"]
        AUTH["AuthService<br/>регистрация / вход / проверка"]
        SESSION["SessionManager<br/>создание / активация / уничтожение"]
    end

    subgraph AUTHN["Уровень аутентификации"]
        IDENTITY["Identity<br/>Анонимный / Базовый / Временный / Сервисный"]
        CREDENTIAL["Credential<br/>Одноразовый / JWT / Сервисный токен"]
        PASSPORT["Passport<br/>Статический пароль / Пара ключей / OAuth / Динамический пароль / Капча / Биометрия"]
    end

    subgraph AUTHZ["Уровень авторизации (RBAC)"]
        ENGINE["RbacEngine<br/>check / check_batch / check_hierarchical"]
        STORE["AssignmentStore<br/>RoleStore"]
        CONSTRAINTS["ConstraintValidator<br/>SSD / DSD / Кардинальность / Предварительные условия"]
        CACHE["PermissionCache<br/>LRU на основе TTL"]
        AUDIT["AuditLogger"]
    end

    subgraph DB["Уровень базы данных"]
        MEMORY["InMemory Stores<br/>(эталонная реализация без зависимостей)"]
        SQL["SQL Backend<br/>(функция: rbac-sql)"]
        REDIS["Redis Cache<br/>(функция: rbac-redis)"]
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

## Уровень аутентификации

Kirino аутентифицирует пользователей через трёхшаговый конвейер:

```mermaid
flowchart LR
    I["Identity<br/>Кто вы?"]
    C["Credential<br/>Докажите"]
    P["Passport<br/>Вызов принят"]

    I --> C --> P
```

### Типы идентичности

| Тип | Описание |
|------|-------------|
| **Anonymous (Анонимный)** | Неаутентифицированный посетитель, минимальные разрешения |
| **Basic (Базовый)** | Стандартный пользователь, начинает с минимальных разрешений |
| **Temporary (Временный)** | Учётная запись с ограниченным сроком, автоматически истекает |
| **Service (Сервисный)** | Сервисная учётная запись для делегирования разрешений |

### Типы учётных данных

| Тип | Описание |
|------|-------------|
| **OneTimeToken** | Одноразовый токен, расходуется при первом использовании |
| **Basic (JWT)** | JSON Web Token с утверждениями и сроком действия |
| **ServiceToken** | Долгосрочный токен для сервисных учётных записей |

### Типы паспортов (вызовов)

| Тип | Описание |
|------|-------------|
| **StaticPassword** | Пароль, проверяемый через argon2 |
| **KeyPair** | Проверка SSH-ключа или TLS-сертификата |
| **OAuth** | Сторонний OAuth-провайдер |
| **DynamicPassword** | TOTP/HOTP, код по email, код по SMS |
| **Captcha** | reCAPTCHA или аналогичное обнаружение ботов |
| **Biological** | Отпечаток пальца, голос, распознавание лица |
| **TemporaryWhitelist** | Временная запись в белом списке |

## Уровень авторизации

Движок RBAC следует стандарту ANSI INCITS 359-2004 и реализует все три уровня RBAC:

```mermaid
graph TD
    subgraph RBAC0["RBAC0 — Базовый"]
        B0["Субъект ↔ Роль ↔ Разрешение"]
    end
    subgraph RBAC1["RBAC1 — Иерархия"]
        B1["Наследование ролей с обнаружением циклов"]
    end
    subgraph RBAC2["RBAC2 — Ограничения"]
        B2["SSD / DSD / Кардинальность / Предварительные / Временные"]
    end
    RBAC0 --> RBAC1 --> RBAC2
```

### Основные принципы проектирования

1. **Полностью обобщённый**: Проекты-потребители определяют свои типы `Permission` и `Subject` через trait.
2. **Семантика приоритета отказа**: Отказанные разрешения всегда имеют приоритет.
3. **Сначала в памяти**: Все бэкенды имеют эталонные реализации без зависимостей.
4. **Многоуровневый**: RBAC0/1/2 реализованы как отдельные блоки impl на `RbacEngine`.
5. **С учётом кэширования**: Проверки разрешений кэшируются с TTL для производительности.

## Управление сессиями

Сессии связывают аутентификацию и авторизацию:

```mermaid
sequenceDiagram
    participant U as Пользователь
    participant A as AuthService
    participant SM as SessionManager
    participant E as RbacEngine

    U->>A: login(credentials)
    A->>A: проверка учётных данных
    A->>SM: create_session(subject, roles)
    SM->>SM: проверка ограничений DSD
    SM-->>A: Session
    A-->>U: JWT token
    U->>E: check(permission)
    E->>E: разрешение ролей → иерархия → ограничения
    E-->>U: разрешить / отказать
```

## С чего начать

- **Быстрый старт**: См. [Руководство по быстрому старту](../guides/quick-start.md) для минимальной настройки.
- **Концепции RBAC**: См. [Основные концепции RBAC](../guides/concepts.md) для детальной теории RBAC.
- **Установка**: См. [Руководство по установке](../guides/installation.md) для флагов функций и зависимостей.
- **Глоссарий**: См. [Глоссарий](../guides/glossary.md) для определений ключевых терминов.
