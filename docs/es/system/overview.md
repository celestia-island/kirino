# Visión General del Sistema

Kirino es un framework de autenticación y autorización en capas. Cada capa se construye sobre la inferior, con límites de trait claros para personalización.

```mermaid
graph TD
    subgraph SERVICE["Capa de Servicio"]
        AUTH["AuthService<br/>registro / inicio de sesión / verificación"]
        SESSION["SessionManager<br/>crear / activar / destruir"]
    end

    subgraph AUTHN["Capa de Autenticación"]
        IDENTITY["Identity<br/>Anónimo / Básico / Temporal / Servicio"]
        CREDENTIAL["Credential<br/>Un solo uso / JWT / Token de servicio"]
        PASSPORT["Passport<br/>Contraseña estática / Par de claves / OAuth / Contraseña dinámica / Captcha / Biométrico"]
    end

    subgraph AUTHZ["Capa de Autorización (RBAC)"]
        ENGINE["RbacEngine<br/>check / check_batch / check_hierarchical"]
        STORE["AssignmentStore<br/>RoleStore"]
        CONSTRAINTS["ConstraintValidator<br/>SSD / DSD / Cardinalidad / Prerrequisito"]
        CACHE["PermissionCache<br/>LRU basado en TTL"]
        AUDIT["AuditLogger"]
    end

    subgraph DB["Capa de Base de Datos"]
        MEMORY["InMemory Stores<br/>(implementación de referencia sin dependencias)"]
        SQL["SQL Backend<br/>(funcionalidad: rbac-sql)"]
        REDIS["Redis Cache<br/>(funcionalidad: rbac-redis)"]
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

## Capa de Autenticación

Kirino autentica usuarios a través de un pipeline de tres pasos:

```mermaid
flowchart LR
    I["Identity<br/>¿Quién eres?"]
    C["Credential<br/>Pruébalo"]
    P["Passport<br/>Desafío aceptado"]

    I --> C --> P
```

### Tipos de Identidad

| Tipo | Descripción |
|------|-------------|
| **Anonymous (Anónimo)** | Visitante no autenticado, permisos mínimos |
| **Basic (Básico)** | Usuario estándar, comienza con permisos mínimos |
| **Temporary (Temporal)** | Cuenta con límite de tiempo, expira automáticamente |
| **Service (Servicio)** | Cuenta de servicio para delegación de permisos |

### Tipos de Credencial

| Tipo | Descripción |
|------|-------------|
| **OneTimeToken** | Token de un solo uso, se consume en el primer uso |
| **Basic (JWT)** | JSON Web Token con claims y expiración |
| **ServiceToken** | Token de larga duración para cuentas de servicio |

### Tipos de Pasaporte (Desafío)

| Tipo | Descripción |
|------|-------------|
| **StaticPassword** | Contraseña verificada mediante argon2 |
| **KeyPair** | Verificación de clave SSH o certificado TLS |
| **OAuth** | Proveedor OAuth de terceros |
| **DynamicPassword** | TOTP/HOTP, código por email, código SMS |
| **Captcha** | reCAPTCHA o detección de bots similar |
| **Biological** | Huella dactilar, voz, reconocimiento facial |
| **TemporaryWhitelist** | Entrada temporal en lista blanca |

## Capa de Autorización

El motor RBAC sigue el estándar ANSI INCITS 359-2004 e implementa los tres niveles RBAC:

```mermaid
graph TD
    subgraph RBAC0["RBAC0 — Base"]
        B0["Sujeto ↔ Rol ↔ Permiso"]
    end
    subgraph RBAC1["RBAC1 — Jerarquía"]
        B1["Herencia de roles con detección de ciclos"]
    end
    subgraph RBAC2["RBAC2 — Restricciones"]
        B2["SSD / DSD / Cardinalidad / Prerrequisito / Temporal"]
    end
    RBAC0 --> RBAC1 --> RBAC2
```

### Principios de Diseño Fundamentales

1. **Completamente genérico**: Los proyectos consumidores definen sus propios tipos `Permission` y `Subject` mediante traits.
2. **Semántica de denegación prioritaria**: Los permisos denegados siempre tienen prioridad.
3. **Primero en memoria**: Todos los backends tienen implementaciones de referencia sin dependencias.
4. **En capas**: RBAC0/1/2 se implementan como bloques impl separados en `RbacEngine`.
5. **Conciente de caché**: Las verificaciones de permisos se cachean con TTL para rendimiento.

## Gestión de Sesiones

Las sesiones conectan la autenticación y la autorización:

```mermaid
sequenceDiagram
    participant U as Usuario
    participant A as AuthService
    participant SM as SessionManager
    participant E as RbacEngine

    U->>A: login(credentials)
    A->>A: verificar credenciales
    A->>SM: create_session(subject, roles)
    SM->>SM: validar restricciones DSD
    SM-->>A: Session
    A-->>U: JWT token
    U->>E: check(permission)
    E->>E: resolver roles → jerarquía → restricciones
    E-->>U: permitir / denegar
```

## Por Dónde Empezar

- **Inicio rápido**: Consulta la [Guía de Inicio Rápido](../guides/quick-start.md) para una configuración mínima.
- **Conceptos RBAC**: Consulta [Conceptos Básicos de RBAC](../guides/concepts.md) para teoría detallada.
- **Instalación**: Consulta la [Guía de Instalación](../guides/installation.md) para banderas y dependencias.
- **Glosario**: Consulta el [Glosario](../guides/glossary.md) para definiciones de términos clave.
