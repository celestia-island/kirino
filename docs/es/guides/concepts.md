# Conceptos Básicos de RBAC

## ¿Qué es RBAC?

El Control de Acceso Basado en Roles (RBAC) es un modelo de autorización que asigna permisos a roles, y roles a usuarios (sujetos). Esta indirección simplifica la gestión de permisos a escala — en lugar de otorgar permisos a cada usuario individualmente, los asignas a un rol.

## Entidades Principales

### Sujeto (Subject)

Un **Sujeto** es cualquier entidad a la que se le pueden otorgar permisos — típicamente un usuario, cuenta de servicio o agente automatizado. En kirino, los sujetos implementan el trait `Subject`:

| Trait | Propósito |
|-------|---------|
| `Subject` | Trait base para cualquier entidad autorizable |
| `Delegatable` | Un sujeto que puede delegar sus permisos a otro sujeto |

### Permiso (Permission)

Un **Permiso** es la unidad atómica de autorización — una acción nombrada sobre un dominio de recurso:

| Trait | Propósito |
|-------|---------|
| `Permission` | `name() -> &str` para serialización, `domain() -> &str` para agrupación |

### Rol (Role)

Un **Rol** es una colección nombrada de permisos:

| Trait | Propósito |
|-------|---------|
| `Role<P>` | Rol base: contiene un conjunto de permisos |
| `HierarchicalRole<P>` | Extiende `Role<P>`, agrega `parent_roles()` para herencia |

## Niveles de RBAC

Kirino implementa los tres niveles del estándar ANSI INCITS 359-2004:

```mermaid
graph TD
    subgraph RBAC0["RBAC0 — Modelo Base"]
        S0["Sujeto"] --> A0["Asignación"]
        A0 --> R0["Rol"]
        R0 --> P0["Permiso"]
    end
    subgraph RBAC1["RBAC1 — Jerarquía"]
        R1["Rol Padre"] -->|hereda| R1C["Rol Hijo"]
        R1C --> P1["Permisos (unión)"]
    end
    subgraph RBAC2["RBAC2 — Restricciones"]
        SSD["SSD: Separación Estática de Deberes"]
        DSD["DSD: Separación Dinámica de Deberes"]
        CARD["Restricciones de Cardinalidad"]
        PREQ["Restricciones de Prerrequisito"]
        TEMP["Restricciones Temporales"]
    end
    RBAC0 --> RBAC1
    RBAC1 --> RBAC2
```

### RBAC0 — Modelo Base

La base: los usuarios se asignan a roles, los roles contienen permisos.

```
Sujeto ──asignado──→ Rol ──contiene──→ Permiso
```

- Un usuario con el rol "editor" obtiene todos los permisos del rol "editor".
- Semántica de denegación prioritaria: `denied_permissions` tiene prioridad sobre los otorgados.
- Permisos extra: elevación temporal sin cambiar la asignación de rol.

### RBAC1 — Modelo Jerárquico

Los roles pueden **heredar** de roles padre, formando un árbol de permisos:

```mermaid
graph TD
    ADMIN["admin<br/>(todos los permisos)"] --> OPERATOR["operator<br/>(lectura + escritura + despliegue)"]
    ADMIN --> AUDITOR["auditor<br/>(lectura + auditoría)"]
    OPERATOR --> VIEWER["viewer<br/>(solo lectura)"]
```

- Los roles hijo heredan todos los permisos de los padres (semántica de unión).
- La detección de ciclos previene bucles infinitos durante la resolución de herencia.
- Herencia múltiple soportada: un rol puede tener múltiples padres.

### RBAC2 — Modelo de Restricciones

Las restricciones imponen separación de deberes y otras reglas de negocio:

#### Separación Estática de Deberes (SSD)

Los roles en conflicto **no pueden asignarse** al mismo usuario.

```
SsdPolicy { roles: {"billing", "auditor"}, cardinality: 2 }
→ Un usuario no puede tener simultáneamente "billing" y "auditor".
```

#### Separación Dinámica de Deberes (DSD)

Los roles en conflicto **pueden asignarse** pero **no pueden activarse** en la misma sesión.

```
DsdPolicy { roles: {"author", "reviewer"}, cardinality: 2 }
→ Un usuario puede ser author y reviewer, pero solo activar uno por sesión.
```

#### Restricción de Cardinalidad

Limita cuántos usuarios pueden tener un rol determinado.

```
CardinalityConstraint { role: "admin", max: 3 }
→ Como máximo 3 usuarios pueden ser administradores.
```

#### Restricción de Prerrequisito

Un usuario debe tener el rol A antes de que se le asigne el rol B.

```
PrerequisiteConstraint { role: "operator", requires: "viewer" }
→ Solo los viewer existentes pueden ser promovidos a operator.
```

#### Restricción Temporal

Un rol solo es válido dentro de una ventana de tiempo.

```
TemporalConstraint { role: "temp-admin", valid_from: ..., valid_until: ... }
→ Expira automáticamente; se revoca automáticamente después de valid_until.
```

## Flujo de Decisión

Cuando se llama a `RbacEngine::check(subject, permission)`:

```mermaid
flowchart TD
    START(["check(subject, permission)"]) --> CACHE{"¿Acierto en caché?"}
    CACHE -->|sí| RETURN_CACHED(["Devolver resultado cacheado"])
    CACHE -->|no| DENIED{"¿En denied_permissions?"}
    DENIED -->|sí| RETURN_DENY(["DENEGAR — persistir en caché"])
    DENIED -->|no| EXTRA{"¿En extra_permissions?"}
    EXTRA -->|sí| RETURN_ALLOW(["PERMITIR — persistir en caché"])
    EXTRA -->|no| ROLES["Resolver roles asignados"]
    ROLES --> HIER["Expandir jerarquía de roles"]
    HIER --> CHECK["Verificar si el permiso ∈ permisos del rol"]
    CHECK -->|sí| RETURN_ALLOW2(["PERMITIR — persistir en caché"])
    CHECK -->|no| RETURN_DENY2(["DENEGAR — persistir en caché"])
```

Semántica clave: **la denegación tiene prioridad**. Un permiso denegado no puede ser otorgado por roles o permisos extra.

## Resumen de Traits Clave

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

    Subject --> AssignmentStore : vía asignación
    Role~P~ <|-- HierarchicalRole~P~
    AssignmentStore --> Role~P~ : referencia
    RbacEngine~S,P,R,A~ --> AssignmentStore
    RbacEngine~S,P,R,A~ --> ConstraintStore
```
