package trino

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# ==============================================================================
# ESTRATÉGIA HÍBRIDA: Default Deny + Allow List + Deny List
# Seguro por padrão, flexível para usuários autorizados
# ==============================================================================

default allow := false

# ------------------------------------------------------------------------------
# ROLES (Papéis de Acesso)
# Centraliza quem tem acesso ao sistema
# ------------------------------------------------------------------------------
user_roles := {
    "admin": ["admin"],
    "rodrigo": ["analista"],
    # Adicione novos usuários aqui explicitamente:
    # "flavio": ["analista"],
    # "maria": ["gerente"],
}

# Função auxiliar para verificar se usuário tem um role
has_role(user, role) if {
    role in user_roles[user]
}

# ------------------------------------------------------------------------------
# ADMIN: Acesso total irrestrito
# ------------------------------------------------------------------------------
allow if {
    has_role(input.context.identity.user, "admin")
}

# ------------------------------------------------------------------------------
# ANALISTA: Operações de infraestrutura (necessárias para queries funcionarem)
# ------------------------------------------------------------------------------
allow if {
    has_role(input.context.identity.user, "analista")
    input.action.operation in [
        "CheckCanAccessCatalog",
        "CheckCanShowSchemas",
        "CheckCanShowTables",
        "FilterSchemas",
        "FilterTables",
        "FilterColumns",
        "ShowSchemas",
        "ShowTables",
        "ShowColumns",
        "UseSchema"
    ]
}

# ------------------------------------------------------------------------------
# ANALISTA: SELECT em qualquer schema EXCETO financeiro
# ------------------------------------------------------------------------------
allow if {
    has_role(input.context.identity.user, "analista")
    input.action.operation == "SelectFromColumns"
    input.action.resource.table.schemaName != "financeiro"
}

# ------------------------------------------------------------------------------
# ANALISTA: INSERT e CREATE TABLE apenas em sandbox e api_lab
# ------------------------------------------------------------------------------
allow if {
    has_role(input.context.identity.user, "analista")
    input.action.operation in ["InsertIntoTable", "CreateTable"]
    input.action.resource.table.schemaName in ["sandbox", "api_lab"]
}

# ------------------------------------------------------------------------------
# AUDITORIA: Loga todas as negações
# ------------------------------------------------------------------------------
deny contains msg if {
    not allow
    msg := sprintf(
        "OPA DENIED: user=%s op=%s schema=%s table=%s",
        [
            input.context.identity.user,
            input.action.operation,
            object.get(input.action.resource.table, "schemaName", "N/A"),
            object.get(input.action.resource.table, "tableName", "N/A")
        ]
    )
}