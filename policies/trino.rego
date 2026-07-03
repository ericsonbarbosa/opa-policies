package trino

import future.keywords.in
import future.keywords.if

# ==============================================================================
# POLÍTICA TRINO-OPA (Default Deny + Allow List Explícita)
# Segurança máxima: apenas o que está explicitamente permitido é autorizado
# ==============================================================================

default allow := false

# ------------------------------------------------------------------------------
# ADMIN: Acesso total irrestrito
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "admin"
}

# ------------------------------------------------------------------------------
# RODRIGO: Operações de infraestrutura (necessárias para queries funcionarem)
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation in [
        "ExecuteQuery",
        "AccessCatalog",
        "CheckCanAccessCatalog",
        "ShowSchemas",
        "FilterSchemas",
        "ShowTables",
        "FilterTables",
        "ShowColumns",
        "FilterColumns",
        "UseSchema"
    ]
}

# ------------------------------------------------------------------------------
# RODRIGO: SELECT em qualquer schema EXCETO financeiro
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation == "SelectFromColumns"
    input.action.resource.table.schemaName != "financeiro"
}

# ------------------------------------------------------------------------------
# RODRIGO: INSERT apenas em sandbox e api_lab
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation == "InsertIntoTable"
    input.action.resource.table.schemaName in ["sandbox", "api_lab"]
}

# ------------------------------------------------------------------------------
# RODRIGO: CREATE TABLE apenas em sandbox e api_lab
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation == "CreateTable"
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