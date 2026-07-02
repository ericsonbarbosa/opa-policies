package trino

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# ==============================================================================
# TRINO + OPA
# Estratégia:
#   - Tudo negado por padrão
#   - Admin possui acesso irrestrito
#   - Rodrigo possui acesso controlado
# ==============================================================================

default allow := false

# ==============================================================================
# ADMIN
# ==============================================================================

allow if {
    input.context.identity.user == "admin"
}

# ==============================================================================
# RODRIGO - OPERAÇÕES BÁSICAS DO ENGINE
# ==============================================================================

allow if {
    input.context.identity.user == "rodrigo"

    input.action.operation in [
        "ExecuteQuery",
        "ViewQuery",
        "FilterCatalogs",
        "FilterViewQueryOwnedBy"
    ]
}

# ==============================================================================
# RODRIGO - ACESSO A CATÁLOGOS
# ==============================================================================

allow if {
    input.context.identity.user == "rodrigo"

    input.action.operation in [
        "AccessCatalog",
        "CheckCanAccessCatalog",
        "ShowCatalogs"
    ]

    input.action.resource.catalog.catalogName in [
        "iceberg",
        "system",
        "memory",
        "tpch"
    ]
}

# ==============================================================================
# RODRIGO - LISTAGEM DE SCHEMAS
# ==============================================================================

allow if {
    input.context.identity.user == "rodrigo"

    input.action.operation == "FilterSchemas"
}

allow if {
    input.context.identity.user == "rodrigo"

    input.action.operation == "ShowSchemas"
}

# ==============================================================================
# RODRIGO - USO DE SCHEMA
# ==============================================================================

allow if {
    input.context.identity.user == "rodrigo"

    input.action.operation == "UseSchema"

    object.get(
        object.get(input.action.resource, "schema", {}),
        "schemaName",
        ""
    ) != "financeiro"
}

# ==============================================================================
# RODRIGO - METADADOS DE TABELAS
# ==============================================================================

allow if {
    input.context.identity.user == "rodrigo"

    input.action.operation in [
        "FilterTables",
        "FilterColumns",
        "ShowTables",
        "ShowColumns"
    ]

    object.get(
        object.get(input.action.resource, "table", {}),
        "schemaName",
        ""
    ) != "financeiro"
}

# ==============================================================================
# RODRIGO - SELECT
# ==============================================================================

allow if {
    input.context.identity.user == "rodrigo"

    input.action.operation == "SelectFromColumns"

    input.action.resource.table.schemaName != "financeiro"
}

# ==============================================================================
# RODRIGO - INSERT E CREATE APENAS EM SANDBOX/API_LAB
# ==============================================================================

allow if {
    input.context.identity.user == "rodrigo"

    input.action.operation in [
        "InsertIntoTable",
        "CreateTable"
    ]

    input.action.resource.table.schemaName in [
        "sandbox",
        "api_lab"
    ]
}

# ==============================================================================
# DEBUG / AUDITORIA
# ==============================================================================

deny contains msg if {
    not allow

    msg := sprintf(
        "OPA DENIED user=%v operation=%v resource=%v",
        [
            input.context.identity.user,
            input.action.operation,
            object.get(input.action, "resource", {})
        ]
    )
}