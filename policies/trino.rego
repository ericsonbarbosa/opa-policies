package trino

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# ==============================================================================
# POLÍTICA DE GOVERNANÇA PARA TRINO (Plugin Oficial)
# ==============================================================================

default allow := false

# ------------------------------------------------------------------------------
# ADMIN: acesso total
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "admin"
}

# ------------------------------------------------------------------------------
# RODRIGO: permissão para iniciar/executar queries
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation in [
        "ExecuteQuery",
        "ViewQuery",
        "FilterCatalogs"
    ]
}

# ------------------------------------------------------------------------------
# RODRIGO: acesso aos catálogos
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation == "CheckCanAccessCatalog"
    input.action.resource.catalog.catalogName in [
        "iceberg",
        "system",
        "memory",
        "tpch"
    ]
}

# ------------------------------------------------------------------------------
# RODRIGO: operações de metadata
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation in [
        "FilterSchemas",
        "FilterTables",
        "FilterColumns",
        "ShowSchemas",
        "ShowTables",
        "ShowColumns",
        "UseSchema"
    ]

    not is_financeiro()
}

# ------------------------------------------------------------------------------
# RODRIGO: SELECT liberado exceto financeiro
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation == "SelectFromColumns"

    schema := object.get(
        input.action.resource.table,
        "schemaName",
        ""
    )

    schema != "financeiro"
}

# ------------------------------------------------------------------------------
# RODRIGO: INSERT e CREATE apenas em sandbox e api_lab
# ------------------------------------------------------------------------------
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

# ------------------------------------------------------------------------------
# Função auxiliar
# ------------------------------------------------------------------------------
is_financeiro if {
    object.get(
        object.get(input.action.resource, "schema", {}),
        "schemaName",
        ""
    ) == "financeiro"
}

is_financeiro if {
    object.get(
        object.get(input.action.resource, "table", {}),
        "schemaName",
        ""
    ) == "financeiro"
}

# ------------------------------------------------------------------------------
# DEBUG
# ------------------------------------------------------------------------------
deny contains msg if {
    not allow

    msg := sprintf(
        "OPA DENIED user=%v operation=%v resource=%v",
        [
            input.context.identity.user,
            input.action.operation,
            input.action.resource
        ]
    )
}