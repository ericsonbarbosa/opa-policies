package trino

import future.keywords.in
import future.keywords.if
import future.keywords.contains

default allow := false

# ------------------------------------------------------------------------------
# ADMIN
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "admin"
}

# ------------------------------------------------------------------------------
# RODRIGO: operações básicas do engine
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation in [
        "ExecuteQuery",
        "ViewQuery",
        "FilterCatalogs",
        "FilterViewQueryOwnedBy"
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
# RODRIGO: schemas
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation == "FilterSchemas"
}

# ------------------------------------------------------------------------------
# RODRIGO: metadados
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"

    input.action.operation in [
        "FilterTables",
        "FilterColumns",
        "ShowSchemas",
        "ShowTables",
        "ShowColumns",
        "UseSchema"
    ]

    object.get(
        object.get(input.action.resource, "schema", {}),
        "schemaName",
        ""
    ) != "financeiro"

    object.get(
        object.get(input.action.resource, "table", {}),
        "schemaName",
        ""
    ) != "financeiro"
}

# ------------------------------------------------------------------------------
# RODRIGO: SELECT
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation == "SelectFromColumns"

    object.get(
        input.action.resource.table,
        "schemaName",
        ""
    ) != "financeiro"
}

# ------------------------------------------------------------------------------
# RODRIGO: INSERT/CREATE
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
# DEBUG
# ------------------------------------------------------------------------------
deny contains msg if {
    not allow

    msg := sprintf(
        "OPA DENIED user=%v op=%v resource=%v",
        [
            input.context.identity.user,
            input.action.operation,
            input.action.resource
        ]
    )
}