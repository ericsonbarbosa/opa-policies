package trino

import future.keywords.in
import future.keywords.if
import future.keywords.contains

default allow := false

# ------------------------------------------------------------------------------
# ADMIN: Acesso total irrestrito
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "admin"
}

# ------------------------------------------------------------------------------
# RODRIGO: Operações de catálogo
# Cobre CheckCanAccessCatalog (usa catalogName), AccessCatalog e FilterCatalogs
# (usam name) — object.get trata ambos os campos sem erro
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation in ["CheckCanAccessCatalog", "AccessCatalog", "FilterCatalogs"]
    catalog_name := object.get(
        input.action.resource.catalog, "name",
        object.get(input.action.resource.catalog, "catalogName", "")
    )
    catalog_name in ["iceberg", "system", "memory", "tpch"]
}

# ------------------------------------------------------------------------------
# RODRIGO: Operações de infraestrutura
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation in [
        "ExecuteQuery",
        "ShowSchemas",
        "FilterSchemas",
        "ShowTables",
        "FilterTables",
        "ShowColumns",
        "FilterColumns",
        "UseSchema",
        "CreateView",
        "DropView",
        "ShowFunctions",
        "FilterFunctions"
    ]
}

# ------------------------------------------------------------------------------
# RODRIGO: SELECT em qualquer schema EXCETO financeiro
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation == "SelectFromColumns"
    schema_name := object.get(input.action.resource.table, "schemaName", "")
    schema_name != "financeiro"
}

# ------------------------------------------------------------------------------
# RODRIGO: INSERT apenas em sandbox e api_lab
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation == "InsertIntoTable"
    schema_name := object.get(input.action.resource.table, "schemaName", "")
    schema_name in ["sandbox", "api_lab"]
}

# ------------------------------------------------------------------------------
# RODRIGO: CREATE TABLE apenas em sandbox e api_lab
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation == "CreateTable"
    schema_name := object.get(input.action.resource.table, "schemaName", "")
    schema_name in ["sandbox", "api_lab"]
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