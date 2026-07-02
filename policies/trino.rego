package trino

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# ==============================================================================
# POLÍTICA DE GOVERNANÇA PARA TRINO (Plugin Oficial)
# Single Source of Truth — OPA decide quem pode fazer o quê
# ==============================================================================

default allow := false

# ------------------------------------------------------------------------------
# ADMIN: Acesso total irrestrito
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "admin"
}

# ------------------------------------------------------------------------------
# RODRIGO (Analista): Acesso aos catálogos (PRÉ-REQUISITO para qualquer operação)
# Sem isso, Trino bloqueia antes mesmo de consultar schemas/tabelas
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation == "CheckCanAccessCatalog"
    input.action.resource.catalog.catalogName in ["iceberg", "system", "memory", "tpch"]
}

# ------------------------------------------------------------------------------
# RODRIGO (Analista): Operações de listagem e metadados
# SHOW SCHEMAS, SHOW TABLES, USE schema
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation == "FilterSchemas"
}

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
    schema_name := object.get(input.action.resource, "schema", {}).schemaName
    schema_name != "financeiro"
    
    table_schema := object.get(input.action.resource.table, "schemaName", "")
    table_schema != "financeiro"
}

# ------------------------------------------------------------------------------
# RODRIGO (Analista): SELECT em qualquer schema, EXCETO financeiro
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation == "SelectFromColumns"
    input.action.resource.table.schemaName != "financeiro"
}

# ------------------------------------------------------------------------------
# RODRIGO (Analista): INSERT e CREATE TABLE apenas em sandbox e api_lab
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation in ["InsertIntoTable", "CreateTable"]
    input.action.resource.table.schemaName in ["sandbox", "api_lab"]
}

# ------------------------------------------------------------------------------
# Mensagens de auditoria (para debug nos logs do OPA)
# ------------------------------------------------------------------------------
deny contains msg if {
    not allow
    msg := sprintf(
        "OPA DENIED: user=%s op=%s catalog=%s schema=%s table=%s",
        [
            input.context.identity.user,
            input.action.operation,
            object.get(input.action.resource.table, "catalogName", "N/A"),
            object.get(input.action.resource.table, "schemaName", "N/A"),
            object.get(input.action.resource.table, "tableName", "N/A")
        ]
    )
}