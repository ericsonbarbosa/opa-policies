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
# RODRIGO (Analista): Operações de listagem
# SHOW SCHEMAS, SHOW TABLES, USE schema
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
    # Permite listar em qualquer schema EXCETO financeiro
    object.get(input.action.resource, "schema", {}).schemaName != "financeiro"
    object.get(input.action.resource.table, "schemaName", "") != "financeiro"
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
# RODRIGO (Analista): SELECT em financeiro apenas para tabela pública específica
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation == "SelectFromColumns"
    input.action.resource.table.schemaName == "financeiro"
    input.action.resource.table.tableName == "vendas_publicas"
}

# ------------------------------------------------------------------------------
# RODRIGO (Analista): INSERT e CREATE apenas em sandbox
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation in ["InsertIntoTable", "CreateTable"]
    input.action.resource.table.schemaName == "sandbox"
}

# ------------------------------------------------------------------------------
# RODRIGO (Analista): CREATE TABLE em api_lab (leitura + criação permitida)
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation in ["CreateTable", "InsertIntoTable"]
    input.action.resource.table.schemaName == "api_lab"
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