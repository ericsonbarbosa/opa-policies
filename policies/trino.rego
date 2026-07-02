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
# RODRIGO: ExecuteQuery — obrigatório para qualquer query rodar
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation == "ExecuteQuery"
}

# ------------------------------------------------------------------------------
# RODRIGO: Acesso aos catálogos
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation == "CheckCanAccessCatalog"
    input.action.resource.catalog.catalogName in ["iceberg", "system", "memory", "tpch"]
}

# ------------------------------------------------------------------------------
# RODRIGO: FilterSchemas — sem restrição de schema (é uma operação de listagem,
# o Trino filtra o resultado; bloquear aqui impede SHOW SCHEMAS inteiro)
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation in ["FilterSchemas", "ShowSchemas"]
}

# ------------------------------------------------------------------------------
# RODRIGO: Metadados de tabelas/colunas — apenas schemas não-financeiros
# Regras separadas por tipo de recurso para evitar undefined em campos ausentes
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation in ["FilterTables", "ShowTables", "FilterColumns", "ShowColumns"]
    input.action.resource.table.schemaName != "financeiro"
}

# ------------------------------------------------------------------------------
# RODRIGO: USE schema — apenas schemas não-financeiros
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation == "UseSchema"
    input.action.resource.schema.schemaName != "financeiro"
}

# ------------------------------------------------------------------------------
# RODRIGO: SELECT — qualquer schema exceto financeiro
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation == "SelectFromColumns"
    input.action.resource.table.schemaName != "financeiro"
}

# ------------------------------------------------------------------------------
# RODRIGO: INSERT e CREATE TABLE apenas em sandbox e api_lab
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation in ["InsertIntoTable", "CreateTable"]
    input.action.resource.table.schemaName in ["sandbox", "api_lab"]
}

# ------------------------------------------------------------------------------
# Auditoria
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