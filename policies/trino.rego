package trino

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# ==============================================================================
# POLÍTICAS DE GOVERNANÇA PARA TRINO
# Single Source of Truth — OPA decide quem pode fazer o quê
# ==============================================================================

default allow := false

# ------------------------------------------------------------------------------
# ADMIN: Acesso total (pode fazer qualquer operação)
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "admin"
}

# ------------------------------------------------------------------------------
# ANALISTA (rodrigo): SELECT em qualquer schema, exceto "financeiro"
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation in ["SelectFromColumns", "FilterTables"]
    input.action.resource.table.schemaName != "financeiro"
}

# ------------------------------------------------------------------------------
# ANALISTA (rodrigo): SELECT em "financeiro" apenas para tabelas públicas
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation == "SelectFromColumns"
    input.action.resource.table.schemaName == "financeiro"
    input.action.resource.table.tableName == "vendas_publicas"
}

# ------------------------------------------------------------------------------
# ANALISTA (rodrigo): INSERT/CREATE apenas em "sandbox"
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation in ["InsertIntoTable", "CreateTable"]
    input.action.resource.table.schemaName == "sandbox"
}

# ------------------------------------------------------------------------------
# ANALISTA (rodrigo): Listar schemas (necessário para SHOW SCHEMAS)
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation == "FilterSchemas"
}

# ------------------------------------------------------------------------------
# Mensagens de negação (para auditoria)
# ------------------------------------------------------------------------------
deny contains msg if {
    not allow
    msg := sprintf(
        "Acesso negado: user=%s operation=%s resource=%v",
        [
            input.context.identity.user,
            input.action.operation,
            input.action.resource
        ]
    )
}