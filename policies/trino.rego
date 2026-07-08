package trino

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# ==============================================================================
# POLÍTICA TRINO-OPA (Default Deny + Allow List + Column Masking)
# ==============================================================================

default allow := false

# ------------------------------------------------------------------------------
# ADMIN: Acesso total irrestrito
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "admin"
}

# ------------------------------------------------------------------------------
# RODRIGO: Operações de catálogo
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
# RODRIGO: FilterSchemas — financeiro fica oculto do SHOW SCHEMAS
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation == "FilterSchemas"
    input.action.resource.schema.schemaName != "financeiro"
}

# ------------------------------------------------------------------------------
# RODRIGO: Operações de infraestrutura
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation in [
        "ExecuteQuery",
        "ShowSchemas",
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
# EXCEÇÃO: financeiro.vendas_com_dados_sensiveis (com column masking)
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation == "SelectFromColumns"
    schema_name := object.get(input.action.resource.table, "schemaName", "")
    schema_name != "financeiro"
}

# Permite SELECT específico em financeiro.vendas_com_dados_sensiveis (com masking)
allow if {
    input.context.identity.user == "rodrigo"
    input.action.operation == "SelectFromColumns"
    input.action.resource.table.schemaName == "financeiro"
    input.action.resource.table.tableName == "vendas_com_dados_sensiveis"
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

# ==============================================================================
# COLUMN MASKING (Ofuscação de Dados Sensíveis)
# ==============================================================================

column_resource := input.action.resource.column

# Admin vê tudo sem máscara (não aplica masking)
is_admin if {
    input.context.identity.user == "admin"
}

# Mascara CPF: mostra apenas os 3 dígitos do meio (***.456.***-**)
columnMask := {"expression": "'***.' || substring(cpf, 5, 3) || '.***-**'"} if {
    not is_admin
    column_resource.tableName == "vendas_com_dados_sensiveis"
    column_resource.columnName == "cpf"
}

# Mascara telefone: mostra apenas os 4 últimos dígitos (119****8888)
columnMask := {"expression": "substring(telefone, 1, 3) || '****' || substring(telefone, 8, 4)"} if {
    not is_admin
    column_resource.tableName == "vendas_com_dados_sensiveis"
    column_resource.columnName == "telefone"
}

# Mascara dados_sensiveis completamente
columnMask := {"expression": "'[REDACTED]'"} if {
    not is_admin
    column_resource.tableName == "vendas_com_dados_sensiveis"
    column_resource.columnName == "dados_sensiveis"
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