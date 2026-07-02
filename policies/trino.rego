package trino

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# ==============================================================================
# ESTRATÉGIA HÍBRIDA: Default Deny + User Roles + Deny List (Versão Defensiva)
# ==============================================================================

default allow := false

# ------------------------------------------------------------------------------
# ROLES (Papéis de Acesso)
# ------------------------------------------------------------------------------
user_roles := {
    "admin": ["admin"],
    "rodrigo": ["analista"],
}

has_role(user, role) if {
    role in user_roles[user]
}

# ------------------------------------------------------------------------------
# ADMIN: Acesso total irrestrito
# ------------------------------------------------------------------------------
allow if {
    has_role(input.context.identity.user, "admin")
}

# ------------------------------------------------------------------------------
# ANALISTA: Permitir TUDO por padrão, exceto operações explicitamente negadas
# Isso resolve o problema de operações desconhecidas do Trino
# ------------------------------------------------------------------------------
allow if {
    has_role(input.context.identity.user, "analista")
    not deny_financial_data
    not deny_financial_schema
    not deny_financial_use
}

# ------------------------------------------------------------------------------
# DENY: SELECT, INSERT, UPDATE, DELETE em tabelas do schema financeiro
# Apenas bloqueia se o campo schemaName existir e for "financeiro"
# ------------------------------------------------------------------------------
deny_financial_data if {
    has_role(input.context.identity.user, "analista")
    input.action.operation in [
        "SelectFromColumns",
        "InsertIntoTable",
        "DeleteFromTable",
        "UpdateTable"
    ]
    # Verificar se resource.table.schemaName existe e é "financeiro"
    input.action.resource.table.schemaName == "financeiro"
}

# ------------------------------------------------------------------------------
# DENY: CREATE, DROP, RENAME em schema financeiro
# ------------------------------------------------------------------------------
deny_financial_schema if {
    has_role(input.context.identity.user, "analista")
    input.action.operation in [
        "CreateTable",
        "DropTable",
        "RenameTable",
        "CreateSchema",
        "DropSchema"
    ]
    # Verificar schema em diferentes estruturas possíveis
    some schema_name
    schema_name := object.get(input.action.resource.table, "schemaName", null)
    schema_name == "financeiro"
}

deny_financial_schema if {
    has_role(input.context.identity.user, "analista")
    input.action.operation in [
        "CreateTable",
        "DropTable",
        "RenameTable",
        "CreateSchema",
        "DropSchema"
    ]
    # Verificar schema em resource.schema.schemaName
    some schema_name
    schema_name := object.get(input.action.resource.schema, "schemaName", null)
    schema_name == "financeiro"
}

# ------------------------------------------------------------------------------
# DENY: USE schema financeiro
# ------------------------------------------------------------------------------
deny_financial_use if {
    has_role(input.context.identity.user, "analista")
    input.action.operation == "UseSchema"
    input.action.resource.schema.schemaName == "financeiro"
}

# ------------------------------------------------------------------------------
# AUDITORIA: Loga todas as negações com detalhes
# ------------------------------------------------------------------------------
deny contains msg if {
    not allow
    msg := sprintf(
        "OPA DENIED: user=%s op=%s",
        [
            input.context.identity.user,
            input.action.operation
        ]
    )
}