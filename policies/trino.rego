package trino

import future.keywords.in
import future.keywords.if

# ==============================================================================
# POLÍTICA TRINO-OPA (Lógica Linear: Default Deny + Allow Condicional)
# ==============================================================================

default allow := false

# ------------------------------------------------------------------------------
# ADMIN: Acesso total
# ------------------------------------------------------------------------------
allow if input.context.identity.user == "admin"

# ------------------------------------------------------------------------------
# RODRIGO: Permitir TUDO, exceto acesso ao schema financeiro
# ------------------------------------------------------------------------------
allow if {
    input.context.identity.user == "rodrigo"
    not is_financial_access
}

# ------------------------------------------------------------------------------
# DEFINIÇÃO DE ACESSO FINANCEIRO (Único bloqueio explícito)
# ------------------------------------------------------------------------------
is_financial_access if {
    input.context.identity.user == "rodrigo"
    input.action.operation in [
        "SelectFromColumns", "InsertIntoTable", "CreateTable", 
        "DropTable", "UseSchema", "RenameTable", "CreateSchema", "DropSchema"
    ]
    # Extrai schemaName de table ou schema (lida com estruturas diferentes)
    schema_name := object.get(input.action.resource.table, "schemaName",
                   object.get(input.action.resource.schema, "schemaName", ""))
    schema_name == "financeiro"
}