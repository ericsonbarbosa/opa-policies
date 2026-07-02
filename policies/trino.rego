package trino

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# ==============================================================================
# ESTRATÉGIA HÍBRIDA: Default Deny + User Roles + Deny List
# Seguro por padrão, flexível para usuários autorizados
# ==============================================================================

default allow := false

# ------------------------------------------------------------------------------
# ROLES (Papéis de Acesso)
# Centraliza quem tem acesso ao sistema
# ------------------------------------------------------------------------------
user_roles := {
    "admin": ["admin"],
    "rodrigo": ["analista"],
    # Adicione novos usuários aqui explicitamente:
    # "flavio": ["analista"],
    # "maria": ["gerente"],
}

# Função auxiliar para verificar se usuário tem um role
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
# ANALISTA: Allow by default para TODAS as operações EXCETO as explicitamente negadas
# Isso resolve o problema de operações desconhecidas do Trino
# ------------------------------------------------------------------------------
allow if {
    has_role(input.context.identity.user, "analista")
    not deny_financial_operations
}

# ------------------------------------------------------------------------------
# DENY LIST: Operações proibidas para analistas no schema financeiro
# ------------------------------------------------------------------------------
deny_financial_operations if {
    has_role(input.context.identity.user, "analista")
    
    # Bloquear SELECT, INSERT, UPDATE, DELETE em financeiro
    input.action.operation in [
        "SelectFromColumns",
        "InsertIntoTable",
        "DeleteFromTable",
        "UpdateTable"
    ]
    input.action.resource.table.schemaName == "financeiro"
}

deny_financial_operations if {
    has_role(input.context.identity.user, "analista")
    
    # Bloquear CREATE, DROP, RENAME em financeiro
    input.action.operation in [
        "CreateTable",
        "DropTable",
        "RenameTable",
        "CreateSchema",
        "DropSchema"
    ]
    # Verificar schema em diferentes estruturas de resource
    schema_name := object.get(input.action.resource.table, "schemaName",
                   object.get(input.action.resource.schema, "schemaName", ""))
    schema_name == "financeiro"
}

deny_financial_operations if {
    has_role(input.context.identity.user, "analista")
    
    # Bloquear USE schema financeiro
    input.action.operation == "UseSchema"
    input.action.resource.schema.schemaName == "financeiro"
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