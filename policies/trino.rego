package trino

# ==============================================================================
# POLÍTICAS DE GOVERNANÇA PARA TRINO
# Single Source of Truth — OPA decide quem pode fazer o quê
# ==============================================================================

default allow := false

# ------------------------------------------------------------------------------
# ADMIN: Acesso total (pode fazer qualquer operação)
# ------------------------------------------------------------------------------
allow if {
    input.user.role == "admin"
}

# ------------------------------------------------------------------------------
# ANALISTA: SELECT em qualquer namespace, exceto "financeiro"
# ------------------------------------------------------------------------------
allow if {
    input.user.role == "analista"
    input.action == "SELECT"
    input.namespace != "financeiro"
}

# ------------------------------------------------------------------------------
# ANALISTA: SELECT em "financeiro" apenas para tabelas específicas
# ------------------------------------------------------------------------------
allow if {
    input.user.role == "analista"
    input.action == "SELECT"
    input.namespace == "financeiro"
    input.table == "vendas_publicas"
}

# ------------------------------------------------------------------------------
# ANALISTA: INSERT/UPDATE/DELETE apenas em namespace "sandbox"
# ------------------------------------------------------------------------------
allow if {
    input.user.role == "analista"
    input.action in ["INSERT", "UPDATE", "DELETE"]
    input.namespace == "sandbox"
}

# ------------------------------------------------------------------------------
# ANALISTA: CREATE/DROP apenas em namespace "sandbox"
# ------------------------------------------------------------------------------
allow if {
    input.user.role == "analista"
    input.action in ["CREATE", "DROP"]
    input.namespace == "sandbox"
}

# ------------------------------------------------------------------------------
# DEV: Acesso total em "sandbox" e "dev"
# ------------------------------------------------------------------------------
allow if {
    input.user.role == "dev"
    input.namespace in ["sandbox", "dev"]
}

# ------------------------------------------------------------------------------
# DEV: SELECT em outros namespaces (apenas leitura)
# ------------------------------------------------------------------------------
allow if {
    input.user.role == "dev"
    input.action == "SELECT"
    input.namespace not in ["financeiro", "comercial"]
}

# ------------------------------------------------------------------------------
# Mensagens de negação (para debug e auditoria)
# ------------------------------------------------------------------------------
deny contains msg if {
    not allow
    msg := sprintf(
        "Acesso negado: user=%s role=%s action=%s namespace=%s table=%s",
        [
            input.user.name,
            input.user.role,
            input.action,
            input.namespace,
            input.table
        ]
    )
}