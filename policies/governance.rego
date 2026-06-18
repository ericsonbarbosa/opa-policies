package governance

# ==============================================================================
# POLÍTICA DE GOVERNANÇA — Carregada via Bundle do SeaweedFS
# Revisão: v1-seaweedfs-2026-06-20
# ==============================================================================

default allow := false

# Admin tem acesso total
allow if {
    input.user.role == "admin"
}

# Analista pode fazer SELECT em qualquer namespace, exceto "financeiro"
allow if {
    input.user.role == "analista"
    input.action == "Select"
    input.namespace != "financeiro"
}

# Mensagens de negação (para debug e auditoria)
deny contains msg if {
    not allow
    msg := sprintf(
        "Acesso negado: user=%s role=%s action=%s namespace=%s bundle=%s",
        [
            input.user.name,
            input.user.role,
            input.action,
            input.namespace,
            "v1-seaweedfs-2026-06-15"
        ]
    )
}
