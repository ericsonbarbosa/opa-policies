package portal.authz

import rego.v1

# Política Portal-OPA: Default Deny + Permissões por Token + Anonimização

default allow := false

# ACESSO: Token tem permissão para a coleção solicitada
allow if {
    perm := data.user_permissions[input.token]
    perm.nome_colecao == input.colecao
}

# ACESSO: Campo solicitado está na lista de campos permitidos
allow if {
    perm := data.user_permissions[input.token]
    perm.nome_colecao == input.colecao
    input.campo in perm.campos_permitidos
}

# ACESSO: Tipo de campos "Completo" libera todos os campos da coleção
allow if {
    perm := data.user_permissions[input.token]
    perm.nome_colecao == input.colecao
    perm.tipo_campos == "Completo"
}

# ACESSO: Operação compatível com o tipo_query (se definido)
allow if {
    perm := data.user_permissions[input.token]
    perm.nome_colecao == input.colecao
    input.campo in perm.campos_permitidos
    perm.tipo_query == input.tipo_query
}

# ANONIMIZAÇÃO: Verifica se o campo possui regra de anonimização
has_anonymization if {
    perm := data.user_permissions[input.token]
    perm.nome_colecao == input.colecao
    some rule in perm.anonimizacao
    rule.campo == input.campo
}

# ANONIMIZAÇÃO: Retorna a regra de anonimização aplicável ao campo
anonymize_rule := rule if {
    perm := data.user_permissions[input.token]
    perm.nome_colecao == input.colecao
    some rule in perm.anonimizacao
    rule.campo == input.campo
}

# COLUMN MASKING: token-sha256 substitui completamente por asteriscos
columnMask := {"expression": "'***'"} if {
    anonymize_rule.funcao == "token-sha256"
}

# COLUMN MASKING: partial-mask mostra primeiros N caracteres + asteriscos
columnMask := {"expression": sprintf("substring(%s, 1, %d) || '***'", [input.campo, anonymize_rule["indice-regex"]])} if {
    anonymize_rule.funcao == "partial-mask"
    anonymize_rule["indice-regex"] != null
}

# COLUMN MASKING: symbol-replace substitui por símbolo customizado
columnMask := {"expression": sprintf("'%s'", [anonymize_rule.simbolo])} if {
    anonymize_rule.funcao == "symbol-replace"
    anonymize_rule.simbolo != null
}

# COLUMN MASKING: regex-mask aplica máscara com regex
columnMask := {"expression": sprintf("regexp_replace(%s, '%s', '***')", [input.campo, anonymize_rule["indice-regex"]])} if {
    anonymize_rule.funcao == "regex-mask"
    anonymize_rule["indice-regex"] != null
}

# COLUMN MASKING: Fallback para funções não reconhecidas
columnMask := {"expression": "'***'"} if {
    has_anonymization
    not anonymize_rule.funcao in ["token-sha256", "partial-mask", "symbol-replace", "regex-mask"]
}

# FILTROS: Retorna campos que devem ser usados como filtro obrigatório
required_filters := perm.filtros if {
    perm := data.user_permissions[input.token]
    perm.nome_colecao == input.colecao
}

# INFO DA COLEÇÃO: Retorna informações da coleção para o cliente
collection_info := {
    "colecao_id": perm.colecao_id,
    "nome_colecao": perm.nome_colecao,
    "tipo_colecao": perm.tipo_colecao,
    "tipo_campos": perm.tipo_campos,
    "campos_permitidos": perm.campos_permitidos,
} if {
    perm := data.user_permissions[input.token]
    perm.nome_colecao == input.colecao
}

# AUDITORIA: Loga todas as negações
deny contains msg if {
    not allow
    msg := sprintf(
        "PORTAL DENIED: token=%s colecao=%s campo=%s",
        [
            substring(input.token, 0, 20),
            input.colecao,
            input.campo,
        ]
    )
}