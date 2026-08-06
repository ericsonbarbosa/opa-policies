package portal.authz

import rego.v1

# Política Portal-OPA: Default Deny + Permissões por Token + Anonimização.
default allow := false

# ==============================================================================
# ACESSO PRINCIPAL
# ==============================================================================
# Unificamos a regra de 'allow' para que todas as condições ajam como AND (E)
allow if {
    perm := data.user_permissions[input.token]
    perm.nome_colecao == input.colecao

    # Verifica se o campo solicitado é válido para este token
    is_campo_valido(perm, input)

    # Verifica se a operação/query é compatível
    is_tipo_query_valido(perm, input)
}

# Validação do Campo
is_campo_valido(perm, input) if {
    not input.campo # Permite requisições de nível de coleção (quando não pedem campo específico)
}
is_campo_valido(perm, input) if {
    input.campo in perm.campos_permitidos
}

# Validação do Tipo de Query
is_tipo_query_valido(perm, input) if {
    not input.tipo_query # Permite se a requisição não vier filtrada por tipo de query
}
is_tipo_query_valido(perm, input) if {
    input.tipo_query
    not perm.tipo_query # Permite se o JSON do usuário não restringir um tipo de query
}
is_tipo_query_valido(perm, input) if {
    input.tipo_query
    perm.tipo_query == input.tipo_query # Aplica restrição estrita quando ambos existem
}

# ==============================================================================
# ANONIMIZAÇÃO
# ==============================================================================
# Verifica se o campo possui regra de anonimização válida (Ignora sujeira nula do data.json)
has_anonymization if {
    perm := data.user_permissions[input.token]
    perm.nome_colecao == input.colecao
    some rule in perm.anonimizacao
    rule.campo == input.campo
    rule.funcao != null
}

# Retorna a regra de anonimização aplicável ao campo
anonymize_rule := rule if {
    perm := data.user_permissions[input.token]
    perm.nome_colecao == input.colecao
    some rule in perm.anonimizacao
    rule.campo == input.campo
    rule.funcao != null
}

# COLUMN MASKING: token-sha256
columnMask := {"expression": "'***'"} if {
    anonymize_rule.funcao == "token-sha256"
}

# COLUMN MASKING: mascarar-por-completo
columnMask := {"expression": sprintf("'%s'", [anonymize_rule.simbolo])} if {
    anonymize_rule.funcao == "mascarar-por-completo"
    anonymize_rule.simbolo != null
}
columnMask := {"expression": "'***'"} if {
    anonymize_rule.funcao == "mascarar-por-completo"
    anonymize_rule.simbolo == null # Fallback caso o símbolo venha nulo
}

# COLUMN MASKING: partial-mask
columnMask := {"expression": sprintf("substring(%s, 1, %d) || '***'", [input.campo, anonymize_rule["indice-regex"]])} if {
    anonymize_rule.funcao == "partial-mask"
    anonymize_rule["indice-regex"] != null
}

# COLUMN MASKING: symbol-replace
columnMask := {"expression": sprintf("'%s'", [anonymize_rule.simbolo])} if {
    anonymize_rule.funcao == "symbol-replace"
    anonymize_rule.simbolo != null
}

# COLUMN MASKING: regex-mask
columnMask := {"expression": sprintf("regexp_replace(%s, '%s', '***')", [input.campo, anonymize_rule["indice-regex"]])} if {
    anonymize_rule.funcao == "regex-mask"
    anonymize_rule["indice-regex"] != null
}

# COLUMN MASKING: Fallback para funções desconhecidas
columnMask := {"expression": "'***'"} if {
    has_anonymization
    not anonymize_rule.funcao in ["token-sha256", "mascarar-por-completo", "partial-mask", "symbol-replace", "regex-mask"]
}

# ==============================================================================
# INFORMAÇÕES DA COLEÇÃO E AUDITORIA
# ==============================================================================
# Retorna filtros obrigatórios
required_filters := perm.filtros if {
    perm := data.user_permissions[input.token]
    perm.nome_colecao == input.colecao
}

# Retorna informações da coleção
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

# Loga as negações usando object.get para evitar erros se 'campo' não for passado na request
deny contains msg if {
    not allow
    campo_str := object.get(input, "campo", "N/A")
    msg := sprintf(
        "PORTAL DENIED: token=%s colecao=%s campo=%s",
        [
            substring(input.token, 0, 20),
            input.colecao,
            campo_str
        ]
    )
}