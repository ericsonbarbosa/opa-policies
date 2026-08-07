package portal.authz

import rego.v1

# Política Portal-OPA: Default Deny + Permissões por Token + Anonimização.
default allow := false

# ==============================================================================
# ACESSO PRINCIPAL
# ==============================================================================
allow if {
    perm := data.user_permissions[input.token]
    perm.nome_colecao == input.colecao

    # Verifica se o campo solicitado é válido para este token
    is_campo_valido(perm, input)

    # Verifica se a operação/query é compatível
    is_tipo_query_valido(perm, input)
}

# ==============================================================================
# REGRAS DE VALIDAÇÃO DE CAMPO
# ==============================================================================
# Helper seguro: Verifica se a chave foi enviada, não é nula e não é vazia
has_campo(req) if {
    _ := req.campo
    req.campo != ""
    req.campo != null
}

# 1. Permite requisições de nível de coleção (quando a chave 'campo' NÃO é enviada)
is_campo_valido(perm, req) if not has_campo(req)

# 2. Se a chave 'campo' foi enviada, ela é OBRIGADA a estar na lista de permitidos
# Correção: Uso de object.get para evitar erros de undefined caso a lista não exista
is_campo_valido(perm, req) if {
    has_campo(req)
    req.campo in object.get(perm, "campos_permitidos", [])
}

# ==============================================================================
# REGRAS DE VALIDAÇÃO DE TIPO DE QUERY
# ==============================================================================
has_req_tq(req) if {
    _ := req.tipo_query
    req.tipo_query != ""
    req.tipo_query != null
}

has_perm_tq(perm) if {
    _ := perm.tipo_query
    perm.tipo_query != ""
    perm.tipo_query != null
}

# 1. Permite se a requisição não vier filtrada por tipo de query
is_tipo_query_valido(perm, req) if not has_req_tq(req)

# 2. Permite se a requisição tem tipo de query, mas o JSON do token NÃO restringe
is_tipo_query_valido(perm, req) if {
    has_req_tq(req)
    not has_perm_tq(perm)
}

# 3. Aplica restrição estrita quando AMBOS existem (Token restringe e Input pede)
is_tipo_query_valido(perm, req) if {
    has_req_tq(req)
    has_perm_tq(perm)
    valida_match_tipo_query(perm.tipo_query, req.tipo_query)
}

# Suporta match caso o token traga uma string única (ex: "api")
valida_match_tipo_query(perm_tq, req_tq) if {
    is_string(perm_tq)
    perm_tq == req_tq
}

# Suporta match caso o token traga um array de tipos (ex: ["api", "sql"])
valida_match_tipo_query(perm_tq, req_tq) if {
    is_array(perm_tq)
    req_tq in perm_tq
}

# ==============================================================================
# ANONIMIZAÇÃO
# ==============================================================================
# Correção: Uso de object.get para lidar com tokens sem a chave "anonimizacao"
has_anonymization if {
    perm := data.user_permissions[input.token]
    perm.nome_colecao == input.colecao
    some rule in object.get(perm, "anonimizacao", [])
    rule.campo == input.campo
    rule.funcao != null
}

anonymize_rule := rule if {
    perm := data.user_permissions[input.token]
    perm.nome_colecao == input.colecao
    some rule in object.get(perm, "anonimizacao", [])
    rule.campo == input.campo
    rule.funcao != null
}

# Correção: columnMask do sha256 foi ajustado para refletir a lógica de hash (não apenas asteriscos)
columnMask := {"expression": sprintf("SHA256(CAST(%s AS VARCHAR))", [input.campo])} if {
    anonymize_rule.funcao == "token-sha256"
}
columnMask := {"expression": sprintf("'%s'", [anonymize_rule.simbolo])} if {
    anonymize_rule.funcao == "mascarar-por-completo"
    anonymize_rule.simbolo != null
}
columnMask := {"expression": "'***'"} if {
    anonymize_rule.funcao == "mascarar-por-completo"
    anonymize_rule.simbolo == null
}
columnMask := {"expression": sprintf("substring(%s, 1, %d) || '***'", [input.campo, anonymize_rule["indice-regex"]])} if {
    anonymize_rule.funcao == "partial-mask"
    anonymize_rule["indice-regex"] != null
}
columnMask := {"expression": sprintf("'%s'", [anonymize_rule.simbolo])} if {
    anonymize_rule.funcao == "symbol-replace"
    anonymize_rule.simbolo != null
}
columnMask := {"expression": sprintf("regexp_replace(%s, '%s', '***')", [input.campo, anonymize_rule["indice-regex"]])} if {
    anonymize_rule.funcao == "regex-mask"
    anonymize_rule["indice-regex"] != null
}
columnMask := {"expression": "'***'"} if {
    has_anonymization
    not anonymize_rule.funcao in ["token-sha256", "mascarar-por-completo", "partial-mask", "symbol-replace", "regex-mask"]
}

# ==============================================================================
# INFORMAÇÕES DA COLEÇÃO E AUDITORIA
# ==============================================================================
# Correção: Retorno seguro em required_filters caso 'filtros' não exista no JSON
required_filters := res if {
    perm := data.user_permissions[input.token]
    perm.nome_colecao == input.colecao
    res := object.get(perm, "filtros", [])
}

# Correção: Fallback seguro via object.get em todos os nós críticos do payload
collection_info := {
    "colecao_id": object.get(perm, "colecao_id", null),
    "nome_colecao": perm.nome_colecao,
    "tipo_colecao": object.get(perm, "tipo_colecao", "N/A"),
    "tipo_campos": object.get(perm, "tipo_campos", "N/A"),
    "campos_permitidos": object.get(perm, "campos_permitidos", []),
} if {
    perm := data.user_permissions[input.token]
    perm.nome_colecao == input.colecao
}

# Correção: Auditoria blindada. Previne "undefined exception" caso o token não seja uma string ou colecao/campo sejam omitidos.
deny contains msg if {
    not allow
    campo_str := object.get(input, "campo", "N/A")
    colecao_str := object.get(input, "colecao", "N/A")
    token_raw := object.get(input, "token", "N/A")
    
    msg := sprintf(
        "PORTAL DENIED: token=%s colecao=%s campo=%s",
        [
            format_token(token_raw),
            colecao_str,
            campo_str
        ]
    )
}

format_token(t) := substring(t, 0, 20) if is_string(t)
format_token(t) := "INVALID_OR_MISSING" if not is_string(t)