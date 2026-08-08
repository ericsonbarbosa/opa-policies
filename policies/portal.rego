package portal.authz

import rego.v1

# Política Portal-OPA: Default Deny + Permissões por Token + Anonimização.
# Fonte da verdade: data.json (user_permissions)
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

# Helper seguro: verifica se a chave 'campo' foi enviada, não é nula e não é vazia
has_campo(req) if {
    _ := req.campo
    req.campo != ""
    req.campo != null
}

# 1. Permite requisições de nível de coleção (quando 'campo' NÃO é enviado)
is_campo_valido(perm, req) if not has_campo(req)

# 2. Se 'campo' foi enviado, é obrigado a estar na lista de campos permitidos
#    object.get evita erro de undefined caso a lista não exista no token
is_campo_valido(perm, req) if {
    has_campo(req)
    req.campo in object.get(perm, "campos_permitidos", [])
}

# ==============================================================================
# REGRAS DE VALIDAÇÃO DE TIPO DE QUERY
# ==============================================================================

# Helpers: verifica se tipo_query foi enviado na requisição e se o token restringe
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

# 2. Permite se a requisição tem tipo de query, mas o token NÃO restringe
is_tipo_query_valido(perm, req) if {
    has_req_tq(req)
    not has_perm_tq(perm)
}

# 3. Aplica restrição estrita quando AMBOS existem
#    O data.json usa tipo_query como string (api, api_doc, jdbc, jdbc_dm)
is_tipo_query_valido(perm, req) if {
    has_req_tq(req)
    has_perm_tq(perm)
    is_string(perm.tipo_query)
    perm.tipo_query == req.tipo_query
}

# ==============================================================================
# ANONIMIZAÇÃO
# Funções suportadas pelo data.json: token-sha256, mascarar-por-completo
# ==============================================================================

# Verifica se o campo possui regra de anonimização válida
has_anonymization if {
    perm := data.user_permissions[input.token]
    perm.nome_colecao == input.colecao
    some rule in object.get(perm, "anonimizacao", [])
    rule.campo == input.campo
    rule.funcao != null
}

# Retorna a regra de anonimização aplicável ao campo
anonymize_rule := rule if {
    perm := data.user_permissions[input.token]
    perm.nome_colecao == input.colecao
    some rule in object.get(perm, "anonimizacao", [])
    rule.campo == input.campo
    rule.funcao != null
}

# token-sha256: substitui pelo hash SHA256 do valor
columnMask := {"expression": sprintf("SHA256(CAST(%s AS VARCHAR))", [input.campo])} if {
    anonymize_rule.funcao == "token-sha256"
}

# mascarar-por-completo com símbolo customizado
columnMask := {"expression": sprintf("'%s'", [anonymize_rule.simbolo])} if {
    anonymize_rule.funcao == "mascarar-por-completo"
    anonymize_rule.simbolo != null
}

# mascarar-por-completo sem símbolo — fallback para asteriscos
columnMask := {"expression": "'***'"} if {
    anonymize_rule.funcao == "mascarar-por-completo"
    anonymize_rule.simbolo == null
}

# Fallback para funções não reconhecidas pelo data.json atual
columnMask := {"expression": "'***'"} if {
    has_anonymization
    not anonymize_rule.funcao in ["token-sha256", "mascarar-por-completo"]
}

# ==============================================================================
# INFORMAÇÕES DA COLEÇÃO
# ==============================================================================

required_filters := res if {
    perm := data.user_permissions[input.token]
    perm.nome_colecao == input.colecao
    res := object.get(perm, "filtros", [])
}

# Retorna metadados da coleção para o cliente
# tipo_query incluído para que o cliente saiba qual operação o token aceita
collection_info := {
    "colecao_id":        object.get(perm, "colecao_id", null),
    "nome_colecao":      perm.nome_colecao,
    "tipo_colecao":      object.get(perm, "tipo_colecao", "N/A"),
    "tipo_campos":       object.get(perm, "tipo_campos", "N/A"),
    "tipo_query":        object.get(perm, "tipo_query", null),
    "campos_permitidos": object.get(perm, "campos_permitidos", []),
} if {
    perm := data.user_permissions[input.token]
    perm.nome_colecao == input.colecao
}

# ==============================================================================
# AUDITORIA
# ==============================================================================

deny contains msg if {
    not allow
    campo_str   := object.get(input, "campo", "N/A")
    colecao_str := object.get(input, "colecao", "N/A")
    token_raw   := object.get(input, "token", "N/A")

    msg := sprintf(
        "PORTAL DENIED: token=%s colecao=%s campo=%s",
        [
            format_token(token_raw),
            colecao_str,
            campo_str,
        ]
    )
}

format_token(t) := substring(t, 0, 20) if is_string(t)
format_token(t) := "INVALID_OR_MISSING"  if not is_string(t)