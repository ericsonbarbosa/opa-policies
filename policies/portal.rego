package portal.authz

import rego.v1

# Política Portal-OPA: Default Deny + Permissões por Token + Anonimização.
default allow := false

# ==============================================================================
# CAMADA DE NORMALIZAÇÃO DE INPUT (Traduz Trino e Portal para um formato único)
# ==============================================================================

# 1. Identifica o usuário/token (Trino usa context.identity.user, Portal usa token)
get_token := t if {
    t := object.get(input.context.identity, "user", object.get(input, "token", ""))
}

# 2. Identifica a coleção (Trino usa schemaName, Portal usa colecao)
get_colecao := c if {
    c := object.get(input.action.resource.table, "schemaName", object.get(input, "colecao", ""))
}

# 3. Identifica o campo (Trino usa columnName, Portal usa campo)
get_campo := f if {
    f := object.get(input.action.resource.column, "columnName", object.get(input, "campo", ""))
}

# 4. Identifica ou infere o tipo de query
get_tipo_query := tq if {
    raw := object.get(input.action, "operation", object.get(input, "tipo_query", ""))
    tq := infer_tipo_query(raw)
}

# Helper para inferir tipo de query a partir da operação do Trino
infer_tipo_query(op) := "api" if {
    is_string(op)
    # Operações de leitura no Trino mapeiam para "api" no seu modelo
    regex.match("(?i)^(show|select|describe|use)", op)
}
infer_tipo_query(op) := "jdbc" if {
    is_string(op)
    # Operações de escrita/DDL mapeiam para "jdbc"
    regex.match("(?i)^(insert|create|drop|alter|delete)", op)
}
infer_tipo_query(op) := op if {
    # Se já for um tipo válido do seu modelo, mantém
    op in ["api", "jdbc", "api_doc", "jdbc_dm"]
}
infer_tipo_query(_) := "N/A"

# Objeto de requisição padronizado para TODAS as regras abaixo
req := {
    "token": get_token,
    "colecao": get_colecao,
    "campo": get_campo,
    "tipo_query": get_tipo_query
}

# ==============================================================================
# ACESSO PRINCIPAL (Usando o req padronizado)
# ==============================================================================
allow if {
    perm := data.user_permissions[req.token]
    perm.nome_colecao == req.colecao

    # Verifica se o campo solicitado é válido para este token
    is_campo_valido(perm, req)

    # Verifica se a operação/query é compatível
    is_tipo_query_valido(perm, req)
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

is_tipo_query_valido(perm, r) if not has_req_tq(r)

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
    perm := data.user_permissions[req.token]
    perm.nome_colecao == req.colecao
    some rule in object.get(perm, "anonimizacao", [])
    rule.campo == req.campo
    rule.funcao != null
}

# Retorna a regra de anonimização aplicável ao campo
anonymize_rule := rule if {
    perm := data.user_permissions[req.token]
    perm.nome_colecao == req.colecao
    some rule in object.get(perm, "anonimizacao", [])
    rule.campo == req.campo
    rule.funcao != null
}

# Correção: columnMask do sha256 foi ajustado para refletir a lógica de hash (não apenas asteriscos)
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
    not anonymize_rule.funcao in ["token-sha256", "mascarar-por-completo"]
}

# ==============================================================================
# INFORMAÇÕES DA COLEÇÃO
# ==============================================================================
# Correção: Retorno seguro em required_filters caso 'filtros' não exista no JSON
required_filters := res if {
    perm := data.user_permissions[req.token]
    perm.nome_colecao == req.colecao
    res := object.get(perm, "filtros", [])
}

# Correção: Fallback seguro via object.get em todos os nós críticos do payload
collection_info := {
    "colecao_id":        object.get(perm, "colecao_id", null),
    "nome_colecao":      perm.nome_colecao,
    "tipo_colecao":      object.get(perm, "tipo_colecao", "N/A"),
    "tipo_campos":       object.get(perm, "tipo_campos", "N/A"),
    "tipo_query":        object.get(perm, "tipo_query", null),
    "campos_permitidos": object.get(perm, "campos_permitidos", []),
} if {
    perm := data.user_permissions[req.token]
    perm.nome_colecao == req.colecao
}

# Correção: Auditoria blindada. Previne "undefined exception" caso o token não seja uma string ou colecao/campo sejam omitidos.
deny contains msg if {
    not allow
    campo_str := object.get(input, "campo", "N/A")
    colecao_str := object.get(input, "colecao", "N/A")
    token_raw := object.get(input, "token", "N/A")
    
    msg := sprintf(
        "ACCESS DENIED: user=%s colecao=%s campo=%s",
        [
            format_token(token_raw),
            colecao_str,
            campo_str,
        ]
    )
}

format_token(t) := substring(t, 0, 20) if is_string(t)
format_token(t) := "INVALID_OR_MISSING"  if not is_string(t)