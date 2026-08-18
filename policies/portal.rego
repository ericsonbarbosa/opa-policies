package portal.authz

import rego.v1

# ==============================================================================
# POLÍTICA UNIFICADA PORTAL + TRINO
# A verdade sobre os acessos reside EXCLUSIVAMENTE no data.json.
# Não há usuários hardcoded. Default Deny para tudo.
# ==============================================================================
default allow := false

# ==============================================================================
# CAMADA DE NORMALIZAÇÃO DE INPUT
# Traduz tanto o formato do Portal (token/colecao/campo) quanto o do Trino
# (context.identity.user / action.resource) para um objeto único chamado "req".
# ==============================================================================

# Token/Usuário: pega o user do Trino OU o token do Portal
get_token := t if {
    t := object.get(input.context.identity, "user", object.get(input, "token", ""))
}

# Coleção: prioriza tableName (nome real da tabela no Trino),
# depois schemaName, depois o campo colecao do Portal
get_colecao := c if {
    c := object.get(
        input.action.resource.table,
        "tableName",
        object.get(input.action.resource.table, "schemaName", object.get(input, "colecao", ""))
    )
}

# Campo: pega columnName do Trino OU campo do Portal
get_campo := f if {
    f := object.get(input.action.resource.column, "columnName", object.get(input, "campo", ""))
}

# Tipo de Query: prioriza um tipo_query EXPLÍCITO (enviado no input).
# Se não houver, infere a partir da operação.
get_tipo_query := tq if {
    raw := object.get(input.action, "tipo_query", object.get(input, "tipo_query", null))
    raw != null
    tq := raw
}

get_tipo_query := tq if {
    object.get(input.action, "tipo_query", null) == null
    object.get(input, "tipo_query", null) == null
    raw := object.get(input.action, "operation", "")
    tq := infer_tipo_query(raw)
}

# ==============================================================================
# HELPER: INFERIR TIPO DE QUERY A PARTIR DA OPERAÇÃO
# CORREÇÃO: As regras são mutuamente exclusivas (usando "not") para evitar
# o erro "functions must not produce multiple outputs for same inputs".
# ==============================================================================

# Operações SQL vindas do Trino são SEMPRE "jdbc"
infer_tipo_query(op) := "jdbc" if {
    is_string(op)
    regex.match("(?i)^(show|select|describe|use|insert|create|drop|alter|delete|execute)", op)
}

# Se a operação já for um tipo conhecido (Portal), mantém o valor
infer_tipo_query(op) := op if {
    is_string(op)
    not regex.match("(?i)^(show|select|describe|use|insert|create|drop|alter|delete|execute)", op)
    op in ["api", "jdbc", "api_doc", "jdbc_dm"]
}

# Fallback para valores que NÃO são string
infer_tipo_query(op) := "N/A" if {
    not is_string(op)
}

# Fallback para strings que não são SQL nem tipos conhecidos
infer_tipo_query(op) := "N/A" if {
    is_string(op)
    not regex.match("(?i)^(show|select|describe|use|insert|create|drop|alter|delete|execute)", op)
    not op in ["api", "jdbc", "api_doc", "jdbc_dm"]
}

# Objeto de requisição padronizado para TODAS as regras abaixo
req := {
    "token": get_token,
    "colecao": get_colecao,
    "campo": get_campo,
    "tipo_query": get_tipo_query
}

# ==============================================================================
# 1. GATE INICIAL + METADATA (ExecuteQuery, ShowCatalogs, etc.)
# O Trino faz uma verificação genérica ANTES de saber qual tabela será acessada
# (ex: operation "ExecuteQuery" sem resource.table). Se o token existe no
# data.json, permitimos passar pelo gate. A proteção REAL dos dados está na
# regra 2 abaixo, que exige match de coleção e campo.
# ==============================================================================
allow if {
    _ = data.user_permissions[req.token]
    is_gate_operation
}

is_gate_operation if {
    op := object.get(input.action, "operation", "")
    op in [
        "ExecuteQuery",
        "ShowCatalogs", "ShowSchemas", "ShowTables", "ShowColumns", "DescribeTable",
        "AccessCatalog", "AccessSchema"
    ]
}

# ==============================================================================
# 2. ACESSO A DADOS (Regra Principal — PROTEGE os dados)
# Só é avaliada quando o Trino envia uma tabela específica.
# Exige match de coleção, campo permitido e tipo_query compatível.
# ==============================================================================
allow if {
    perm := data.user_permissions[req.token]

    # Deve haver uma coleção específica na requisição
    req.colecao != ""

    # O token DEVE ter acesso a esta coleção
    perm.nome_colecao == req.colecao

    # O campo DEVE estar na lista de permitidos
    is_campo_valido(perm, req)

    # O tipo de operação DEVE ser compatível com o token
    is_tipo_query_valido(perm, req)
}

# ==============================================================================
# REGRAS DE VALIDAÇÃO DE CAMPO
# ==============================================================================
has_campo(r) if {
    _ := r.campo
    r.campo != ""
    r.campo != null
}

# Se não há campo específico (ex: operação de tabela), permite
is_campo_valido(perm, r) if not has_campo(r)

# Se há campo, ele DEVE estar na lista de permitidos
is_campo_valido(perm, r) if {
    has_campo(r)
    r.campo in object.get(perm, "campos_permitidos", [])
}

# ==============================================================================
# REGRAS DE VALIDAÇÃO DE TIPO DE QUERY
# ==============================================================================
has_req_tq(r) if {
    _ := r.tipo_query
    r.tipo_query != ""
    r.tipo_query != null
}

has_perm_tq(perm) if {
    _ := perm.tipo_query
    perm.tipo_query != ""
    perm.tipo_query != null
}

# Se a requisição não tem tipo_query, permite
is_tipo_query_valido(perm, r) if not has_req_tq(r)

# Se a requisição tem tipo_query mas o token não restringe, permite
is_tipo_query_valido(perm, r) if {
    has_req_tq(r)
    not has_perm_tq(perm)
}

# Se AMBOS existem, devem dar match
is_tipo_query_valido(perm, r) if {
    has_req_tq(r)
    has_perm_tq(perm)
    valida_match_tipo_query(perm.tipo_query, r.tipo_query)
}

valida_match_tipo_query(perm_tq, req_tq) if {
    is_string(perm_tq)
    perm_tq == req_tq
}

valida_match_tipo_query(perm_tq, req_tq) if {
    is_array(perm_tq)
    req_tq in perm_tq
}

# ==============================================================================
# ANONIMIZAÇÃO (Column Masking)
# ==============================================================================
has_anonymization if {
    perm := data.user_permissions[req.token]
    perm.nome_colecao == req.colecao
    some rule in object.get(perm, "anonimizacao", [])
    rule.campo == req.campo
    rule.funcao != null
}

anonymize_rule := rule if {
    perm := data.user_permissions[req.token]
    perm.nome_colecao == req.colecao
    some rule in object.get(perm, "anonimizacao", [])
    rule.campo == req.campo
    rule.funcao != null
}

columnMask := {"expression": sprintf("SHA256(CAST(%s AS VARCHAR))", [req.campo])} if {
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

columnMask := {"expression": sprintf("substring(%s, 1, %d) || '***'", [req.campo, anonymize_rule["indice-regex"]])} if {
    anonymize_rule.funcao == "partial-mask"
    anonymize_rule["indice-regex"] != null
}

columnMask := {"expression": sprintf("'%s'", [anonymize_rule.simbolo])} if {
    anonymize_rule.funcao == "symbol-replace"
    anonymize_rule.simbolo != null
}

columnMask := {"expression": sprintf("regexp_replace(%s, '%s', '***')", [req.campo, anonymize_rule["indice-regex"]])} if {
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
required_filters := res if {
    perm := data.user_permissions[req.token]
    perm.nome_colecao == req.colecao
    res := object.get(perm, "filtros", [])
}

collection_info := {
    "colecao_id": object.get(perm, "colecao_id", null),
    "nome_colecao": perm.nome_colecao,
    "tipo_colecao": object.get(perm, "tipo_colecao", "N/A"),
    "tipo_campos": object.get(perm, "tipo_campos", "N/A"),
    "campos_permitidos": object.get(perm, "campos_permitidos", []),
} if {
    perm := data.user_permissions[req.token]
    perm.nome_colecao == req.colecao
}

deny contains msg if {
    not allow
    campo_str := object.get(input, "campo", object.get(input.action.resource.column, "columnName", "N/A"))
    colecao_str := object.get(input, "colecao", object.get(input.action.resource.table, "tableName", object.get(input.action.resource.table, "schemaName", "N/A")))
    token_raw := object.get(input, "token", object.get(input.context.identity, "user", "N/A"))

    msg := sprintf(
        "ACCESS DENIED: user=%s colecao=%s campo=%s",
        [
            format_token(token_raw),
            colecao_str,
            campo_str
        ]
    )
}

format_token(t) := substring(t, 0, 20) if is_string(t)
format_token(t) := "INVALID_OR_MISSING" if not is_string(t)