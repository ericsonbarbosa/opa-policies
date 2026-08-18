package portal.authz

import rego.v1

# Política Unificada: A verdade sobre os acessos reside EXCLUSIVAMENTE no data.json.
# Não há usuários hardcoded. Default Deny para tudo.
default allow := false

# ==============================================================================
# CAMADA DE NORMALIZAÇÃO DE INPUT (Traduz Trino e Portal para um formato único)
# ==============================================================================

get_token := t if {
    t := object.get(input.context.identity, "user", object.get(input, "token", ""))
}

get_colecao := c if {
    c := object.get(input.action.resource.table, "schemaName", object.get(input, "colecao", ""))
}

get_campo := f if {
    f := object.get(input.action.resource.column, "columnName", object.get(input, "campo", ""))
}

get_tipo_query := tq if {
    # 1. Prioridade MÁXIMA: Se há tipo_query explícito, usa-o
    raw := object.get(input.action, "tipo_query", object.get(input, "tipo_query", null))
    raw != null
    tq := raw
}

get_tipo_query := tq if {
    # 2. Fallback: Se NÃO há tipo_query explícito, infere da operação
    object.get(input.action, "tipo_query", null) == null
    object.get(input, "tipo_query", null) == null
    raw := object.get(input.action, "operation", "")
    tq := infer_tipo_query(raw)
}

# Helper para inferir tipo de query a partir da operação
# CORREÇÃO: Operações SQL do Trino são SEMPRE "jdbc" (ou "jdbc_dm" para datamarts)
infer_tipo_query(op) := "jdbc" if {
    is_string(op)
    regex.match("(?i)^(show|select|describe|use|insert|create|drop|alter|delete)", op)
}

# Operações de metadata específicas de datamart
infer_tipo_query(op) := "jdbc_dm" if {
    is_string(op)
    op in ["ShowCatalogs", "ShowSchemas", "ShowTables", "ShowColumns", "DescribeTable"]
}

# Fallback: se não é SQL, assume "api" (Portal)
infer_tipo_query(op) := "api" if {
    is_string(op)
    not regex.match("(?i)^(show|select|describe|use|insert|create|drop|alter|delete)", op)
    not op in ["ShowCatalogs", "ShowSchemas", "ShowTables", "ShowColumns", "DescribeTable"]
}

# Se não é string, retorna N/A
infer_tipo_query(_) := "N/A"

# Objeto de requisição padronizado para TODAS as regras abaixo
req := {
    "token": get_token,
    "colecao": get_colecao,
    "campo": get_campo,
    "tipo_query": get_tipo_query
}

# ==============================================================================
# 1. ACESSO A METADATA (Listar Catálogos, Schemas, Tabelas, Colunas)
# Permite que qualquer token válido no data.json liste a estrutura do banco,
# desde que o tipo_query seja compatível. Isso NÃO concede acesso aos dados.
# ==============================================================================
allow if {
    # O token DEVE existir no data.json
    perm := data.user_permissions[req.token]
    
    # A operação DEVE ser de metadata (enviada pelo plugin do Trino)
    is_trino_metadata_operation
    
    # O tipo_query DEVE ser compatível com a permissão do token
    is_tipo_query_valido(perm, req)
}

# Helper para identificar operações de metadata do Trino
is_trino_metadata_operation if {
    op := input.action.operation
    op in ["ShowCatalogs", "ShowSchemas", "ShowTables", "ShowColumns", "DescribeTable"]
}

# ==============================================================================
# 2. ACESSO A DADOS (Regra Principal - Exige match de coleção e campo)
# Esta é a regra que PROTEGE os dados. Ela não foi alterada e continua rigorosa.
# ==============================================================================
allow if {
    perm := data.user_permissions[req.token]
    
    # O token DEVE ter acesso a esta coleção específica
    perm.nome_colecao == req.colecao

    # O campo DEVE estar na lista de permitidos
    is_campo_valido(perm, req)

    # O tipo de operação DEVE ser compatível com o token
    is_tipo_query_valido(perm, req)
}

# ==============================================================================
# REGRAS DE VALIDAÇÃO DE CAMPO (Inalteradas)
# ==============================================================================
has_campo(r) if {
    _ := r.campo
    r.campo != ""
    r.campo != null
}

is_campo_valido(perm, r) if not has_campo(r)

is_campo_valido(perm, r) if {
    has_campo(r)
    r.campo in object.get(perm, "campos_permitidos", [])
}

# ==============================================================================
# REGRAS DE VALIDAÇÃO DE TIPO DE QUERY (Inalteradas)
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

is_tipo_query_valido(perm, r) if not has_req_tq(r)

is_tipo_query_valido(perm, r) if {
    has_req_tq(r)
    not has_perm_tq(perm)
}

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
# ANONIMIZAÇÃO (Inalterada)
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
# INFORMAÇÕES DA COLEÇÃO E AUDITORIA (Inalteradas)
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
    colecao_str := object.get(input, "colecao", object.get(input.action.resource.table, "schemaName", "N/A"))
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