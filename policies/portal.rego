package portal.authz

import rego.v1

# ==============================================================================
# POLÍTICA UNIFICADA PORTAL + TRINO — Default Deny
# ==============================================================================
default allow := false

# ==============================================================================
# HELPER: busca chave tolerando espaço no final (data.json com/sem espaço)
# ==============================================================================
get_key(obj, key, def) := val if {
    val := object.get(obj, key, null)
    val != null
}

get_key(obj, key, def) := val if {
    object.get(obj, key, null) == null
    val := object.get(obj, sprintf("%s ", [key]), def)
}

# ==============================================================================
# NORMALIZAÇÃO DE INPUT (BLINDADA)
# ==============================================================================
get_identity := object.get(input, "identity", object.get(object.get(input, "context", {}), "identity", {}))
get_action := object.get(input, "action", {})
get_resource := object.get(get_action, "resource", {})

get_table := t if {
    t := object.get(get_resource, "table", {})
    t != {}
}

get_table := t if {
    object.get(get_resource, "table", {}) == {}
    t := object.get(get_resource, "column", {})
}

get_column := object.get(get_resource, "column", {})
get_catalog_obj := object.get(get_resource, "catalog", {})

get_token := t if {
    t := trim(object.get(get_identity, "user", object.get(input, "token", "")), " ")
}

get_catalog := c if {
    c := object.get(get_catalog_obj, "catalogName", object.get(get_table, "catalogName", ""))
}

get_colecao := c if {
    c := object.get(
        get_table,
        "tableName",
        object.get(get_table, "schemaName", object.get(input, "colecao", ""))
    )
}

get_campo := f if {
    f := object.get(get_column, "columnName", object.get(input, "campo", ""))
}

get_columns := object.get(get_table, "columns", object.get(get_resource, "columns", []))

has_columns if {
    count(get_columns) > 0
}

get_tipo_query := tq if {
    raw := object.get(get_action, "tipo_query", object.get(input, "tipo_query", null))
    raw != null
    tq := raw
}

get_tipo_query := tq if {
    object.get(get_action, "tipo_query", null) == null
    object.get(input, "tipo_query", null) == null
    raw := object.get(get_action, "operation", "")
    tq := infer_tipo_query(raw)
}

infer_tipo_query(op) := "jdbc" if {
    is_string(op)
    regex.match("(?i)^(show|select|describe|use|insert|create|drop|alter|delete|execute)", op)
}

infer_tipo_query(op) := op if {
    is_string(op)
    not regex.match("(?i)^(show|select|describe|use|insert|create|drop|alter|delete|execute)", op)
    op in ["api", "jdbc", "api_doc", "jdbc_dm"]
}

infer_tipo_query(op) := "N/A" if {
    not is_string(op)
}

infer_tipo_query(op) := "N/A" if {
    is_string(op)
    not regex.match("(?i)^(show|select|describe|use|insert|create|drop|alter|delete|execute)", op)
    not op in ["api", "jdbc", "api_doc", "jdbc_dm"]
}

req := {
    "token": get_token,
    "catalog": get_catalog,
    "colecao": get_colecao,
    "campo": get_campo,
    "tipo_query": get_tipo_query
}

# ==============================================================================
# FONTE DE PERMISSÕES (array por usuário + tolerância a espaços)
# ==============================================================================
raw_permissions := p if {
    p := data.user_permissions
}

raw_permissions := p if {
    not data.user_permissions
    p := data["user_permissions "]
}

has_permissions(token) if {
    some k, _ in raw_permissions
    trim(k, " ") == token
}

perms_for(token) := perms if {
    some k, v in raw_permissions
    trim(k, " ") == token
    is_array(v)
    perms := v
}

perms_for(token) := perms if {
    some k, v in raw_permissions
    trim(k, " ") == token
    is_object(v)
    perms := [v]
}

colecao_match(perm, colecao_req) if {
    nome := get_key(perm, "nome_colecao", "")
    is_string(nome)
    lower(trim(nome, " ")) == lower(trim(colecao_req, " "))
}

has_table_resource if {
    t := object.get(get_resource, "table", null)
    t != null
    t != {}
}

# ==============================================================================
# CONJUNTO ATIVO/BLOQUEADO
# ativo=true (ou ausente) = liberado | ativo=false = bloqueado/oculto
# Encerramento: entrada permanece com ativo=false
# Reativação: gera duplicata com ativo=true (só esta vigora)
# ==============================================================================
perm_ativa(perm) if {
    get_key(perm, "ativo", true) == true
}

perm_ativa(perm) if {
    raw := get_key(perm, "ativo", "true")
    is_string(raw)
    lower(trim(raw, " ")) == "true"
}

perm_bloqueada(perm) if {
    not perm_ativa(perm)
}

# ==============================================================================
# CONTROLE TEMPORAL (janela ISO 8601 + validade)
# ==============================================================================
now_ns := time.now_ns()

parse_ts(raw) := ns if {
    is_string(raw)
    trim(raw, " ") != ""
    ns := time.parse_rfc3339_ns(trim(raw, " "))
}

perm_vencida(perm) if {
    raw := get_key(perm, "data_validade", null)
    is_string(raw)
    trim(raw, " ") != ""
    vd := time.date([time.parse_rfc3339_ns(trim(raw, " ")), "America/Sao_Paulo"])
    td := time.date([time.now_ns(), "America/Sao_Paulo"])
    (td[0] * 10000 + td[1] * 100 + td[2]) > (vd[0] * 10000 + vd[1] * 100 + vd[2])
}

perm_fora_janela(perm) if {
    ini := parse_ts(get_key(perm, "horario_inicio", null))
    now_ns < ini
}

perm_fora_janela(perm) if {
    fim := parse_ts(get_key(perm, "horario_fim", null))
    now_ns > fim
}

limitar_acesso_soft(perm) if {
    get_key(perm, "limitar_acesso", null) == false
}

limitar_acesso_soft(perm) if {
    raw := get_key(perm, "limitar_acesso", "")
    is_string(raw)
    lower(trim(raw, " ")) == "false"
}

perm_bloqueio_tempo(perm) if {
    perm_fora_janela(perm)
    not limitar_acesso_soft(perm)
}

is_tempo_valido(perm) if {
    not perm_vencida(perm)
    not perm_bloqueio_tempo(perm)
}

access_alert contains msg if {
    some perm in perms_for(req.token)
    perm_ativa(perm)
    colecao_match(perm, req.colecao)
    not perm_vencida(perm)
    perm_fora_janela(perm)
    limitar_acesso_soft(perm)
    msg := sprintf("OUT_OF_HOURS: user=%s colecao=%s", [req.token, req.colecao])
}

expired_alert contains msg if {
    some perm in perms_for(req.token)
    perm_ativa(perm)
    colecao_match(perm, req.colecao)
    perm_vencida(perm)
    msg := sprintf("EXPIRED: user=%s colecao=%s validade=%s", [
        req.token,
        req.colecao,
        get_key(perm, "data_validade", "?")
    ])
}

# ==============================================================================
# CONTAS DE SERVIÇO
# ==============================================================================
service_accounts_full := {"trino", "hadoop", "ingestor", "presto"}

allow if {
    req.token in service_accounts_full
}

service_account_readonly := "servico"

write_ops := {
    "InsertIntoColumns", "InsertIntoTable",
    "CreateTable", "CreateTableAsSelect", "CreateView", "CreateMaterializedView",
    "CreateSchema", "DropTable", "DropView", "DropMaterializedView", "DropSchema",
    "AlterTable", "AlterView", "RenameTable", "RenameColumn", "RenameSchema",
    "AddColumn", "DropColumn", "DeleteFromTable", "TruncateTable",
    "CommentTable", "CommentColumn",
    "Grant", "Deny", "Revoke",
    "CreateRole", "DropRole", "GrantRoles", "RevokeRoles", "SetRole"
}

allow if {
    req.token == service_account_readonly
    op := object.get(get_action, "operation", "")
    not op in write_ops
}

# ==============================================================================
# REGRA 1 — GATE GENÉRICO (sem tabela)
# ==============================================================================
allow if {
    has_permissions(req.token)
    not has_table_resource
}

# ==============================================================================
# REGRA 1.5 — METADADOS DE SISTEMA
# ==============================================================================
allow if {
    has_permissions(req.token)
    has_table_resource
    is_system_target
}

is_system_target if {
    req.catalog in ["system", "memory", "jmx", "tpch", "tpcds", "sys"]
}

is_system_target if {
    object.get(get_table, "schemaName", "") == "information_schema"
}

# ==============================================================================
# REGRA 2 — ACESSO A DADOS (ativa + coleção + colunas + temporal)
# ==============================================================================
allow if {
    some perm in perms_for(req.token)
    perm_ativa(perm)
    has_table_resource
    not is_system_target
    req.colecao != ""
    colecao_match(perm, req.colecao)
    is_campo_valido(perm, req)
    is_tipo_query_valido(perm, req)
    is_tempo_valido(perm)
}

# ==============================================================================
# VALIDAÇÃO DE CAMPO
# ==============================================================================
has_campo(r) if {
    _ := r.campo
    r.campo != ""
    r.campo != null
}

campo_permitido_ci(perm, campo_req) if {
    campos := get_key(perm, "campos_permitidos", [])
    some campo_perm in campos
    is_string(campo_perm)
    lower(trim(campo_perm, " ")) == lower(trim(campo_req, " "))
}

is_campo_valido(perm, r) if {
    not has_campo(r)
    not has_columns
}

is_campo_valido(perm, r) if {
    not has_campo(r)
    has_columns
    every c in get_columns {
        campo_permitido_ci(perm, c)
    }
}

is_campo_valido(perm, r) if {
    has_campo(r)
    campo_permitido_ci(perm, r.campo)
}

# ==============================================================================
# VALIDAÇÃO DE TIPO DE QUERY
# ==============================================================================
has_req_tq(r) if {
    _ := r.tipo_query
    r.tipo_query != ""
    r.tipo_query != null
}

has_perm_tq(perm) if {
    tq := get_key(perm, "tipo_query", null)
    tq != null
    tq != ""
}

is_tipo_query_valido(perm, r) if not has_req_tq(r)

is_tipo_query_valido(perm, r) if {
    has_req_tq(r)
    not has_perm_tq(perm)
}

is_tipo_query_valido(perm, r) if {
    has_req_tq(r)
    has_perm_tq(perm)
    valida_match_tipo_query(get_key(perm, "tipo_query", null), r.tipo_query)
}

valida_match_tipo_query(perm_tq, req_tq) if {
    is_string(perm_tq)
    trim(perm_tq, " ") == req_tq
}

valida_match_tipo_query(perm_tq, req_tq) if {
    is_array(perm_tq)
    req_tq in perm_tq
}

# ==============================================================================
# ANONIMIZAÇÃO (Column Masking) — só para conjuntos ATIVOS
# ==============================================================================
find_anonymization_rules := [rule |
    some perm in perms_for(req.token)
    perm_ativa(perm)
    colecao_match(perm, req.colecao)
    some r in get_key(perm, "anonimizacao", [])
    campo_r := get_key(r, "campo", null)
    is_string(campo_r)
    lower(trim(campo_r, " ")) == lower(trim(req.campo, " "))
    funcao_r := get_key(r, "funcao", null)
    is_string(funcao_r)
    trim(funcao_r, " ") != ""
    rule := r
]

has_anonymization if {
    count(find_anonymization_rules) > 0
}

anonymize_rule := find_anonymization_rules[0] if {
    count(find_anonymization_rules) > 0
}

get_funcao(rule) := f if {
    raw := get_key(rule, "funcao", "")
    is_string(raw)
    f := trim(raw, " ")
}

get_simbolo(rule) := s if {
    raw := get_key(rule, "simbolo", "*")
    is_string(raw)
    t := trim(raw, " ")
    t != ""
    s := t
}

get_simbolo(rule) := "*" if {
    raw := get_key(rule, "simbolo", "*")
    not is_string(raw)
}

get_simbolo(rule) := "*" if {
    raw := get_key(rule, "simbolo", "*")
    is_string(raw)
    trim(raw, " ") == ""
}

get_indice(rule) := n if {
    raw := get_key(rule, "indice-regex", null)
    is_number(raw)
    n := raw
}

columnMask := {"expression": sprintf("to_hex(sha256(to_utf8(%s)))", [req.campo])} if {
    get_funcao(anonymize_rule) == "token-sha256"
}

columnMask := {"expression": sprintf("regexp_replace(%s, '.', '%s')", [req.campo, get_simbolo(anonymize_rule)])} if {
    get_funcao(anonymize_rule) == "mascarar-por-completo"
}

columnMask := {"expression": sprintf("concat(rpad('', %d, '%s'), substring(%s, %d))", [
    n, sym, req.campo, n + 1
])} if {
    get_funcao(anonymize_rule) == "mascarar-inicio"
    n := get_indice(anonymize_rule)
    sym := get_simbolo(anonymize_rule)
    is_number(n)
}

columnMask := {"expression": sprintf("concat(substring(%s, 1, greatest(length(%s) - %d, 0)), rpad('', %d, '%s'))", [
    req.campo, req.campo, n, n, sym
])} if {
    get_funcao(anonymize_rule) == "mascarar-fim"
    n := get_indice(anonymize_rule)
    sym := get_simbolo(anonymize_rule)
    is_number(n)
}

columnMask := {"expression": sprintf("CASE WHEN length(%s) > %d THEN concat(rpad('', %d, '%s'), substring(%s, %d, greatest(length(%s) - %d, 0)), rpad('', %d, '%s')) ELSE rpad('', length(%s), '%s') END", [
    req.campo, 2 * n, n, sym, req.campo, n + 1, req.campo, 2 * n, n, sym, req.campo, sym
])} if {
    get_funcao(anonymize_rule) == "mascarar-inicio-fim"
    n := get_indice(anonymize_rule)
    sym := get_simbolo(anonymize_rule)
    is_number(n)
}

columnMask := {"expression": sprintf("substring(%s, 1, %d) || '***'", [req.campo, get_key(anonymize_rule, "indice-regex", 0)])} if {
    get_funcao(anonymize_rule) == "partial-mask"
    is_number(get_key(anonymize_rule, "indice-regex", null))
}

columnMask := {"expression": sprintf("'%s'", [get_simbolo(anonymize_rule)])} if {
    get_funcao(anonymize_rule) == "symbol-replace"
}

columnMask := {"expression": sprintf("regexp_replace(%s, '%s', '***')", [req.campo, get_key(anonymize_rule, "indice-regex", "")])} if {
    get_funcao(anonymize_rule) == "regex-mask"
    is_string(get_key(anonymize_rule, "indice-regex", null))
}

columnMask := {"expression": "'***'"} if {
    has_anonymization
    not get_funcao(anonymize_rule) in ["token-sha256", "mascarar-por-completo", "mascarar-inicio", "mascarar-fim", "mascarar-inicio-fim", "partial-mask", "symbol-replace", "regex-mask"]
}

# ==============================================================================
# FILTROS E INFO DA COLEÇÃO
# ==============================================================================
required_filters := res if {
    some perm in perms_for(req.token)
    perm_ativa(perm)
    colecao_match(perm, req.colecao)
    res := get_key(perm, "filtros", [])
}

collection_info := {
    "colecao_id": get_key(perm, "colecao_id", null),
    "nome_colecao": get_key(perm, "nome_colecao", ""),
    "tipo_colecao": get_key(perm, "tipo_colecao", "N/A"),
    "tipo_campos": get_key(perm, "tipo_campos", "N/A"),
    "campos_permitidos": get_key(perm, "campos_permitidos", []),
} if {
    some perm in perms_for(req.token)
    perm_ativa(perm)
    colecao_match(perm, req.colecao)
}

# ==============================================================================
# ROW FILTERS (SQL pronto do Portal) — só para conjuntos ATIVOS
# ==============================================================================
rowFilters := filters if {
    filters := [
        {"expression": e} |
            some perm in perms_for(req.token)
            perm_ativa(perm)
            colecao_match(perm, req.colecao)
            e := trim(get_key(perm, "row_filter_sql", ""), " ")
            e != ""
    ]
    count(filters) > 0
}

# ==============================================================================
# DENY — silencioso quando o conjunto está bloqueado (ativo=true)
# ==============================================================================
conjunto_silenciado if {
    req.colecao != ""
    some perm in perms_for(req.token)
    colecao_match(perm, req.colecao)
    perm_bloqueada(perm)
}

deny contains msg if {
    not allow
    not conjunto_silenciado
    campo_str := object.get(input, "campo", object.get(get_column, "columnName", "N/A"))
    colecao_str := object.get(input, "colecao", object.get(get_table, "tableName", object.get(get_table, "schemaName", "N/A")))
    token_raw := object.get(input, "token", object.get(get_identity, "user", "N/A"))

    msg := sprintf(
        "ACCESS DENIED: user=%s colecao=%s campo=%s",
        [format_token(token_raw), colecao_str, campo_str]
    )
}

format_token(t) := substring(t, 0, 20) if is_string(t)
format_token(t) := "INVALID_OR_MISSING" if not is_string(t)