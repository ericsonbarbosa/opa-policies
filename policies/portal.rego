package portal.authz

import rego.v1

# ==============================================================================
# POLÍTICA UNIFICADA PORTAL + TRINO
# A verdade sobre os acessos reside EXCLUSIVAMENTE no data.json.
# Default Deny para tudo que não for explicitamente permitido.
# ==============================================================================
default allow := false

# ==============================================================================
# CAMADA DE NORMALIZAÇÃO DE INPUT (BLINDADA)
# ==============================================================================
get_identity := object.get(input, "identity", object.get(object.get(input, "context", {}), "identity", {}))
get_action := object.get(input, "action", {})
get_resource := object.get(get_action, "resource", {})

# Allow: tabela vem em resource.table
get_table := t if {
    t := object.get(get_resource, "table", {})
    t != {}
}

# GetColumnMask: o Trino embute catalog/schema/table DENTRO de resource.column
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

# SelectFromColumns real do Trino: colunas vêm num array DENTRO de resource.table
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
# FONTE DE PERMISSÕES (tolerante a chave com espaço e ao formato antigo)
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

# NOVO formato: array de permissões por usuário
perms_for(token) := perms if {
    some k, v in raw_permissions
    trim(k, " ") == token
    is_array(v)
    perms := v
}

# LEGADO: objeto único
perms_for(token) := perms if {
    some k, v in raw_permissions
    trim(k, " ") == token
    is_object(v)
    perms := [v]
}

# Comparação de coleção tolerante a espaço/case
colecao_match(perm, colecao_req) if {
    lower(trim(object.get(perm, "nome_colecao", ""), " ")) == lower(trim(colecao_req, " "))
}

has_table_resource if {
    t := object.get(get_resource, "table", null)
    t != null
    t != {}
}

# ==============================================================================
# CONTAS DE SERVIÇO / INFRAESTRUTURA
# ==============================================================================
service_accounts_full := {"trino", "hadoop", "ingestor"}

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
# CONTROLE TEMPORAL (JANELA DE HORÁRIO + DATA DE VALIDADE)
# Campos do data.json (ISO 8601):
#   "horario_inicio" / "horario_fim" → janela de acesso
#   "limitar_acesso": true  → modo SOFT (fora da janela libera; e-mail fica
#                             por conta da camada de serviço / access_alert)
#   "limitar_acesso": false → modo HARD (fora da janela = bloqueio)
#   "data_validade"         → após esta data = bloqueio duro sempre
# ==============================================================================
now_ns := time.now_ns()

parse_ts(raw) := ns if {
    is_string(raw)
    trim(raw, " ") != ""
    ns := time.parse_rfc3339_ns(trim(raw, " "))
}

perm_vencida(perm) if {
    ns := parse_ts(object.get(perm, "data_validade", null))
    now_ns >= ns
}

perm_fora_janela(perm) if {
    ini := parse_ts(object.get(perm, "horario_inicio", null))
    fim := parse_ts(object.get(perm, "horario_fim", null))
    not (now_ns >= ini and now_ns <= fim)
}

# limitar_acesso == true → modo soft
limitar_acesso_soft(perm) if {
    object.get(perm, "limitar_acesso", null) == true
}

limitar_acesso_soft(perm) if {
    raw := object.get(perm, "limitar_acesso", "")
    is_string(raw)
    lower(trim(raw, " ")) == "true"
}

# Bloqueio duro: fora da janela E modo hard (flag false/ausente)
perm_bloqueio_tempo(perm) if {
    perm_fora_janela(perm)
    not limitar_acesso_soft(perm)
}

is_tempo_valido(perm) if {
    not perm_vencida(perm)
    not perm_bloqueio_tempo(perm)
}

# INFORMATIVO (não afeta o allow): camada de serviço pode consultar este
# endpoint para disparar o e-mail de "acesso fora do horário" (modo soft).
access_alert contains msg if {
    some perm in perms_for(req.token)
    colecao_match(perm, req.colecao)
    not perm_vencida(perm)
    perm_fora_janela(perm)
    limitar_acesso_soft(perm)
    msg := sprintf("OUT_OF_HOURS: user=%s colecao=%s", [req.token, req.colecao])
}

# ==============================================================================
# REGRA 1 — GATE GENÉRICO (nível de catálogo/schema, SEM tabela)
# ==============================================================================
allow if {
    has_permissions(req.token)
    not has_table_resource
}

# ==============================================================================
# REGRA 1.5 — METADADOS DE SISTEMA / INFORMATION_SCHEMA (com tabela)
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
# REGRA 2 — ACESSO A DADOS (varre TODAS as permissões do usuário)
# ==============================================================================
allow if {
    some perm in perms_for(req.token)
    has_table_resource
    not is_system_target
    req.colecao != ""
    colecao_match(perm, req.colecao)
    is_campo_valido(perm, req)
    is_tipo_query_valido(perm, req)
    is_tempo_valido(perm)
}

# ==============================================================================
# VALIDAÇÃO DE CAMPO (case/space-insensitive + array columns do Trino)
# ==============================================================================
has_campo(r) if {
    _ := r.campo
    r.campo != ""
    r.campo != null
}

campo_permitido_ci(perm, campo_req) if {
    some campo_perm in object.get(perm, "campos_permitidos", [])
    is_string(campo_perm)
    lower(trim(campo_perm, " ")) == lower(trim(campo_req, " "))
}

# Sem coluna nem array (metadados, SHOW, etc.) → libera
is_campo_valido(perm, r) if {
    not has_campo(r)
    not has_columns
}

# SelectFromColumns real do Trino: valida CADA coluna do array
is_campo_valido(perm, r) if {
    not has_campo(r)
    has_columns
    every c in get_columns {
        campo_permitido_ci(perm, c)
    }
}

# Formato de curl/legado (column.columnName)
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
    trim(perm_tq, " ") == req_tq
}

valida_match_tipo_query(perm_tq, req_tq) if {
    is_array(perm_tq)
    req_tq in perm_tq
}

# ==============================================================================
# ANONIMIZAÇÃO (Column Masking) — varre todas as permissões
# ==============================================================================
has_anonymization if {
    some perm in perms_for(req.token)
    colecao_match(perm, req.colecao)
    some rule in object.get(perm, "anonimizacao", [])
    is_string(rule.campo)
    lower(trim(rule.campo, " ")) == lower(req.campo)
    get_funcao(rule) != ""
}

anonymize_rule := rule if {
    some perm in perms_for(req.token)
    colecao_match(perm, req.colecao)
    some rule in object.get(perm, "anonimizacao", [])
    is_string(rule.campo)
    lower(trim(rule.campo, " ")) == lower(req.campo)
    get_funcao(rule) != ""
}

# --- Helpers de leitura tolerantes a espaço/null ---
get_funcao(rule) := f if {
    raw := object.get(rule, "funcao", "")
    is_string(raw)
    f := trim(raw, " ")
}

get_simbolo(rule) := s if {
    raw := object.get(rule, "simbolo", "")
    is_string(raw)
    t := trim(raw, " ")
    t != ""
    s := t
}

get_simbolo(rule) := "*" if {
    raw := object.get(rule, "simbolo", "")
    is_string(raw)
    trim(raw, " ") == ""
}

get_simbolo(rule) := "*" if {
    raw := object.get(rule, "simbolo", "")
    not is_string(raw)
}

get_indice(rule) := n if {
    raw := object.get(rule, "indice-regex", null)
    is_number(raw)
    n := raw
}

# --- 1. token-sha256 (sem parâmetro) ---
columnMask := {"expression": sprintf("to_hex(sha256(to_utf8(%s)))", [req.campo])} if {
    get_funcao(anonymize_rule) == "token-sha256"
}

# --- 2. mascarar-por-completo (parâmetro: símbolo) ---
columnMask := {"expression": sprintf("regexp_replace(%s, '.', '%s')", [req.campo, get_simbolo(anonymize_rule)])} if {
    get_funcao(anonymize_rule) == "mascarar-por-completo"
}

# --- 3. mascarar-inicio (símbolo + nº casas) ---
columnMask := {"expression": sprintf("concat(rpad('', %d, '%s'), substring(%s, %d))", [
    n,
    sym,
    req.campo,
    n + 1
])} if {
    get_funcao(anonymize_rule) == "mascarar-inicio"
    n := get_indice(anonymize_rule)
    sym := get_simbolo(anonymize_rule)
}

# --- 4. mascarar-fim (símbolo + nº casas) ---
columnMask := {"expression": sprintf("concat(substring(%s, 1, greatest(length(%s) - %d, 0)), rpad('', %d, '%s'))", [
    req.campo,
    req.campo,
    n,
    n,
    sym
])} if {
    get_funcao(anonymize_rule) == "mascarar-fim"
    n := get_indice(anonymize_rule)
    sym := get_simbolo(anonymize_rule)
}

# --- 5. mascarar-inicio-fim (símbolo + nº casas) ---
columnMask := {"expression": sprintf("CASE WHEN length(%s) > %d THEN concat(rpad('', %d, '%s'), substring(%s, %d, greatest(length(%s) - %d, 0)), rpad('', %d, '%s')) ELSE rpad('', length(%s), '%s') END", [
    req.campo,
    2 * n,
    n,
    sym,
    req.campo,
    n + 1,
    req.campo,
    2 * n,
    n,
    sym,
    req.campo,
    sym
])} if {
    get_funcao(anonymize_rule) == "mascarar-inicio-fim"
    n := get_indice(anonymize_rule)
    sym := get_simbolo(anonymize_rule)
}

# --- Legado: partial-mask ---
columnMask := {"expression": sprintf("substring(%s, 1, %d) || '***'", [req.campo, anonymize_rule["indice-regex"]])} if {
    get_funcao(anonymize_rule) == "partial-mask"
    is_number(anonymize_rule["indice-regex"])
}

# --- Legado: symbol-replace ---
columnMask := {"expression": sprintf("'%s'", [get_simbolo(anonymize_rule)])} if {
    get_funcao(anonymize_rule) == "symbol-replace"
}

# --- Legado: regex-mask ---
columnMask := {"expression": sprintf("regexp_replace(%s, '%s', '***')", [req.campo, anonymize_rule["indice-regex"]])} if {
    get_funcao(anonymize_rule) == "regex-mask"
    is_string(anonymize_rule["indice-regex"])
}

# --- Fallback genérico ---
columnMask := {"expression": "'***'"} if {
    has_anonymization
    not get_funcao(anonymize_rule) in ["token-sha256", "mascarar-por-completo", "mascarar-inicio", "mascarar-fim", "mascarar-inicio-fim", "partial-mask", "symbol-replace", "regex-mask"]
}

# ==============================================================================
# FILTROS E INFO DA COLEÇÃO
# ==============================================================================
required_filters := res if {
    some perm in perms_for(req.token)
    colecao_match(perm, req.colecao)
    res := object.get(perm, "filtros", [])
}

collection_info := {
    "colecao_id": object.get(perm, "colecao_id", null),
    "nome_colecao": perm.nome_colecao,
    "tipo_colecao": object.get(perm, "tipo_colecao", "N/A"),
    "tipo_campos": object.get(perm, "tipo_campos", "N/A"),
    "campos_permitidos": object.get(perm, "campos_permitidos", []),
} if {
    some perm in perms_for(req.token)
    colecao_match(perm, req.colecao)
}

deny contains msg if {
    not allow
    campo_str := object.get(input, "campo", object.get(get_column, "columnName", "N/A"))
    colecao_str := object.get(input, "colecao", object.get(get_table, "tableName", object.get(get_table, "schemaName", "N/A")))
    token_raw := object.get(input, "token", object.get(get_identity, "user", "N/A"))

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