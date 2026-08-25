package portal.authz

import rego.v1

default allow := false

# ==============================================================================
# NORMALIZAÇÃO DE INPUT
# ==============================================================================
get_identity := object.get(input, "identity", object.get(object.get(input, "context", {}), "identity", {}))
get_action := object.get(input, "action", {})
get_resource := object.get(get_action, "resource", {})
get_table := object.get(get_resource, "table", {})
get_column := object.get(get_resource, "column", {})
get_catalog_obj := object.get(get_resource, "catalog", {})

get_token := t if {
    t := object.get(get_identity, "user", object.get(input, "token", ""))
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
# NOVO: MULTI-PERMISSÃO POR USUÁRIO
# Aceita valor = objeto (legado) OU array de objetos (novo gerador)
# ==============================================================================
perms_for(token) := perms if {
    v := data.user_permissions[token]
    is_array(v)
    perms := v
}

perms_for(token) := perms if {
    v := data.user_permissions[token]
    is_object(v)
    perms := [v]
}

has_table_resource if {
    t := object.get(get_resource, "table", null)
    t != null
    t != {}
}

# ==============================================================================
# CONTAS DE SERVIÇO
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
# REGRA 1 — GATE GENÉRICO
# ==============================================================================
allow if {
    _ = data.user_permissions[req.token]
    not has_table_resource
}

# ==============================================================================
# REGRA 1.5 — METADADOS DE SISTEMA
# ==============================================================================
allow if {
    _ = data.user_permissions[req.token]
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
# REGRA 2 — ACESSO A DADOS (agora varre TODAS as permissões do usuário)
# ==============================================================================
allow if {
    some perm in perms_for(req.token)
    has_table_resource
    not is_system_target
    req.colecao != ""
    lower(perm.nome_colecao) == lower(req.colecao)
    is_campo_valido(perm, req)
    is_tipo_query_valido(perm, req)
}

# ==============================================================================
# VALIDAÇÃO DE CAMPO (case-insensitive)
# ==============================================================================
has_campo(r) if {
    _ := r.campo
    r.campo != ""
    r.campo != null
}

is_campo_valido(perm, r) if not has_campo(r)

campo_permitido_ci(perm, campo_req) if {
    some campo_perm in object.get(perm, "campos_permitidos", [])
    is_string(campo_perm)
    lower(campo_perm) == lower(campo_req)
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
# ANONIMIZAÇÃO (varre todas as permissões)
# ==============================================================================
has_anonymization if {
    some perm in perms_for(req.token)
    lower(perm.nome_colecao) == lower(req.colecao)
    some rule in object.get(perm, "anonimizacao", [])
    is_string(rule.campo)
    lower(rule.campo) == lower(req.campo)
    rule.funcao != null
}

anonymize_rule := rule if {
    some perm in perms_for(req.token)
    lower(perm.nome_colecao) == lower(req.colecao)
    some rule in object.get(perm, "anonimizacao", [])
    is_string(rule.campo)
    lower(rule.campo) == lower(req.campo)
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
# FILTROS E INFO DA COLEÇÃO
# ==============================================================================
required_filters := res if {
    some perm in perms_for(req.token)
    lower(perm.nome_colecao) == lower(req.colecao)
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
    lower(perm.nome_colecao) == lower(req.colecao)
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