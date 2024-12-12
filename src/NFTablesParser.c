#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <nftables/libnftables.h>
#include <json-c/json.h>

#include <NFTablesParser.h>
#include <nftables.h>


#if NFTABLES_ACTIVE == 1

// EXTERNAL Global vars
extern struct write_global_vars w_globvars;

// PRIVATE FUNCTIONS POR ITERATE AND PARSE ALL TABLES, CHAINS AND RULES OF NFTABLES
/*
Iterate and parse all chains in a nftables table
PARAMS:     nftables context
            Table's name
MODIFIES:   input_chains list adding all chains with input hook
RETURN:     1 if all is ok
            0 if any error
*/
int iterate_chains(struct nft_ctx *ctx, const char *table_name);
/*
Iterate and parse all rules in a nftables chain
PARAMS:     nftables context
            Table's name
            Chain's name
MODIFIES:   chains dictionary adding all rules of the chain (in a list which is the value's dict)
RETURN:     1 if all is ok
            0 if any error
*/
int iterate_chain_rules(struct nft_ctx *ctx, const char *table_name, const char *chain_name);
/*
Iterate and parse all expression in a nftables rule
PARAMS:     A list
            A rule
MODIFIES:   l_chain list adding the rule
RETURN:     1 if all is ok
            0 if any error
*/
int iterate_rule_expresions(double_list l_chain, json_object *expresions_obj);


// PRIVATE FUNCTION PROTOTYPES RELATIVE TO PARSE RULES AND EXPRESSIONS
/*
Parse a match expression
PARAMS:     A rule
            A match expression
RETURN:     1 if all is ok
            0 if any error
*/
int parse_match(rule_t *rule, struct json_object *m_obj);
/*
Parse a meta expression
PARAMS:     A rule
            An expression to store this one
            The left part of the meta expression
            The right part of the meta expression
RETURN:     1 if it is a meta expression and parse is ok
            0 if an error
*/
int left_meta(rule_t *rule, expr_t *expr, struct json_object *left_obj, struct json_object *right_obj);
/*
Parse a payload expression
PARAMS:     A rule
            An expression to store this one
            The left part of the payload expression
            The right part of the payload expression
RETURN:     1 if it is a payload expression and parse is ok
            0 if an error
*/
int left_payload(rule_t *rule, expr_t *expr, struct json_object *left_obj, struct json_object *right_obj);
/*
Parse a ct expression
PARAMS:     A rule
            An expression to store this one
            The left part of the meta expression
            The right part of the meta expression
RETURN:     1 if it is a meta expression and parse is ok
            0 if an error
*/
int left_ct(rule_t *rule, expr_t *expr, struct json_object *left_obj, struct json_object *right_obj);
/*
Insert a device name in a expression
PARAMS:     An expression to store the device
            The device name
MODIFIES:   expr to store the device name
RETURN:     1 if all is ok
            0 if an error
*/
int store_devname(expr_t *expr, const char *dev_name);
/*
Parse a iifname/oifname expression
PARAMS:     A rule
            An expression to store this one
            The right part of the expression
            0 if it is a iifname expressión or 1 if it is a oifname one
MODIFIES:   expr to store the expression
            rule to add this expression
RETURN:     1 if all is ok
            0 if an error
*/
int right_ifname(rule_t *rule, expr_t *expr, struct json_object *right_obj, int dev_type);
/*
Insert a global protocol in a expression
PARAMS:     An expression to store the device
            The protocol (int text format: tcp, udp, icmp)
MODIFIES:   expr to store the protocol
RETURN:     1 if all is ok
            0 if an error
*/
int store_protocol(expr_t *expr, const char *proto);
/*
Parse a global protocol expression
PARAMS:     A rule
            An expression to store this one
            The right part of the expression
MODIFIES:   expr to store the expression
            rule to add this expression
RETURN:     1 if all is ok
            0 if an error
*/
int right_protocol(rule_t *rule, expr_t *expr, struct json_object *right_obj);
/*
Parse local protocol of expression
PARAMS:     An expression to store local protocol
            The protocol (JSON object)
MODIFIES:   expr to store the local protocol
RETURN:     1 if all is ok
            0 if an error
*/
int right_local_protocol(expr_t *expr, struct json_object *proto);
/*
Insert an address or range of addresses in a expression
PARAMS:     An expression to store the address
            The address (in text format x.x.x.x) or the lower address (if a range address)
            The len (number of bits for mask address)
            The second address (in text format x.x.x.x) (the upper address ) of range.
            Or NULL if it is not a range
            The len (number of bits for mask address) or 0 if it is not a range
MODIFIES:   expr to store the address
RETURN:     1 if all is ok
            0 if an error
*/
int store_address(expr_t *expr, const char *ip_address, uint8_t len, const char *ip_address2, uint8_t len2);
/*
Parse a saddr/daddr single value
PARAMS:     An expression to store this address
            The adress in JSON format (either single value, range or prefix)
MODIFIES:   expr to store the expression
RETURN:     1 if all is ok
            0 if an error
*/
int right_addr_single_value(expr_t *expr, struct json_object *value_obj);
/*
Parse a saddr/daddr expression
PARAMS:     A rule
            An expression to store this one
            The right part of the expression
            0 if it is a saddr expressión or 1 if it is a daddr one
MODIFIES:   expr to store the expression
            rule to add this expression
RETURN:     1 if all is ok
            0 if an error
*/
int right_addr(rule_t *rule, expr_t *expr, struct json_object *right_obj, int dest);
/*
Insert a port or range of ports in a expression
PARAMS:     An expression to store the port
            The port (in text format) or the lower port (if a range of ports)
            The second port (in text format) (the upper port) of range.
            Or NULL if it is not a range
MODIFIES:   expr to store the port (or range)
RETURN:     1 if all is ok
            0 if an error
*/
int store_port(expr_t *expr, const char *port, const char *port2);
/*
Parse a sport/dport single value
PARAMS:     An expression to store this port
            The port in JSON format (either single value or range)
MODIFIES:   expr to store the expression
RETURN:     1 if all is ok
            0 if an error
*/
int right_port_single_value(expr_t *expr, struct json_object *value_obj);
/*
Parse a sport/dport expression
PARAMS:     A rule
            An expression to store this one
            The right part of the expression
            0 if it is a sport expressión or 1 if it is a dport one
MODIFIES:   expr to store the expression
            rule to add this expression
RETURN:     1 if all is ok
            0 if an error
*/
int right_port(rule_t *rule, expr_t *expr, struct json_object *right_obj, int dest);
/*
Insert a ct state in a expression
PARAMS:     An expression to store the device
            The ct state (int text format: established, related, invalid)
MODIFIES:   expr to store the ct state
RETURN:     1 if all is ok
            0 if an error
*/
int store_ct_state(expr_t *expr, const char *state);
/*
Parse a CT state expression
PARAMS:     A rule
            An expression to store this one
            The right part of the expression
MODIFIES:   expr to store the expression
            rule to add this expression
RETURN:     1 if all is ok
            0 if an error
*/
int right_ct_state(rule_t *rule, expr_t *expr, struct json_object *right_obj);

/*
Iterate and parse all nftables tables and chains
RETURN: 1 if all is ok
        0 if any error
*/
int iterate_tables_and_chains() {
    struct nft_ctx *ctx;
    struct json_object *parsed_json;
    struct json_object *nftables;
    struct json_object *obj;
    struct json_object *table_obj;

    // nftables context
    ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!ctx) {
        perror("iterate_tables_and_chains: nft_ctx_new");
        return 0;
    }

    // Output to ctx with JSON format
    nft_ctx_output_set_flags(ctx, NFT_CTX_OUTPUT_HANDLE | NFT_CTX_OUTPUT_JSON);
    nft_ctx_buffer_output(ctx);
    

    // Iterate all tables
    if (nft_run_cmd_from_buffer(ctx, "list tables") < 0) {
        fprintf(stderr, "iterate_tables_and_chains: Error with command: %s\n", nft_ctx_get_error_buffer(ctx));
        nft_ctx_free(ctx);
        return 0;
    }

    // Get JSON output
    const char *json_str = nft_ctx_get_output_buffer(ctx);
    if (!json_str) {
        fprintf(stderr, "iterate_tables_and_chains: Can't get command output\n");
        nft_ctx_free(ctx);
        return 0;
    }

    // Apply JSON parser to extract tables
    parsed_json = json_tokener_parse(json_str);
    if (!parsed_json) {
        fprintf(stderr, "iterate_tables_and_chains: JSON parser error\n");
        nft_ctx_free(ctx);
        return 0;
    }

    // Get nftables object from JSON
    if (!json_object_object_get_ex(parsed_json, "nftables", &nftables)) {
        fprintf(stderr, "iterate_tables_and_chains: 'nftables' object not found\n");
        json_object_put(parsed_json);
        nft_ctx_free(ctx);
        return 0;
    }

    // Iterate tables
    for (size_t i = 0; i < json_object_array_length(nftables); i++) {
        // Get current JSON object
        obj = json_object_array_get_idx(nftables, i);
        
        // Is it a table?
        if (json_object_object_get_ex(obj, "table", &table_obj)) {
            // Get name's table
            const char *table_name = json_object_get_string(json_object_object_get(table_obj, "name"));

            // Iterate table's chains
            if (!iterate_chains(ctx, table_name)) {
                json_object_put(parsed_json);
                nft_ctx_free(ctx);
                return 0;
            }
        }
    }

    json_object_put(parsed_json);
    nft_ctx_free(ctx);
    return 1;
}

/*
Iterate and parse all chains in a nftables table
PARAMS:     nftables context
            Table's name
MODIFIES:   input_chains list adding all chains with input hook
RETURN:     1 if all is ok
            0 if any error
*/
int iterate_chains(struct nft_ctx *ctx, const char *table_name) {
    char cmd[256];
    struct json_object *parsed_json;
    struct json_object *nftables;
    struct json_object *obj;
    struct json_object *chain_obj;
    input_chain_t *el;
    const char *chain_name;
    const char *family;
    const char *hook;
    const char *priority;
    const char *policy;

    // Command for listing chains of a table
    snprintf(cmd, sizeof(cmd), "list table inet %s", table_name);

    // Execute command and get its output
    if (nft_run_cmd_from_buffer(ctx, cmd) < 0) {
        fprintf(stderr, "iterate_chains: Error in command: %s\n", nft_ctx_get_error_buffer(ctx));
        // Alternative command for listing chains of a table
        snprintf(cmd, sizeof(cmd), "list table %s", table_name);
        if (nft_run_cmd_from_buffer(ctx, cmd) < 0) {
            fprintf(stderr, "iterate_chains: Error in command: %s\n", nft_ctx_get_error_buffer(ctx));
            return 0;
        }
    }

    // Get JSON output
    const char *json_str = nft_ctx_get_output_buffer(ctx);
    if (!json_str) {
        fprintf(stderr, "iterate_chains: Can't get command output\n");
        return 0;
    }

    // Apply JSON parser to extract chains
    parsed_json = json_tokener_parse(json_str);
    if (!parsed_json) {
        fprintf(stderr, "iterate_chains: JSON parser error\n");
        return 0;
    }

    // Get nftables object from JSON
    if (!json_object_object_get_ex(parsed_json, "nftables", &nftables)) {
        fprintf(stderr, "iterate_chains: 'nftables' object not found\n");
        json_object_put(parsed_json);
        return 0;
    }

    // Iterate chains with hook of type input
#ifdef DEBUG_NFTABLES
    printf("ITERATING CHAINS OF TABLE %s\n", table_name);
    printf("=====================================\n");
#endif
    for (size_t i = 0; i < json_object_array_length(nftables); i++) {
        obj = json_object_array_get_idx(nftables, i);

        // Is it a chain?
        if (json_object_object_get_ex(obj, "chain", &chain_obj)) {
            // Get its attributes
            chain_name = json_object_get_string(json_object_object_get(chain_obj, "name"));
            family = json_object_get_string(json_object_object_get(chain_obj, "family"));
            hook = json_object_get_string(json_object_object_get(chain_obj, "hook"));
            priority = json_object_get_string(json_object_object_get(chain_obj, "prio"));
            policy = json_object_get_string(json_object_object_get(chain_obj, "policy"));

            // Is a hook input chain?
            if (chain_name != NULL && family != NULL && hook != NULL && priority != NULL && policy != NULL) {
                if (!strcmp(family, "ip") && !strcmp(hook, "input")) {
#ifdef DEBUG_NFTABLES
                    printf("INPUT CHAIN: %s    family: %s   hook: %s   priority: %s    policy: %s\n", chain_name, family, hook, priority, policy);
#endif
                    // Add chain to list
                    el = (input_chain_t *) malloc(sizeof(input_chain_t));
                    if (el == NULL) {
                        json_object_put(parsed_json);
                        fprintf(stderr, "iterate_chains: Can't allocate memory for input_chain_t\n");
                        return 0;
                    }
                    el->priority = atoi(priority);
                    el->name = NULL;
                    insert_sorted_list(w_globvars.input_chains, el);
                    el->name = (char *) malloc(strlen(chain_name)+1);
                    if (el->name == NULL) {
                        json_object_put(parsed_json);
                        fprintf(stderr, "iterate_chains: Can't allocate memory for chain_name\n");
                        return 0;
                    }
                    strcpy(el->name, chain_name);
                    if (!strcmp(policy, "drop")) {
                        el->default_policy = DROP;
                    }
                    else {
                        if (!strcmp(policy, "accept")) {
                            el->default_policy = ACCEPT;
                        }
                        else {
                            json_object_put(parsed_json);
                            fprintf(stderr, "iterate_chains: Can't recognize default policy\n");
                            return 0;
                        }
                    }
                    // Iterate rules
                    if (!iterate_chain_rules(ctx, table_name, chain_name)) {
                        json_object_put(parsed_json);
                        return 0;
                    }

                }
            }

            // Is a customized chain?
            if (chain_name != NULL && family != NULL && hook == NULL) {
                if (!strcmp(family, "ip")) {
#ifdef DEBUG_NFTABLES
                    //printf("CUSTOMIZE CHAIN: %s    family: %s\n", chain_name, family);
#endif
                    // Iterate rules
                    if (!iterate_chain_rules(ctx, table_name, chain_name)) {
                        json_object_put(parsed_json);
                        return 0;
                    }
                }
            }
        }
    }
    json_object_put(parsed_json);
    return 1;
}

/*
Iterate and parse all rules in a nftables chain
PARAMS:     nftables context
            Table's name
            Chain's name
MODIFIES:   chains dictionary adding all rules of the chain (in a list which is the value's dict)
RETURN:     1 if all is ok
            0 if any error
*/
int iterate_chain_rules(struct nft_ctx *ctx, const char *table_name, const char *chain_name) {
    char cmd[256];
    char *cname;
    struct json_object *parsed_json;
    struct json_object *nftables;
    struct json_object *obj;
    struct json_object *rule_obj;
#ifdef DEBUG_NFTABLES
    const char *handle;
#endif
    struct json_object *expresions_obj;
    double_list l_chain = NULL;

    // Command for listing rules of a chain
    snprintf(cmd, sizeof(cmd), "list chain %s %s", table_name, chain_name);

    // Execute command and get its output
    if (nft_run_cmd_from_buffer(ctx, cmd) < 0) {
        fprintf(stderr, "iterate_chain_rules: Error in command: %s\n", nft_ctx_get_error_buffer(ctx));
        return 0;
    }

    // Get JSON output
    const char *json_str = nft_ctx_get_output_buffer(ctx);
    if (!json_str) {
        fprintf(stderr, "iterate_chain_rules: Can't get command output\n");
        return 0;
    }

    // Apply JSON parser to extract rules
   parsed_json = json_tokener_parse(json_str);
    if (!parsed_json) {
        fprintf(stderr, "iterate_chain_rules: JSON parser error\n");
        return 0;
    }

    // Get nftables object from JSON
    if (!json_object_object_get_ex(parsed_json, "nftables", &nftables)) {
        json_object_put(parsed_json);
        fprintf(stderr, "iterate_chain_rules: 'nftables' object not found\n");
        return 0;
    }

    // Create list to store the chain's rules
    init_double_list(&l_chain);
    // Create key for the dictionary
    cname = (char *)malloc(strlen(chain_name)+1);
    if (cname == NULL) {
        free(l_chain);
        json_object_put(parsed_json);
        fprintf(stderr, "iterate_chains: Can't allocate memory for cname\n");
        return 0;
    }
    strcpy(cname, chain_name);
    // Add new entry to chains dictionary
    insert_dict(w_globvars.chains, cname, l_chain);

    // Iterate rules
#ifdef DEBUG_NFTABLES
    printf("ITERATING RULES OF CHAIN %s\n", chain_name);
    printf("=====================================\n");
#endif
    for (size_t i = 0; i < json_object_array_length(nftables); i++) {
        obj = json_object_array_get_idx(nftables, i);

        // Is it a rule?
        if (json_object_object_get_ex(obj, "rule", &rule_obj)) {
            // Get its attributes
#ifdef DEBUG_NFTABLES
            handle = json_object_get_string(json_object_object_get(rule_obj, "handle"));
#endif
            expresions_obj = json_object_object_get(rule_obj, "expr");
            if (expresions_obj != NULL) {
                // Iterate its expresions
#ifdef DEBUG_NFTABLES
                printf("Regla %s\n", handle);
#endif
                if (!iterate_rule_expresions(l_chain, expresions_obj)) {
                    json_object_put(parsed_json);
                    return 0;
                }
            }
        }
    }

    json_object_put(parsed_json);
    return 1;
}

/*
Iterate and parse all expression in a nftables rule
PARAMS:     A list
            A rule
MODIFIES:   l_chain list adding the rule
RETURN:     1 if all is ok
            0 if any error
*/
int iterate_rule_expresions(double_list l_chain, json_object *expresions_obj) {
    const char *s_val;
    rule_t *rule;
    struct json_object *expr_obj;
    struct json_object *action_obj;
    struct json_object *dest_chain_obj;
    int key_count = 0;
    int action;

    // Check rule's action
    action_obj = json_object_array_get_idx(expresions_obj, json_object_array_length(expresions_obj)-1);
    // Is it a valid action ?
    if (action_obj == NULL) {
        fprintf(stderr, "iterate_rule_expresions: Error while getting action object\n");
        return 0;
    }
    json_object_object_foreach(action_obj, key, val) {
        key_count++;
    }
    if (key_count != 1) {
        fprintf(stderr, "iterate_rule_expresions: Multiple actions in rule\n");
        return 0;
    }

    // Get rule's action
    if (!strcmp(key, "drop")) {
        action = DROP;
    }
    else {
        if (!strcmp(key, "accept")) {
            action = ACCEPT;
        }
        else {
            if (!strcmp(key, "jump")) {
                action = JUMP;
                dest_chain_obj = val;
            }
            else {
                if (!strcmp(key, "goto")) {
                    action = GOTO;
                    dest_chain_obj = val;
                }
                else {
                    // Jump over this rule
                    return 1;
                }
            }
        }
    }
    // A new rule
    rule = (rule_t *) malloc(sizeof(rule_t));
    if (rule == NULL) {
        fprintf(stderr, "iterate_rule_expresions: Can't allocalte memory for rule\n");
        return 0;
    }
    rule->action = action;
    rule->ifname = NULL;
    rule->ofname = NULL;
    rule->proto = NULL;
    rule->src_address = NULL;
    rule->dst_address = NULL;
    rule->src_ports = NULL;
    rule->dst_ports = NULL;
    rule->ct = NULL;
    rule->dest_chain = NULL;
    // Insert rule in list
    insert_tail_double_list(l_chain, rule);

    // Is it a jump, goto action?
    if (rule->action == JUMP || rule->action == GOTO) {
        // Get destination chain
        key_count = 0;
        json_object_object_foreach(dest_chain_obj, key, val) {
            key_count++;
        }
        if (key_count != 1) {
            fprintf(stderr, "iterate_rule_expresions: jump/goto action: multiple targets are invalid\n");
            return 0;
        }
        if (strcmp(key, "target")) {
            fprintf(stderr, "iterate_rule_expresions: jump/goto action: 'target' word expected in key value\n");
            return 0;
        }
        s_val = json_object_get_string(val);
        rule->dest_chain = (char *) malloc(strlen(s_val)+1);
        if (rule->dest_chain == NULL) {
            fprintf(stderr, "iterate_rule_expresions: Can't allocalte memory for rule->dest_chain\n");
            return 0;          
        }
        strcpy(rule->dest_chain, s_val);
    }

    // Iterate expresions (except last expression which is the action already processed)
#ifdef DEBUG_NFTABLES
    printf("ITERATING EXPRESSIONS OF RULE...\n");
#endif
    for (size_t i = 0; i < json_object_array_length(expresions_obj)-1; i++) {
        expr_obj = json_object_array_get_idx(expresions_obj, i);
        json_object_object_foreach(expr_obj, key, val) {
#ifdef DEBUG_NFTABLES
            printf("CURRENT EXPRESSION: Key: %s   Value %s\n", key, json_object_get_string(val));
#endif
            // Check if expression is a match one
            if (!strcmp(key, "match")) {
                if (!parse_match(rule, val)) {
                    return 0;
                }
            }
            else {
                if (!strcmp(key, "log")) {
                    continue;
                }
                else {
                    // Unknown expression --> Error
                    fprintf(stderr, "iterate_rule_expresions: Unknown expression in rule %s\n", json_object_get_string(expr_obj));
                    return 0;
                }
            }
        }
    }
    return 1;
}


/*
Parse a match expression
PARAMS:     A rule
            A match expression
RETURN:     1 if all is ok
            0 if any error
*/
int parse_match(rule_t *rule, struct json_object *m_obj) {
    int count;
    const char *s_op_obj;
    struct json_object *op_obj = NULL, *left_obj = NULL, *right_obj = NULL;
    expr_t *expr;

#ifdef DEBUG_NFTABLES
    printf("Parsing match expression...\n");
#endif

    // Try to get operator, left op and right op
    json_object_object_foreach(m_obj, key, val) {
        if (!strcmp(key, "op")) {
            op_obj = val;
        }
        if (!strcmp(key, "left")) {
            left_obj = val;
        }
        if (!strcmp(key, "right")) {
            right_obj = val;
        }
    }

    // Check if all is valid
    if (op_obj == NULL || left_obj == NULL || right_obj == NULL) {
        fprintf(stderr, "parse_match: Can't get the tree parts of expression.\n");
        return 0;
    }

#ifdef DEBUG_NFTABLES
    printf("Operator: %s\n", json_object_get_string(op_obj));
    printf("Left: %s\n", json_object_get_string(left_obj));
    printf("Right: %s\n", json_object_get_string(right_obj));
#endif

    // New expression in rule
    expr = (expr_t *) malloc(sizeof(expr_t));
    if (expr == NULL) {
        fprintf(stderr, "parse_match: Can't allocalte memory for expression\n");
        return 0;
    }
    expr->proto = ANY;
    expr->values = NULL;

    // Process operator
    s_op_obj = json_object_get_string(op_obj);
    if (!strcmp(s_op_obj, "==") || !strcmp(s_op_obj, "in")) {
        expr->operator = EQ_OP;
    }
    else {
        if (!strcmp(s_op_obj, "!=")) {
            expr->operator = NE_OP;
        }
        else {
            if (!strcmp(s_op_obj, "<")) {
                expr->operator = LT_OP;
            }
            else {
                if (!strcmp(s_op_obj, ">")) {
                    expr->operator = GT_OP;
                }
                else {
                    if (!strcmp(s_op_obj, "<=")) {
                        expr->operator = LE_OP;
                    }
                    else {
                        if (!strcmp(s_op_obj, ">=")) {
                            expr->operator = GE_OP;
                        }
                        else {
                            // Invalid operator
                            free(expr);
                            fprintf(stderr, "parse_match: Invalid operator in expresssion\n");
                            return 0;
                        }
                    }
                }
            }
        }
    }

    // PROCESS LEFT PART OF THE RULE
    // is a meta expression?
    count = 0;
    json_object_object_foreach(left_obj, subkey, subval) {
        count++;
    }
    if (count != 1) {
        free(expr);
        fprintf(stderr, "parse_match: Multiple values checking left expression %s\n", json_object_get_string(left_obj));
        return 0;
    }
    if (!strcmp(subkey, "meta")) {
        return left_meta(rule, expr, subval, right_obj);
    }
    else {
        if (!strcmp(subkey, "payload")) {
            return left_payload(rule, expr, subval, right_obj);
        }
        else {
            if (!strcmp(subkey, "ct")) {
                return left_ct(rule, expr, subval, right_obj);
            }
            else {
                fprintf(stderr, "parse_match: Unknown key %s in expression\n", subkey);
                free(expr);
                return 0;
            }
        }
    }
}

/*
Parse a meta expression
PARAMS:     A rule
            An expression to store this one
            The left part of the meta expression
            The right part of the meta expression
RETURN:     1 if it is a meta expression and parse is ok
            0 if an error
*/
int left_meta(rule_t *rule, expr_t *expr, struct json_object *left_obj, struct json_object *right_obj) {
    const char *s_left_obj, *s_val;
    int count = 0;

    s_left_obj = json_object_get_string(left_obj);
#ifdef DEBUG_NFTABLES
    printf("meta key found: %s\n", s_left_obj);
#endif
    // Meta key found. Process subexpressions of meta
    json_object_object_foreach(left_obj, key, val) {
        count++;
    }
    if (count != 1) {
        fprintf(stderr, "left_meta: Multiple values in meta expression\n");
        return 0;
    }
    if (strcmp(key, "key")) {
        fprintf(stderr, "left_meta: Expected word 'key' in the key value of %s\n", s_left_obj);
        return 0;
    }
    s_val = json_object_get_string(val);

    // Process right part of the expression if the value is iifname
    if (!strcmp(s_val, "iifname")) {
        return right_ifname(rule, expr, right_obj, 0);
    }
    else {
        // Process right part of the expression if the value is oifname
        if (!strcmp(s_val, "oifname")) {
            return right_ifname(rule, expr, right_obj, 1);
        }
        else {
            // Process right part of the expression if the value is saddr
            if (!strcmp(s_val, "saddr")) {
                return right_addr(rule, expr, right_obj, 0);
            }
            else {
                // Process right part of the expression if the value is daddr
                if (!strcmp(s_val, "daddr")) {
                    return right_addr(rule, expr, right_obj, 1);
                }
                else {
                    fprintf(stderr, "left_meta: Unknown key in meta expression %s\n", s_val);
                    return 0;
                }
            }
        }
    }
}

/*
Parse a payload expression
PARAMS:     A rule
            An expression to store this one
            The left part of the payload expression
            The right part of the payload expression
RETURN:     1 if it is a payload expression and parse is ok
            0 if an error
*/
int left_payload(rule_t *rule, expr_t *expr, struct json_object *left_obj, struct json_object *right_obj) {
    const char *s_val;

#ifdef DEBUG_NFTABLES
    printf("payload key found: %s\n", json_object_get_string(left_obj));
#endif
    json_object_object_foreach(left_obj, key, val) {
        s_val = json_object_get_string(val);
        if (!strcmp(key, "protocol")) {
            // Store the local protocol of this subexpression
            if (!right_local_protocol(expr, val)) {
                return 0;
            }
        }
        else {
            if (!strcmp(key, "field")) {
                if (!strcmp(s_val, "protocol")) {
                    return right_protocol(rule, expr, right_obj);
                }
                else {
                    if (!strcmp(s_val, "saddr")) {
                        return right_addr(rule, expr, right_obj, 0);
                    }
                    else {
                        if (!strcmp(s_val, "daddr")) {
                            return right_addr(rule, expr, right_obj, 1);
                        }
                        else {
                            if (!strcmp(s_val, "sport")) {
                                return right_port(rule, expr, right_obj, 0);
                            }
                            else {
                                if (!strcmp(s_val, "dport")) {
                                    return right_port(rule, expr, right_obj, 1);
                                }
                                else {
                                    fprintf(stderr, "left_payload: field %s not supported\n", s_val);
                                    return 0;
                                }
                            }
                        }
                    }
                }
            }
            else {
                fprintf(stderr, "left_payload: key %s not supported\n", key);
                return 0;
            }
        }
    }
    fprintf(stderr, "left_payload: valid key not found\n");
    return 0;
}

/*
Parse a ct expression
PARAMS:     A rule
            An expression to store this one
            The left part of the meta expression
            The right part of the meta expression
RETURN:     1 if it is a meta expression and parse is ok
            0 if an error
*/
int left_ct(rule_t *rule, expr_t *expr, struct json_object *left_obj, struct json_object *right_obj) {
    const char *s_left_obj, *s_val;
    int count = 0;

    s_left_obj = json_object_get_string(left_obj);
#ifdef DEBUG_NFTABLES
    printf("ct key found: %s\n", s_left_obj);
#endif
    // ct key found. Process subexpressions of ct
    json_object_object_foreach(left_obj, key, val) {
        count++;
    }
    if (count != 1) {
        fprintf(stderr, "left_ct: Multiple values in meta expression\n");
        return 0;
    }
    if (strcmp(key, "key")) {
        fprintf(stderr, "left_ct: Expected word 'key' in the key value of %s\n", s_left_obj);
        return 0;
    }
    s_val = json_object_get_string(val);

    // Process right part of the expression if the value is state
    if (!strcmp(s_val, "state")) {
        return right_ct_state(rule, expr, right_obj);
    }
    else {
        fprintf(stderr, "left_ct: Unknown key in ct expression %s\n", s_val);
        return 0;
    }
}

/*
Insert a device name in a expression
PARAMS:     An expression to store the device
            The device name
MODIFIES:   expr to store the device name
RETURN:     1 if all is ok
            0 if an error
*/
int store_devname(expr_t *expr, const char *dev_name) {
    char *name;

    name = (char *) malloc(strlen(dev_name)+1);
    if (name == NULL) {
        fprintf(stderr, "store_devname: Can't allocate memory for dev name\n");
        return 0;
    }
    strcpy(name, dev_name);
    insert_tail_double_list(expr->values, name);
#ifdef DEBUG_NFTABLES
    printf("%s inserted in expression\n", name);
#endif
    return 1;
}

/*
Parse a iifname/oifname expression
PARAMS:     A rule
            An expression to store this one
            The right part of the expression
            0 if it is a iifname expressión or 1 if it is a oifname one
MODIFIES:   expr to store the expression
            rule to add this expression
RETURN:     1 if all is ok
            0 if an error
*/
int right_ifname(rule_t *rule, expr_t *expr, struct json_object *right_obj, int dev_type) {
    const char *s_val_set, *s_right_obj;
    struct json_object *val_set;
    int count = 0;

    if (dev_type == 0) {
#ifdef DEBUG_NFTABLES
        printf("iifname expression found.\n");
#endif
        // Create list for iifname expressions (if not yet created)
        if (rule->ifname == NULL) {
            init_double_list(&rule->ifname);
        }
        // Add expression to rule
        insert_tail_double_list(rule->ifname, expr);
    }
    else {
#ifdef DEBUG_NFTABLES
        printf("oifname expression found.\n");
#endif
        // Create list for oifname expressions (if not yet created)
        if (rule->ofname == NULL) {
            init_double_list(&rule->ofname);
        }
        // Add expression to rule
        insert_tail_double_list(rule->ofname, expr);
    }
    // Create list for values (right part of the rule)
    init_double_list(&expr->values);

    // Is it a set?
    if (json_object_get_type(right_obj) == json_type_object) {
#ifdef DEBUG_NFTABLES
        printf("Right part is a set of values %s\n", json_object_get_string(right_obj));
#endif
        json_object_object_foreach(right_obj, key, set) {
            count++;
        }
        if (count != 1) {
            fprintf(stderr, "right_iifname: Multiple values checking set of values\n");
            return 0;
        }
        if (strcmp(key, "set")) {
            fprintf(stderr, "right_iifname: Word 'set' expected\n");
            return 0;
        }
        // Iterate set
        for (size_t i = 0; i < json_object_array_length(set); i++) {
            val_set = json_object_array_get_idx(set, i);
            s_val_set = json_object_get_string(val_set);
            // Store current value in expression
            if (!store_devname(expr, s_val_set)) {
                return 0;
            }
        }
        return 1;
    }
    else {
        s_right_obj = json_object_get_string(right_obj);
#ifdef DEBUG_NFTABLES
        printf("Right part is a single value: %s\n", s_right_obj);
#endif
        // Store value in expression
        return store_devname(expr, s_right_obj);
    }
}

/*
Insert a global protocol in a expression
PARAMS:     An expression to store the device
            The protocol (int text format: tcp, udp, icmp)
MODIFIES:   expr to store the protocol
RETURN:     1 if all is ok
            0 if an error
*/
int store_protocol(expr_t *expr, const char *proto) {
    uint8_t aux;
    uint8_t *protocol;

    // Check if proto is valid
    if (!strcmp(proto, "tcp")) {
        aux = TCP;
    }
    else {
        if (!strcmp(proto, "udp")) {
            aux = UDP;
        }
        else {
            if (!strcmp(proto, "icmp")) {
                aux = ICMP;
            }
            else {
                if (!strcmp(proto, "th")) {
                    aux = TH;
                }
                else {
                    aux = UNSUPPORTED;
                }
            }
        }
    }

    protocol = (uint8_t *) malloc(sizeof(uint8_t));
    if (protocol == NULL) {
        fprintf(stderr, "store_protocol: Can't allocate memory for protocol\n");
        return 0;
    }
    *protocol = aux;
    insert_tail_double_list(expr->values, protocol);
#ifdef DEBUG_NFTABLES
    printf("protocol %0d inserted in expression\n", *protocol);
#endif
    return 1;
}

/*
Parse a global protocol expression
PARAMS:     A rule
            An expression to store this one
            The right part of the expression
MODIFIES:   expr to store the expression
            rule to add this expression
RETURN:     1 if all is ok
            0 if an error
*/
int right_protocol(rule_t *rule, expr_t *expr, struct json_object *right_obj) {
    const char *s_val_set, *s_right_obj;
    struct json_object *val_set;
    int count = 0;

#ifdef DEBUG_NFTABLES
    printf("Global protocol expression found.\n");
#endif
    // Create list for protocol expressions (if not yet created)
    if (rule->proto == NULL) {
        init_double_list(&rule->proto);
    }
    // Add expression to rule
    insert_tail_double_list(rule->proto, expr);
    // Create list for values (right part of the rule)
    init_double_list(&expr->values);

    // Is it a set?
    if (json_object_get_type(right_obj) == json_type_object) {
#ifdef DEBUG_NFTABLES
        printf("Right part is a set of values %s\n", json_object_get_string(right_obj));
#endif
        json_object_object_foreach(right_obj, key, set) {
            count++;
        }
        if (count != 1) {
            fprintf(stderr, "right_protocol: Multiple values checking set of values\n");
            return 0;
        }
        if (strcmp(key, "set")) {
            fprintf(stderr, "right_protocol: Word 'set' expected\n");
            return 0;
        }
        // Iterate set
        for (size_t i = 0; i < json_object_array_length(set); i++) {
            val_set = json_object_array_get_idx(set, i);
            s_val_set = json_object_get_string(val_set);
            if (!store_protocol(expr, s_val_set)) {
                return 0;
            }
        }
        return 1;
    }
    else {
        s_right_obj = json_object_get_string(right_obj);
#ifdef DEBUG_NFTABLES
        printf("Right part is a single value: %s\n", s_right_obj);
#endif
        // Store value in expression
        return store_protocol(expr, s_right_obj);
    }
}

/*
Parse local protocol of expression
PARAMS:     An expression to store local protocol
            The protocol (JSON object)
MODIFIES:   expr to store the local protocol
RETURN:     1 if all is ok
            0 if an error
*/
int right_local_protocol(expr_t *expr, struct json_object *proto) {
    const char *s_proto = json_object_get_string(proto);

#ifdef DEBUG_NFTABLES
    printf("Local protocol expression found.\n");
#endif
    if (!strcmp(s_proto, "ip") || !strcmp(s_proto, "inet")) {
        expr->proto = ANY;
    }
    else {
        if (!strcmp(s_proto, "icmp")) {
            expr->proto = ICMP;
        }
        else {
            if (!strcmp(s_proto, "tcp")) {
                expr->proto = TCP;
            }
            else {
                if (!strcmp(s_proto, "udp")) {
                    expr->proto = UDP;
                }
                else {
                    if (!strcmp(s_proto, "th")) {
                        expr->proto = TH;
                    }
                    else {
                        fprintf(stderr, "right_local_protocol: Protocol %s not supported\n", s_proto);
                        return 0;
                    }
                }
            }
        }
    }
#ifdef DEBUG_NFTABLES
    printf("Protocol %0d stored in expression.\n", expr->proto);
#endif
    return 1;
}

/*
Insert an address or range of addresses in a expression
PARAMS:     An expression to store the address
            The address (in text format x.x.x.x) or the lower address (if a range address)
            The len (number of bits for mask address)
            The second address (in text format x.x.x.x) (the upper address ) of range.
            Or NULL if it is not a range
            The len (number of bits for mask address) or 0 if it is not a range
MODIFIES:   expr to store the address
RETURN:     1 if all is ok
            0 if an error
*/
int store_address(expr_t *expr, const char *ip_address, uint8_t len, const char *ip_address2, uint8_t len2) {
    address_mask_t *value;


    value = (address_mask_t *) malloc(sizeof(address_mask_t));
    if (value == NULL) {
        fprintf(stderr, "store_address: Can't allocate memory for address\n");
        return 0;
    }
    inet_pton(AF_INET, ip_address, &value->address);
    value->mask = len;
    if (ip_address2 != NULL) {
        inet_pton(AF_INET, ip_address2, &value->address2);
        value->mask2 = len2;
#ifdef DEBUG_NFTABLES
        printf("%s/%0u - %s/%0u inserted in expression\n", ip_address, len, ip_address2, len2);
#endif
    }
    else {
        value->mask2 = 0;
#ifdef DEBUG_NFTABLES
        printf("%s/%0u inserted in expression\n", ip_address, len);
#endif
    }
    insert_tail_double_list(expr->values, value);

    return 1;
}

/*
Parse a saddr/daddr single value
PARAMS:     An expression to store this address
            The adress in JSON format (either single value, range or prefix)
MODIFIES:   expr to store the expression
RETURN:     1 if all is ok
            0 if an error
*/
int right_addr_single_value(expr_t *expr, struct json_object *value_obj) {
    const char *lower_range, *upper_range;
    const char *s_address, *s_len;
    int count = 0;

    // Is it a single address
    if (json_object_get_type(value_obj) != json_type_object) {
#ifdef DEBUG_NFTABLES
        printf("Parsing a single address value: %s\n", json_object_get_string(value_obj));
#endif
        // It's a single address
        return store_address(expr, json_object_get_string(value_obj), 32, NULL, 0);
    }

    // Is it a prefix or range ?
    json_object_object_foreach(value_obj, key, val) {
        count++;
    }
    if (count != 1) {
        fprintf(stderr, "right_addr_single_value: Multiple values checking expression\n");
        return 0;
    }
    if (!strcmp(key, "prefix")) {
#ifdef DEBUG_NFTABLES
        printf("Parsing a prefix address value: %s\n", json_object_get_string(value_obj));
#endif
        // It's a prefix address
        json_object_object_foreach(val, subkey, subval) {
            if (!strcmp(subkey, "addr")) {
                s_address = json_object_get_string(subval);
            }
            else {
                if (!strcmp(subkey, "len")) {
                    s_len = json_object_get_string(subval);
                }
                else {
                    fprintf(stderr, "right_addr_single_value: Unknown key %s in prefix address\n", subkey);
                    return 0;                    
                }
            }
        }
        return store_address(expr, s_address, (uint8_t) atoi(s_len), NULL, 0);
    }
    else {
        if (!strcmp(key, "range")) {
#ifdef DEBUG_NFTABLES
        printf("Parsing a range address value: %s\n", json_object_get_string(value_obj));
#endif
            // It's a range address
            lower_range = json_object_get_string(json_object_array_get_idx(val, 0));
            upper_range = json_object_get_string(json_object_array_get_idx(val, 1));
            return store_address(expr, lower_range, 32, upper_range, 32);
        }
        else {
            // Unknown
            fprintf(stderr, "right_addr_single_value: %s unsupported address type\n", key);
            return 0;
        }
    }
}

/*
Parse a saddr/daddr expression
PARAMS:     A rule
            An expression to store this one
            The right part of the expression
            0 if it is a saddr expressión or 1 if it is a daddr one
MODIFIES:   expr to store the expression
            rule to add this expression
RETURN:     1 if all is ok
            0 if an error
*/
int right_addr(rule_t *rule, expr_t *expr, struct json_object *right_obj, int dest) {
    struct json_object *val_set;
    int count = 0;

    if (dest == 0) {
#ifdef DEBUG_NFTABLES
        printf("saddr expression found.\n");
#endif
        // Create list for saddr expressions (if not yet created)
        if (rule->src_address == NULL) {
            init_double_list(&rule->src_address);
        }
        // Add expression to rule
        insert_tail_double_list(rule->src_address, expr);
    }
    else {
#ifdef DEBUG_NFTABLES
        printf("daddr expression found.\n");
#endif
        // Create list for daddr expressions (if not yet created)
        if (rule->dst_address == NULL) {
            init_double_list(&rule->dst_address);
        }
        // Add expression to rule
        insert_tail_double_list(rule->dst_address, expr);
    }
    // Create list for values (right part of the rule)
    init_double_list(&expr->values);

    // Is it a set?
    if (json_object_get_type(right_obj) == json_type_object) {
        json_object_object_foreach(right_obj, key, set) {
            count++;
        }
        if (count != 1) {
            fprintf(stderr, "right_addr: Multiple values checking set of values\n");
            return 0;
        }
        if (!strcmp(key, "set")) {
#ifdef DEBUG_NFTABLES
            printf("Right part is a set of values %s\n", json_object_get_string(right_obj));
#endif
            // Iterate set
            for (size_t i = 0; i < json_object_array_length(set); i++) {
                val_set = json_object_array_get_idx(set, i);
                // Store current value in expression
                if (!right_addr_single_value(expr, val_set)) {
                    return 0;
                }
            }
            return 1;
        }
    }

    // It is not a set
#ifdef DEBUG_NFTABLES
    printf("Right part is a single value: %s\n", json_object_get_string(right_obj));
#endif
        // Store value in expression
    return right_addr_single_value(expr, right_obj);
}

/*
Insert a port or range of ports in a expression
PARAMS:     An expression to store the port
            The port (in text format) or the lower port (if a range of ports)
            The second port (in text format) (the upper port) of range.
            Or NULL if it is not a range
MODIFIES:   expr to store the port (or range)
RETURN:     1 if all is ok
            0 if an error
*/
int store_port(expr_t *expr, const char *port, const char *port2) {
    port_t *value;

    value = (port_t *) malloc(sizeof(port_t));
    if (value == NULL) {
        fprintf(stderr, "store_port: Can't allocate memory for port\n");
        return 0;
    }
    value->port = (uint16_t) atoi(port);
    if (port2 != NULL) {
        value->port2 = (uint16_t) atoi(port2);
#ifdef DEBUG_NFTABLES
        printf("%0u - %0u inserted in expression\n", value->port, value->port2);
#endif
    }
    else {
        value->port2 = 0;
#ifdef DEBUG_NFTABLES
        printf("%0u inserted in expression\n", value->port);
#endif
    }
    insert_tail_double_list(expr->values, value);

    return 1;
}

/*
Parse a sport/dport single value
PARAMS:     An expression to store this port
            The port in JSON format (either single value or range)
MODIFIES:   expr to store the expression
RETURN:     1 if all is ok
            0 if an error
*/
int right_port_single_value(expr_t *expr, struct json_object *value_obj) {
    const char *lower_range, *upper_range;
    int count = 0;

    // Is it a single port?
    if (json_object_get_type(value_obj) != json_type_object) {
#ifdef DEBUG_NFTABLES
        printf("Parsing a single port value: %s\n", json_object_get_string(value_obj));
#endif
        // It's a single port
        return store_port(expr, json_object_get_string(value_obj), NULL);
    }

    // Is it a range ?
    json_object_object_foreach(value_obj, key, val) {
        count++;
    }
    if (count != 1) {
        fprintf(stderr, "right_port_single_value: Multiple values checking expression\n");
        return 0;
    }
    if (!strcmp(key, "range")) {
#ifdef DEBUG_NFTABLES
    printf("Parsing a range of ports: %s\n", json_object_get_string(value_obj));
#endif
        // It's a range of ports
        lower_range = json_object_get_string(json_object_array_get_idx(val, 0));
        upper_range = json_object_get_string(json_object_array_get_idx(val, 1));
        return store_port(expr, lower_range, upper_range);
    }
    else {
        // Unknown
        fprintf(stderr, "right_port_single_value: %s unsupported address type\n", key);
        return 0;
    }
}

/*
Parse a sport/dport expression
PARAMS:     A rule
            An expression to store this one
            The right part of the expression
            0 if it is a sport expressión or 1 if it is a dport one
MODIFIES:   expr to store the expression
            rule to add this expression
RETURN:     1 if all is ok
            0 if an error
*/
int right_port(rule_t *rule, expr_t *expr, struct json_object *right_obj, int dest) {
    struct json_object *val_set;
    int count = 0;

    if (dest == 0) {
#ifdef DEBUG_NFTABLES
        printf("sport expression found.\n");
#endif
        // Create list for sportg expressions (if not yet created)
        if (rule->src_ports == NULL) {
            init_double_list(&rule->src_ports);
        }
        // Add expression to rule
        insert_tail_double_list(rule->src_ports, expr);
    }
    else {
#ifdef DEBUG_NFTABLES
        printf("dport expression found.\n");
#endif
        // Create list for dport expressions (if not yet created)
        if (rule->dst_ports == NULL) {
            init_double_list(&rule->dst_ports);
        }
        // Add expression to rule
        insert_tail_double_list(rule->dst_ports, expr);
    }
    // Create list for values (right part of the rule)
    init_double_list(&expr->values);

    // Is it a set?
    if (json_object_get_type(right_obj) == json_type_object) {
        json_object_object_foreach(right_obj, key, set) {
            count++;
        }
        if (count != 1) {
            fprintf(stderr, "right_port: Multiple values checking set of values\n");
            return 0;
        }
        if (!strcmp(key, "set")) {
#ifdef DEBUG_NFTABLES
            printf("Right part is a set of values %s\n", json_object_get_string(right_obj));
#endif
            // Iterate set
            for (size_t i = 0; i < json_object_array_length(set); i++) {
                val_set = json_object_array_get_idx(set, i);
                // Store current value in expression
                if (!right_port_single_value(expr, val_set)) {
                    return 0;
                }
            }
            return 1;
        }
    }

    // It is not a set
#ifdef DEBUG_NFTABLES
    printf("Right part is a single value: %s\n", json_object_get_string(right_obj));
#endif
        // Store value in expression
    return right_port_single_value(expr, right_obj);
}

/*
Insert a ct state in a expression
PARAMS:     An expression to store the device
            The ct state (int text format: established, related, invalid)
MODIFIES:   expr to store the ct state
RETURN:     1 if all is ok
            0 if an error
*/
int store_ct_state(expr_t *expr, const char *state) {
    uint8_t aux;
    uint8_t *ct_state;

    // Check if proto is valid
    if (!strcmp(state, "established")) {
        aux = ESTABLISHED;
    }
    else {
        if (!strcmp(state, "related")) {
            aux = RELATED;
        }
        else {
            if (!strcmp(state, "invalid")) {
                aux = INVALID;
            }
            else {
                fprintf(stderr, "store_ct_state: State %s not supported\n", state);
                return 0;
            }
        }
    }

    ct_state = (uint8_t *) malloc(sizeof(uint8_t));
    if (ct_state == NULL) {
        fprintf(stderr, "store_ct_state: Can't allocate memory for ct state\n");
        return 0;
    }
    *ct_state = aux;
    insert_tail_double_list(expr->values, ct_state);
#ifdef DEBUG_NFTABLES
    printf("CT State %0d inserted in expression\n", *ct_state);
#endif
    return 1;
}

/*
Parse a CT state expression
PARAMS:     A rule
            An expression to store this one
            The right part of the expression
MODIFIES:   expr to store the expression
            rule to add this expression
RETURN:     1 if all is ok
            0 if an error
*/
int right_ct_state(rule_t *rule, expr_t *expr, struct json_object *right_obj) {
    const char *s_val_set, *s_right_obj;
    struct json_object *val_set;
    int count = 0;

#ifdef DEBUG_NFTABLES
    printf("CT state expression found.\n");
#endif
    // Create list for ct state expressions (if not yet created)
    if (rule->ct == NULL) {
        init_double_list(&rule->ct);
    }
    // Add expression to rule
    insert_tail_double_list(rule->ct, expr);
    // Create list for values (right part of the rule)
    init_double_list(&expr->values);

    // Is it a set?
    if (json_object_get_type(right_obj) == json_type_object) {
#ifdef DEBUG_NFTABLES
        printf("Right part is a set of values %s\n", json_object_get_string(right_obj));
#endif
        json_object_object_foreach(right_obj, key, set) {
            count++;
        }
        if (count != 1) {
            fprintf(stderr, "right_ct_state: Multiple values checking set of values\n");
            return 0;
        }
        if (strcmp(key, "set")) {
            fprintf(stderr, "right_ct_state: Word 'set' expected\n");
            return 0;
        }
        // Iterate set
        for (size_t i = 0; i < json_object_array_length(set); i++) {
            val_set = json_object_array_get_idx(set, i);
            s_val_set = json_object_get_string(val_set);
            if (!store_ct_state(expr, s_val_set)) {
                return 0;
            }
        }
        return 1;
    }
    else {
        s_right_obj = json_object_get_string(right_obj);
#ifdef DEBUG_NFTABLES
        printf("Right part is a single value: %s\n", s_right_obj);
#endif
        // Store value in expression
        return store_ct_state(expr, s_right_obj);
    }
}


#endif

