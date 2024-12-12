#include <string.h>
#include <stdlib.h>

#include <nftables.h>
#include <NFTablesParser.h>
#include <NFTablesEvaluator.h>

#if NFTABLES_ACTIVE == 1

// EXTERNAL Global vars
extern struct write_global_vars w_globvars;

// PRIVATE FUNCTION PROTOTYPES RELATIVE TO FREE MEMORY OF LISTS AND DICTIONARIES

// Function to free ALL NFTABLES INFO AND STRUCTURAL DATA
void flush_nftables();
// Function to free an element of the input chains list
void free_element_input_chain_list(void *el, void *param);
// Function to free an expression
void free_expression(void *expression, void *param);
// Function to free a rule of a chain in the chains dictionary
void free_rule_chain_dictionary(void *el, void *param);
// Function to free all rules of a chain in the chains dictionary
void free_rules_chain_dictionary(struct value_dict *el, void *param);

// PRIVATE FUNCTION PROTOTYPES RELATIVE TO LISTS AND DICTIONARIES

// Function to compare for sorting two elements of the input chains list
int compare_input_chains(void *val1, void *val2);
// Function to compares for sorting two keys of type char *
int compare_keys_string(void *val1, void *val2);
// Function to compare for sorting two elements of the dictionary
int compare_string(struct value_dict *val1, struct value_dict *val2);


void initXtables() {
    // Removes old info
    flush_nftables();

    // List with the names of input hook chains (in priority order)
    w_globvars.input_chains = NULL;
    init_sorted_list(&w_globvars.input_chains, compare_input_chains);
    if (w_globvars.input_chains == NULL) {
        fprintf(stderr, "initXtables: CAN NOT CREATE INPUT CHAINS LIST\n");
        return;
    }

    // Dictionary with no hook chains
    w_globvars.chains = NULL;
    init_dict(&w_globvars.chains, compare_string, compare_keys_string);
    if (w_globvars.chains == NULL) {
        fprintf(stderr, "initXtables: CAN NOT CREATE CHAINS DICTIONARY\n");
        return;
    }

    // Dictionary with sets
    w_globvars.sets = NULL;
    init_dict(&w_globvars.sets, compare_string, compare_keys_string);
    if (w_globvars.sets == NULL) {
        fprintf(stderr, "initXtables: CAN NOT CREATE SETS DICTIONARY\n");
        return;
    }

    // Iterate tables and chains
    if (!iterate_tables_and_chains()) {
        fprintf(stderr, "initXtables: CAN NOT GET NFTABLES RULES\n");
        flush_nftables();
        return;
    }

#ifdef DEBUG_NFTABLES
    // Print all nftables rules
    printf("\n\nLISTADO DE REGLAS NFTABLES\n");
    printf("==============================\n\n");
    for_each_dict(chains, print_list_rules_chain_dictionary, NULL);
    printf("\n\n");
#endif
}

int actionIncoming(char *net_device, uint8_t proto, in_addr_t s_address, uint16_t sport, in_addr_t d_address, uint16_t dport, 
                       uint8_t flags_type, uint8_t code, int new_connection) {
    // By now, icmp protocol is not supported
    if (proto == IPPROTO_ICMP) {
        return 0;
    }
    if (new_connection) {
        return evaluate_packet(proto, 0, net_device, NULL, s_address, d_address, sport, dport);
    }
    else {
        return evaluate_packet(proto, ESTABLISHED, net_device, NULL, s_address, d_address, sport, dport);
    }
}

void flush_nftables() {
    if (w_globvars.input_chains != NULL) {
#ifdef DEBUG_NFTABLES
        printf("Clearing input chains list...\n");
#endif
        clear_all_sorted_list(w_globvars.input_chains, 1, free_element_input_chain_list, NULL);
        free(w_globvars.input_chains);
#ifdef DEBUG_NFTABLES
        printf("DONE!\n");
#endif
    }
    if (w_globvars.chains != NULL) {
#ifdef DEBUG_NFTABLES
        printf("Clearing chains dictionary...\n");
#endif
        clear_all_dict(w_globvars.chains, 1, 1, free_rules_chain_dictionary, NULL);
        free(w_globvars.chains);
#ifdef DEBUG_NFTABLES
        printf("DONE!\n");
#endif
    }
}

#ifdef DEBUG_NFTABLES
// PRIVATE FUNCTION PROTOTYPES RELATIVE TO PRINT LISTS AND DICTIONARIES INFO
// Function to print rules of a chain
void print_rules_chain(void *el, void *param);
// Function to print list of rules of the chains dictionary
void print_list_rules_chain_dictionary(struct value_dict *el, void *param);
#endif

// Function to free an element of the input chains list
void free_element_input_chain_list(void *el, void *param) {
    input_chain_t *val = (input_chain_t *)el;

    if (val->name != NULL) {
        free(val->name);
    }
}

// Function to free an expression
void free_expression(void *expression, void *param) {
    expr_t *exp = (expr_t *)expression;

    if (exp->set_name != NULL) {
        free(exp->set_name);
    }
    if (exp->values != NULL) {
        clear_all_double_list(exp->values, 1, NULL, NULL);
        free(exp->values);
    }
}

// Function to free a rule of a chain in the chains dictionary
void free_rule_chain_dictionary(void *el, void *param) {
#ifdef DEBUG_NFTABLES
    char *chain_name = (char *) param;
#endif
    rule_t *rule = (rule_t *)el;

#ifdef DEBUG_NFTABLES
    printf("Clearing rule of chain %s...\n", chain_name);
#endif

    if (rule->ifname != NULL) {
        clear_all_double_list(rule->ifname, 1 , free_expression, NULL);
        free(rule->ifname);
    }
    if (rule->ofname != NULL) {
        clear_all_double_list(rule->ofname, 1 , free_expression, NULL);
        free(rule->ofname);
    }
    if (rule->proto != NULL) {
        clear_all_double_list(rule->proto, 1 , free_expression, NULL);
        free(rule->proto);
    }
    if (rule->src_address != NULL) {
        clear_all_double_list(rule->src_address, 1 , free_expression, NULL);
        free(rule->src_address);
    }
    if (rule->dst_address != NULL) {
        clear_all_double_list(rule->dst_address, 1 , free_expression, NULL);
        free(rule->dst_address);
    }
    if (rule->src_ports != NULL) {
        clear_all_double_list(rule->src_ports, 1 , free_expression, NULL);
        free(rule->src_ports);
    }
    if (rule->dst_ports != NULL) {
        clear_all_double_list(rule->dst_ports, 1 , free_expression, NULL);
        free(rule->dst_ports);
    }
    if (rule->ct != NULL) {
        clear_all_double_list(rule->ct, 1 , free_expression, NULL);
        free(rule->ct);
    }
    if (rule->dest_chain != NULL) {
        free(rule->dest_chain);
    }
#ifdef DEBUG_NFTABLES
    printf("DONE!\n");
#endif
}

// Function to free all rules of a chain in the chains dictionary
void free_rules_chain_dictionary(struct value_dict *el, void *param) {
    double_list l_chain = (double_list)el->value;

#ifdef DEBUG_NFTABLES
    printf("Clearing all rules of chain %s...\n", (char *)el->key);
    clear_all_double_list(l_chain, 1, free_rule_chain_dictionary, el->key);
    printf("DONE!\n");
#else
    clear_all_double_list(l_chain, 1, free_rule_chain_dictionary, NULL);
#endif
}

// Function to compare for sorting two elements of the input chains list
int compare_input_chains(void *val1, void *val2) {
    input_chain_t *chain1, *chain2;

    chain1 = (input_chain_t *)val1;
    chain2 = (input_chain_t *)val2;

    if (chain1->priority < chain2->priority) {
        return -1;
    }
    if (chain1->priority == chain2->priority) {
        return 0;
    }
    return 1;
}

// Function to compares for sorting two keys of type char *
int compare_keys_string(void *val1, void *val2) {
    char *key1, *key2;
    int comp;

    key1 = (char *)val1;
    key2 = (char *)val2;
    comp = strcmp(key1, key2);
    if (comp < 0) {
        return -1;
    }
    if (comp == 0) {
        return 0;
    }
    return 1;
}

// Function to compare for sorting two elements of the dictionary
int compare_string(struct value_dict *val1, struct value_dict *val2) {
    char *key1, *key2;
    int comp;

    key1 = (char *)val1->key;
    key2 = (char *)val2->key;
    comp = strcmp(key1, key2);
    if (comp < 0) {
        return -1;
    }
    if (comp == 0) {
        return 0;
    }
    return 1;
}

#ifdef DEBUG_NFTABLES_NFTABLES

// Function to print rules of a chain
void print_rules_chain(void *el, void *param) {
    static int count_rules_chain;
    static char *ant_chain_name = NULL;
    char *chain_name = (char *)param;
    rule_t *rule = (rule_t *) el;

    if (chain_name != ant_chain_name) {
        ant_chain_name = chain_name;
        count_rules_chain = 0;
    }
    count_rules_chain++;
    printf("Rule %3d: ", count_rules_chain);
    if (rule->ifname != NULL) {
        printf("iifname filter\t");
    }
    if (rule->ofname != NULL) {
        printf("oifname filter\t");
    }
    if (rule->proto != NULL) {
        printf("protocol filter\t");
    }
    if (rule->src_address != NULL) {
        printf("saddr filter\t");
    }
    if (rule->dst_address != NULL) {
        printf("daddr filter\t");
    }
    if (rule->src_ports != NULL) {
        printf("sport filter\t");
    }
    if (rule->dst_ports != NULL) {
        printf("dport filter\t");
    }
    if (rule->ct != NULL) {
        printf("ct filter\t");
    }
    switch (rule->action) {
        case DROP:
            printf("----> DROP\n");
            break;
        case ACCEPT:
            printf("----> ACCEPT\n");
            break;
        case JUMP:
            printf("----> JUMP %s\n", rule->dest_chain);
            break;
        case GOTO:
            printf("----> GOTO %s\n", rule->dest_chain);
            break;
    }
}

// Function to print list of rules of the chains dictionary
void print_list_rules_chain_dictionary(struct value_dict *el, void *param) {
    char *chain_name = (char *)el->key;
    double_list l_chain = (double_list)el->value;

    printf("RULES OF CHAIN %s\n", chain_name);
    printf("==============================\n");
    for_each_double_list(l_chain, print_rules_chain, chain_name);
}
#endif

#endif
