#include <string.h>

#include <NFTablesEvaluator.h>
#include <nftables.h>

#if NFTABLES_ACTIVE == 1

// EXTERNAL Global vars
extern struct write_global_vars w_globvars;

// EXTERNAL Global vars
extern struct write_global_vars w_globvars;

// PRIVATE FUNCTION PROTOTYPES RELATIVE TO EVALUATE RULES AND EXPRESSIONS
/*
Evaluate a chain
PARAMS:     Chain name
            Default policy
            Packet's protocol
            Packet's conntrack state (flags bits)
            Packet's input device (or NULL if it is an output packet)
            Packet's output device (or NULL if it is an input packet)
            Packet's source address
            Packet's destination address
            Packet's source port
            Packet's destination port
RETURN:     ACCEPT (if packet is accepted)
            DROP   (if packet is dropped)
            -1 if any error
*/
int evaluate_chain(char *chain_name, int def_policy, uint8_t protocol, uint8_t ct_state, const char *input_dev, const char *output_dev, in_addr_t s_address, in_addr_t d_address, uint16_t s_port, uint16_t d_port);
/*
Evaluate a rule
PARAMS:     The rule
            Packet's protocol
            Packet's conntrack state (flags bits)
            Packet's input device (or NULL if it is an output packet)
            Packet's output device (or NULL if it is an input packet)
            Packet's source address
            Packet's destination address
            Packet's source port
            Packet's destination port
RETURN:     Rule's action if packet match the rule.
            NOT_MATCH if packet DO NOT match the rule
            -1 if any error
*/
int evaluate_rule(rule_t *rule, uint8_t protocol, uint8_t ct_state, const char *input_dev, const char *output_dev, in_addr_t s_address, in_addr_t d_address, uint16_t s_port, uint16_t d_port);

/*
Check if expression's value is in a named set
PARAMS:     The expression
            Packet's protocol
RETURN:     expr->values if there is not a named set
            or
            the list of values of named set
            or 
            NULL if any error
*/
double_list check_named_set(expr_t *expr);
/*
Evaluate local protocol expression
PARAMS:     The expression
            Packet's protocol
RETURN:     1 if matching
            NOT_MATCH if not matching
            -1 if any error
*/
int evaluate_local_protocol(expr_t *expr, uint8_t protocol);
/*
Evaluate device name expressions
PARAMS:     The device expressions
            Packet's protocol
            The device name
RETURN:     1 if matching
            NOT_MATCH if not matching
            -1 if any error
*/
int evaluate_device(double_list l_expr, uint8_t protocol, const char *dev_name);
/*
Evaluate an address expression
PARAMS:     A list of addresses
            A matching operator
            The address
RETURN:     1 if matching
            NOT_MATCH if not matching
            -1 if any error
*/
int evaluate_single_address(double_list l_address, int operator, in_addr_t address);
/*
Evaluate addresses expression
PARAMS:     The address expressions
            Packet's protocol
            The address
RETURN:     1 if matching
            NOT_MATCH if not matching
            -1 if any error
*/
int evaluate_address(double_list l_expr, uint8_t protocol, in_addr_t in_address);
/*
Evaluate a port expression
PARAMS:     A list of ports
            A matching operator
            A port
RETURN:     1 if matching
            NOT_MATCH if not matching
            -1 if any error
*/
int evaluate_single_port(double_list l, int operator, uint16_t port);
/*
Evaluate port expressions
PARAMS:     The port expressions
            Packet's protocol
            A port
RETURN:     1 if matching
            NOT_MATCH if not matching
            -1 if any error
*/
int evaluate_ports(double_list l_expr, uint8_t protocol, uint16_t port);


// PRIVATE FUNCTION PROTOTYPES RELATIVE TO SEARCH IN LISTS AND DICTIONARIES
// Function to compares uint8_t (for searching protocols) 
int compare_u_int8(void *val1, void *val2);
// Function to compares uint16_t (for searching ports) 
int compare_u_int16(void *val1, void *val2);
// Function to compares char * (for searching chain's names or general text) 
int compare_pchar(void *val1, void *val2);
// Function to compares ct states (for searching them)
int compare_ct_states(void *val1, void *val2);


/*
Evaluate a packet
PARAMS:     Packet's protocol
            Packet's conntrack state (flags bits)
            Packet's input device (or NULL if it is an output packet)
            Packet's output device (or NULL if it is an input packet)
            Packet's source address
            Packet's destination address
            Packet's source port
            Packet's destination port
RETURN:     ACCEPT (if packet is accepted)
            DROP   (if packet is dropped)
            -1 if any error
*/
int evaluate_packet(uint8_t protocol, uint8_t ct_state, const char *input_dev, const char *output_dev, in_addr_t s_address, in_addr_t d_address, uint16_t s_port, uint16_t d_port) {
    input_chain_t *val;
    struct node_sorted_list *node;
    int eval;

    // Iterate input chains (in order of priority)
    node = first_sorted_list(w_globvars.input_chains);
    while (node != NULL) {
        // Get next input chain
        val = (input_chain_t *) node->info;
        // Evaluate input chain
        if ((eval=evaluate_chain(val->name, val->default_policy, protocol, ct_state, input_dev, output_dev, s_address, d_address, s_port, d_port)) != ACCEPT) {
            return eval;
        }
        // Next input chain
        node = next_sorted_list(node);
    }
    return ACCEPT;
}


/*
Evaluate a chain
PARAMS:     Chain name
            Default policy
            Packet's protocol
            Packet's conntrack state (flags bits)
            Packet's input device (or NULL if it is an output packet)
            Packet's output device (or NULL if it is an input packet)
            Packet's source address
            Packet's destination address
            Packet's source port
            Packet's destination port
RETURN:     ACCEPT (if packet is accepted)
            DROP   (if packet is dropped)
            -1 if any error
*/
int evaluate_chain(char *chain_name, int def_policy, uint8_t protocol, uint8_t ct_state, const char *input_dev, const char *output_dev, in_addr_t s_address, in_addr_t d_address, uint16_t s_port, uint16_t d_port) {
    double_list l_chain;
    struct node_double_list *node;
    rule_t *rule;
    int chain_eval = def_policy;
    int eval = NOT_MATCH;
    int blacklist;
#ifdef DEBUG_NFTABLES
    int jumping;
    int count = 0;
#endif

    // Is it the black list chain
    blacklist = !strcmp(chain_name, NFTABLES_CHAIN_BLACKLIST);
    
    // Get rules list of chain
    l_chain = get_value_dict(w_globvars.chains, chain_name);

    if (l_chain == NULL) {
        fprintf(stderr, "evaluate_chain: Chain %s not found\n", chain_name);
        return -1;
    }

    // Iterate chain's rules
    node = first_double_list(l_chain);
    while (node != NULL && eval == NOT_MATCH) {
#ifdef DEBUG_NFTABLES
        jumping = 0;
        count++;
        printf("Evaluating rule %0d in chain %s ... ", count, chain_name);
#endif
        // Get rule
        rule = (rule_t *) node->info;
        // Evaluate rule
        eval = evaluate_rule(rule, protocol, ct_state, input_dev, output_dev, s_address, d_address, s_port, d_port);
#ifdef DEBUG_NFTABLES
        printf("DONE!  eval=%0d.\t", eval);
#endif
        // Jump?
        if (eval == JUMP) {
#ifdef DEBUG_NFTABLES
            jumping = 1;
            printf("Matching! --> JUMP %s\n", rule->dest_chain);
#endif
            // If jumping to regular chain the default policy must be NOT_MATCH
            eval = evaluate_chain(rule->dest_chain, NOT_MATCH, protocol, ct_state, input_dev, output_dev, s_address, d_address, s_port, d_port);
        }
        switch (eval) {
            case GOTO:
#ifdef DEBUG_NFTABLES
                printf("Matching! --> GOTO %s\n", rule->dest_chain);
#endif
                // Result is in another chain
                return evaluate_chain(rule->dest_chain, def_policy, protocol, ct_state, input_dev, output_dev, s_address, d_address, s_port, d_port);            
            case NOT_MATCH:
#ifdef DEBUG_NFTABLES
                if (!jumping) {
                    printf("NOT Matching!\n");
                }
#endif
                // Next rule
                node = next_double_list(node);
                // Without store result
                break;
            case ACCEPT:
#ifdef DEBUG_NFTABLES
                if (!jumping) {
                    printf("Matching! --> ACCEPT\n");
                }
#endif
                // Store result...
                chain_eval = eval;
                break;
            case -1:
                // Error
#ifdef DEBUG_NFTABLES
                if (!jumping) {
                    printf("ERROR!\n");
                }
#endif
                // Store result
                chain_eval = eval;
                break;
            case DROP:
                // Store result
                if (blacklist) {
#ifdef DEBUG_NFTABLES
                    if (!jumping) {
                        printf("Matching! --> BANNED\n");
                    }
#endif
                    chain_eval = BANNED;
                }
                else {
                    chain_eval = eval;
#ifdef DEBUG_NFTABLES
                    if (!jumping) {
                        printf("Matching! --> DROP\n");
                    }
#endif
                }
                break;
            case BANNED:
#ifdef DEBUG_NFTABLES
                if (!jumping) {
                    printf("Matching! --> BANNED\n");
                }
#endif
                // Store result
                chain_eval = eval;
                break;
            default:
#ifdef DEBUG_NFTABLES
                printf("UNEXPECTED eval VALUE %0d!\n", eval);
#endif
                return -1;
        }
    }
#ifdef DEBUG_NFTABLES
    if (def_policy == NOT_MATCH) {
        printf("Returning from JUMP with eval %0d\n", chain_eval);
    }
#endif
    return chain_eval;
}

/*
Evaluate a rule
PARAMS:     The rule
            Packet's protocol
            Packet's conntrack state (flags bits)
            Packet's input device (or NULL if it is an output packet)
            Packet's output device (or NULL if it is an input packet)
            Packet's source address
            Packet's destination address
            Packet's source port
            Packet's destination port
RETURN:     Rule's action if packet match the rule.
            NOT_MATCH if packet DO NOT match the rule
            -1 if any error
*/
int evaluate_rule(rule_t *rule, uint8_t protocol, uint8_t ct_state, const char *input_dev, const char *output_dev, in_addr_t s_address, in_addr_t d_address, uint16_t s_port, uint16_t d_port) {
    double_list l;
    struct node_double_list *node;
    expr_t *expr;
    int ret;
    
    // Protocol matching?
    if (rule->proto != NULL && !isEmpty_double_list(rule->proto)) {
        // Iterate proto expressions (and apply operator AND with all of them)
        node = first_double_list(rule->proto);
        while (node != NULL) {
            expr = (expr_t *)node->info;
            // Local protocol matching?
            ret = evaluate_local_protocol(expr, protocol);
            if ( ret != 1) {
                return ret;
            }
            // Is it a named set?
            l = check_named_set(expr);
            if (l == NULL) {
                return -1;
            }
            // Evaluation
            if (find_double_list(l, &protocol, compare_u_int8) == NULL) {
                if (expr->operator == EQ_OP) {
                    return NOT_MATCH;
                }
            }
            else {
                if (expr->operator == NE_OP) {
                    return NOT_MATCH;
                }
            }
            // Next expression
            node = next_double_list(node);
        }
    }

    // Input device matching?
    ret = evaluate_device(rule->ifname, protocol, input_dev);
    if (ret != 1) {
        return ret;
    }

    // Output device matching?
    ret = evaluate_device(rule->ofname, protocol, output_dev);
    if (ret != 1) {
        return ret;
    }

    // CT State matching?
    if (rule->ct != NULL && !isEmpty_double_list(rule->ct)) {
        // Iterate CT state expressions (and apply operator AND with all of them)
        node = first_double_list(rule->ct);
        while (node != NULL) {
            expr = (expr_t *)node->info;
            // Local protocol matching?
            ret = evaluate_local_protocol(expr, protocol);
            if ( ret != 1) {
                return ret;
            }
            // Is it a named set?
            l = check_named_set(expr);
            if (l == NULL) {
                return -1;
            }
            // Evaluation
            if (find_double_list(l, &ct_state, compare_ct_states) == NULL) {
                if (expr->operator == EQ_OP) {
                    return NOT_MATCH;
                }
            }
            else {
                if (expr->operator == NE_OP) {
                    return NOT_MATCH;
                }
            }
            // Next expression
            node = next_double_list(node);
        }
    }

    // Source address matching?
    ret = evaluate_address(rule->src_address, protocol, s_address);
    if (ret != 1) {
        return ret;
    }

    // Destination address matching?
    ret = evaluate_address(rule->dst_address, protocol, d_address);
    if (ret != 1) {
        return ret;
    }

    // Source port matching?
    ret = evaluate_ports(rule->src_ports, protocol, s_port);
    if (ret != 1) {
        return ret;
    }

    // Destination port matching?
    ret = evaluate_ports(rule->dst_ports, protocol, d_port);
    if (ret != 1) {
        return ret;
    }

    // Match
    return rule->action; 
}

/*
Check if expression's value is in a named set
PARAMS:     The expression
            Packet's protocol
RETURN:     expr->values if there is not a named set
            or
            the list of values of named set
            or 
            NULL if any error
*/
double_list check_named_set(expr_t *expr) {
    // Is it a named set?
    if (expr->set_name != NULL) {
        // Yes. Try to find its list of values
        return (double_list) get_value_dict(w_globvars.sets, expr->set_name);
    }
    else {
        // No
        return expr->values;
    }
}

/*
Evaluate local protocol expression
PARAMS:     The expression
            Packet's protocol
RETURN:     1 if matching
            NOT_MATCH if not matching
            -1 if any error
*/
int evaluate_local_protocol(expr_t *expr, uint8_t protocol) {
    switch (expr->proto) {
        case ANY:
            return 1;
        case TH:
            if (protocol == TCP || protocol == UDP) {
                return 1;
            }
            return NOT_MATCH;
        default:
            if (expr->proto == protocol) {
                return 1;
            }
            return NOT_MATCH;
    }
}

/*
Evaluate device name expressions
PARAMS:     The device expressions
            Packet's protocol
            The device name
RETURN:     1 if matching
            NOT_MATCH if not matching
            -1 if any error
*/
int evaluate_device(double_list l_expr, uint8_t protocol, const char *dev_name) {
    double_list l;
    struct node_double_list *node;
    expr_t *expr;
    int ret;

    // Device matching?
    if (dev_name != NULL && l_expr != NULL && !isEmpty_double_list(l_expr)) {
        // Iterate expressions (and apply operator AND with all of them)
        node = first_double_list(l_expr);
        while (node != NULL) {
            expr = (expr_t *)node->info;
            // Local protocol matching?
            ret = evaluate_local_protocol(expr, protocol);
            if ( ret != 1) {
                return ret;
            }
            // Is it a named set?
            l = check_named_set(expr);
            if (l == NULL) {
                return -1;
            }
            // Evaluation
            if (find_double_list(l, (char *)dev_name, compare_pchar) == NULL) {
                if (expr->operator == EQ_OP) {
                    return NOT_MATCH;
                }
            }
            else {
                if (expr->operator == NE_OP) {
                    return NOT_MATCH;
                }
            }
            // Next expression
            node = next_double_list(node);
        }
    }
    return 1;
}

/*
Evaluate an address expression
PARAMS:     A list of addresses
            A matching operator
            The address
RETURN:     1 if matching
            NOT_MATCH if not matching
            -1 if any error
*/
int evaluate_single_address(double_list l_address, int operator, in_addr_t address) {
    struct node_double_list *node_address;
    address_mask_t *addr;
    in_addr_t address_net, address1, address2, mask;
	unsigned mask_bits;

    // Iterate addresses
    node_address = first_double_list(l_address);
    while (node_address != NULL) {
        addr = (address_mask_t *)node_address->info;
        // Extract network address of address
        // with current mask
        if (addr->mask != 32) {
            mask = 0xFFFFFFFF;
            mask_bits = 32 - addr->mask;
            mask = mask << mask_bits;
            address_net = address & mask;
        }
        else {
            address_net = address;
        }
        // Get address1 in decimal format
        address1 = ntohl(addr->address);
        // Get address2 in decimal forma (if it is a range)
        if (addr->mask2){
            address2 = ntohl(addr->address2);
        }
        switch (operator) {
            case EQ_OP:
                // Is it a range?
                if (addr->mask2) {
                    if (address >= address1 && address <= address2) {
                        return 1;
                    }
                }
                else {
                    // It's a single address or prefix
                    if (address_net == address1) {
                        return 1;
                    }
                }
                break;
            case NE_OP:
                // Is it a range?
                if (addr->mask2) {
                    if (address >= address1 && address <= address2) {
                        return NOT_MATCH;
                    }
                }
                else {
                    // It's a single address or prefix
                    if (address_net == address1) {
                        return NOT_MATCH;
                    }
                }
                break;
            case LT_OP:
                if (address < address1) {
                    return 1;
                }
                break;
            case GT_OP:
                if (address > address1) {
                    return 1;
                }
                break;
            case LE_OP:
                if (address <= address1) {
                    return 1;
                }
                break;
            case GE_OP:
                if (address >= address1) {
                    return 1;
                }
                break;
        }        
        // Next address
        node_address = next_double_list(node_address);
    }
    if (operator == NE_OP) {
        return 1;
    }
    return NOT_MATCH;
}

/*
Evaluate addresses expression
PARAMS:     The address expressions
            Packet's protocol
            The address
RETURN:     1 if matching
            NOT_MATCH if not matching
            -1 if any error
*/
int evaluate_address(double_list l_expr, uint8_t protocol, in_addr_t in_address) {
    double_list l;
    struct node_double_list *node;
    expr_t *expr;
    in_addr_t address;
    int ret;

    // Address matching?
    if (l_expr != NULL && !isEmpty_double_list(l_expr)) {
        // Get address1 in decimal format
        address = ntohl(in_address);
        // Iterate expressions (and apply operator AND with all of them)
        node = first_double_list(l_expr);
        while (node != NULL) {
            expr = (expr_t *)node->info;
            // Local protocol matching?
            ret = evaluate_local_protocol(expr, protocol);
            if ( ret != 1) {
                return ret;
            }
            // Is it a named set?
            l = check_named_set(expr);
            if (l == NULL) {
                return -1;
            }
            // Evaluation
            ret = evaluate_single_address(l, expr->operator, address);
            if (ret != 1) {
                return ret;
            }
            // Next expression
            node = next_double_list(node);
        }
    }
    return 1;
}


/*
Evaluate a port expression
PARAMS:     A list of ports
            A matching operator
            A port
RETURN:     1 if matching
            NOT_MATCH if not matching
            -1 if any error
*/
int evaluate_single_port(double_list l, int operator, uint16_t port) {
    struct node_double_list *node_ports;
    port_t *val;

    // Iterate ports
    node_ports = first_double_list(l);
    while (node_ports != NULL) {
        val = (port_t *)node_ports->info;
        switch (operator) {
            case EQ_OP:
                // Is it a range?
                if (val->port2) {
                    if (port >= val->port && port <= val->port2) {
                        return 1;
                    }
                }
                else {
                    // It's a single port
                    if (port == val->port) {
                        return 1;
                    }
                }
                break;
            case NE_OP:
                // Is it a range?
                if (val->port2) {
                    if (port >= val->port && port <= val->port2) {
                        return NOT_MATCH;
                    }
                }
                else {
                    // It's a single port
                    if (port == val->port) {
                        return NOT_MATCH;
                    }
                }
                break;
            case LT_OP:
                if (port < val->port) {
                    return 1;
                }
                break;
            case GT_OP:
                if (port > val->port) {
                    return 1;
                }
                break;
            case LE_OP:
                if (port <= val->port) {
                    return 1;
                }
                break;
            case GE_OP:
                if (port >= val->port) {
                    return 1;
                }
                break;
        }        
        // Next port
        node_ports = next_double_list(node_ports);
    }
    if (operator == NE_OP) {
        return 1;
    }
    return NOT_MATCH;
}

/*
Evaluate port expressions
PARAMS:     The port expressions
            Packet's protocol
            A port
RETURN:     1 if matching
            NOT_MATCH if not matching
            -1 if any error
*/
int evaluate_ports(double_list l_expr, uint8_t protocol, uint16_t port) {
    double_list l;
    struct node_double_list *node;
    expr_t *expr;
    int ret;

    // Address matching?
    if (l_expr != NULL && !isEmpty_double_list(l_expr)) {
        // Iterate ports (and apply operator AND with all of them)
        node = first_double_list(l_expr);
        while (node != NULL) {
            expr = (expr_t *)node->info;
            // Local protocol matching?
            ret = evaluate_local_protocol(expr, protocol);
            if ( ret != 1) {
                return ret;
            }
            // Is it a named set?
            l = check_named_set(expr);
            if (l == NULL) {
                return -1;
            }
            // Evaluation
            ret = evaluate_single_port(l, expr->operator, port);
            if (ret != 1) {
                return ret;
            }
            // Next expression
            node = next_double_list(node);
        }
    }
    return 1;
}

// Function to compares (for searching) uint8_t
int compare_u_int8(void *val1, void *val2) {
    uint8_t *ok_val1 = (uint8_t *)val1;
    uint8_t *ok_val2 = (uint8_t *)val2;

    return *ok_val1 == *ok_val2;
}

// Function to compares (for searching) uint16_t
int compare_u_int16(void *val1, void *val2) {
    uint16_t *ok_val1 = (uint16_t *)val1;
    uint16_t *ok_val2 = (uint16_t *)val2;

    return *ok_val1 == *ok_val2;
}

// Function to compares (for searching) char *
int compare_pchar(void *val1, void *val2) {
    char *key1, *key2;

    key1 = (char *)val1;
    key2 = (char *)val2;
    return !strcmp(key1, key2);
}

// Function to compares ct states
int compare_ct_states(void *val1, void *val2) {
    uint8_t *ok_val1 = (uint8_t *)val1;
    uint8_t *ok_val2 = (uint8_t *)val2;

    return *ok_val1 & *ok_val2;
}


#endif

