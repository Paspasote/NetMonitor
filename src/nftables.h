#ifndef __NFTABLES_H
#define __NFTABLES_H

#include <Configuration.h>
#if NFTABLES_ACTIVE == 1

#include <stdint.h>

#include <GlobalVars.h>
#include <DoubleList.h>
#include <SortedList.h>
#include <Dictionary.h>

// CONSTANTS
#define NOT_MATCH -10

// Protocols in rule
#define ANY         0
#define ICMP        IPPROTO_ICMP
#define TCP         IPPROTO_TCP
#define UDP         IPPROTO_UDP
#define TH          254
#define UNSUPPORTED 255
// Actions in rule
#define ACCEPT      1
#define DROP        2
#define BANNED      4
#define JUMP        10
#define GOTO        11
// Operators in rule
#define EQ_OP       0
#define NE_OP       1
#define LT_OP       2
#define GT_OP       3
#define LE_OP       4
#define GE_OP       5
// CT states in rule
#define ESTABLISHED 1
#define RELATED     2
#define INVALID     4

// STRUCTURAL DATA

// struct for rules
typedef
    struct {
        double_list ifname;
        double_list ofname;
        double_list proto;
        double_list src_address;
        double_list dst_address;
        double_list src_ports;
        double_list dst_ports;
        double_list ct;
        char *dest_chain;
        int action;
    } rule_t;

// struct for expressions
typedef
    struct {
        int operator;
        uint8_t proto;
        double_list values;
    } expr_t;

// struct to store an address or range of addresses
typedef
    struct {
        in_addr_t address;
        in_addr_t address2;
        uint8_t mask;
        uint8_t mask2;
    } address_mask_t;

// struct to store a port or rage of ports
typedef
    struct {
        uint16_t port;
        uint16_t port2;
    }  port_t;

// struct for input chains
typedef 
    struct {
        char *name;
        int priority;
        int default_policy;
    } input_chain_t;


// Function prototypes
void initXtables();

// Need: Network incoming device
//       The IP protocol 
//       A source IP address in binary format
//       The source port
//       A destination IP address in binary format
//       The destination port
//       The TCP flags or ICMP type code
//       ICMP code
//       1 if the connection is new or 0 in another case
// MODIFIES: action with the action applied to connection with arguments above, "" if not action applied (no matched rule found),
// RETURN: 4 if address is banned, 2 if adresss is dropped, 1 if address is accepted, 
//         0 if not rule has been found, -1 if a NOT supported rule was found
int actionIncoming(char *net_device, uint8_t proto, in_addr_t s_address, uint16_t sport, in_addr_t d_address, uint16_t dport, 
                       uint8_t flags_type, uint8_t code, int new_connection);

#endif

#endif

