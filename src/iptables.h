#ifndef __IPTABLES_H
#define __IPTABLES_H

// Constants
#define BLACKLIST_CHAIN "BlackList"
#define RULE_TIMEOUT    300

// Function prototypes
void initIPtables();
int actionIncoming(char *net_device, uint8_t proto, uint32_t s_address, u_int16_t sport, uint32_t d_address, u_int16_t dport, 
                   u_int8_t flags_type, u_int8_t code, int new_connection, const char *chain_name);
// Need: Network incoming device
//       The IP protocol 
//       A source IP address in binary format
//       The source port
//       A destination IP address in binary format
//       The destination port
//       The TCP flags or ICMP type code
//       ICMP code
//       1 if the connection is new or 0 in another case
//       The initial chain iptables where start the search
//       Buffer to store the action applied to connection with arguments above
// MODIFIES: action with the action applied to connection with arguments above, "" if not action applied (no matched rule found),
// RETURN: 4 if address is banned, 3 if address is rejected, 2 if adresss is dropped, 1 if address is accepted, 
//         0 if not rule has been found, -1 if a NOT supported rule was found

#endif