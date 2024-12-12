#ifndef __NFTABLESEVALUATOR_H
#define __NFTABLESEVALUATOR_H

#include <Configuration.h>
#if NFTABLES_ACTIVE == 1

#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Function prototypes
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
int evaluate_packet(uint8_t protocol, uint8_t ct_state, const char *input_dev, const char *output_dev, in_addr_t s_address, in_addr_t d_address, uint16_t s_port, uint16_t d_port);


#endif

#endif
