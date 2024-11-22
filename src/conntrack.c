#include <conntrack.h>

// This callback function search for a conntrack query and (if is is found)
// put its info in data param
int cb(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data)
{          
        struct nf_conntrack *obj = data;

        nfct_copy(obj, ct, NFCT_CP_ALL);
        return NFCT_CB_CONTINUE;    
}         

int get_conntrack_TCP_UDP(uint8_t ip_protocol, in_addr_t ip_src, uint16_t port_src, in_addr_t ip_dst, uint16_t port_dst, uint32_t *ip_NAT, uint16_t *port_NAT)
{    
        int ret;    
        struct nfct_handle *h;    
        struct nf_conntrack *ct;
        struct nf_conntrack *ct_result;
        uint32_t orig_ip_src, reply_ip_src;
        uint16_t reply_port_src;
        uint32_t status;

        ct = nfct_new();
        if (!ct) {
            return -1;    
        }    

        ct_result = nfct_new();
        if (!ct_result) {
            return -1;
        }

        nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);    
        nfct_set_attr_u8(ct, ATTR_L4PROTO, ip_protocol);    
        nfct_set_attr_u32(ct, ATTR_IPV4_SRC, ip_src);    
        nfct_set_attr_u32(ct, ATTR_IPV4_DST, ip_dst);
        nfct_set_attr_u16(ct, ATTR_PORT_SRC, htons(port_src));         
        nfct_set_attr_u16(ct, ATTR_PORT_DST, htons(port_dst));

        h = nfct_open(CONNTRACK, 0);    
        if (!h) {
            nfct_destroy(ct);    
            return -1;    
        }         

        nfct_callback_register(h, NFCT_T_ALL, cb, ct_result);

        ret = nfct_query(h, NFCT_Q_GET, ct);

        if (ret != -1) {
            ret = 0;
            orig_ip_src = nfct_get_attr_u32(ct_result, ATTR_ORIG_IPV4_SRC);
            reply_ip_src = nfct_get_attr_u32(ct_result, ATTR_REPL_IPV4_SRC);
            reply_port_src = ntohs(nfct_get_attr_u16(ct_result, ATTR_REPL_PORT_SRC));
            status = nfct_get_attr_u32(ct_result, ATTR_STATUS);
            // Is this a start (client) connection ?
            if (orig_ip_src == ip_src) {
                // Yes
                ret += CONNTRACK_CLIENT;
            }
            // Is there a reply connection ?
            if ((status & IPS_SEEN_REPLY) != 0) {
                // Yes
                ret += CONNTRACK_SEEN_REPLY;
            }
            // Is this a stablished connection ?
            if ((status & IPS_CONFIRMED) != 0) {
                // Yes
                ret += CONNTRACK_STABLISHED;
            }
            // Is this an asured connection?
            if ((status & IPS_ASSURED ) != 0) {
                // Yes
                ret += CONNTRACK_ASURED;
            }
            // Is this a NAT connection?
            if ((status & IPS_DST_NAT ) != 0) {
                // Yes
                ret += CONNTRACK_NAT;
                *ip_NAT = reply_ip_src;
                *port_NAT = reply_port_src;
            }
        }

        nfct_callback_unregister(h);
        nfct_close(h);
        nfct_destroy(ct);
        nfct_destroy(ct_result);

        return ret;
}

int get_conntrack_ICMP(in_addr_t ip_src, in_addr_t ip_dst, uint8_t type, uint8_t code, uint32_t *ip_NAT)
{    
        int ret;    
        struct nfct_handle *h;    
        struct nf_conntrack *ct;
        struct nf_conntrack *ct_result;
        uint32_t orig_ip_src;
        uint32_t status;

        ct = nfct_new();
        if (!ct) {
            return -1;    
        }    

        ct_result = nfct_new();
        if (!ct_result) {
            return -1;
        }

        nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);    
        nfct_set_attr_u8(ct, ATTR_L4PROTO, IPPROTO_ICMP);    
        nfct_set_attr_u32(ct, ATTR_IPV4_SRC, ip_src);    
        nfct_set_attr_u32(ct, ATTR_IPV4_DST, ip_dst);
        nfct_set_attr_u8(ct, ATTR_ICMP_TYPE, type);
        nfct_set_attr_u8(ct, ATTR_ICMP_CODE, code);

        h = nfct_open(CONNTRACK, 0);    
        if (!h) {
            nfct_destroy(ct);    
            return -1;    
        }         

        nfct_callback_register(h, NFCT_T_ALL, cb, ct_result);

        ret = nfct_query(h, NFCT_Q_GET, ct);

        if (ret != -1) {
            ret = 0;
            orig_ip_src = nfct_get_attr_u32(ct_result, ATTR_ORIG_IPV4_SRC);
            status = nfct_get_attr_u32(ct_result, ATTR_STATUS);
            // Is this a start (client) connection ?
            if (orig_ip_src == ip_src) {
                // Yes
                ret += CONNTRACK_CLIENT;
            }
            // Is there a reply connection ?
            if ((status & IPS_SEEN_REPLY) != 0) {
                // Yes
                ret += CONNTRACK_SEEN_REPLY;
            }
            // Is this a stablished connection ?
            if ((status & IPS_CONFIRMED) != 0) {
                // Yes
                ret += CONNTRACK_STABLISHED;
            }
            // Is this an asured connection?
            if ((status & IPS_ASSURED ) != 0) {
                // Yes
                ret += CONNTRACK_ASURED;
            }
            // Is this a NAT connection?
            if ((status & IPS_DST_NAT ) != 0) {
                // Yes
                ret += CONNTRACK_NAT;
                *ip_NAT = nfct_get_attr_u32(ct_result, ATTR_DNAT_IPV4);
            }
        }

        nfct_callback_unregister(h);
        nfct_close(h);
        nfct_destroy(ct);
        nfct_destroy(ct_result);

        return ret;
}
