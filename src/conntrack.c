#include <conntrack.h>

// This callback function search for a conntrack query and (if is is found)
// put its info in data param
int cb(enum nf_conntrack_msg_type type,struct nf_conntrack *ct,void *data)
{          
        char buf[1024];
        struct nf_conntrack *obj = data;

        nfct_copy(obj, ct, NFCT_CP_ALL);
        return NFCT_CB_CONTINUE;    
}         

int get(uint8_t ip_protocol, in_addr_t ip_src, uint16_t port_src, in_addr_t ip_dst, uint16_t port_dst)
{    
        int ret;    
        struct nfct_handle *h;    
        struct nf_conntrack *ct;
        struct nf_conntrack *ct_result;
        uint32_t orig_ip_src;
        uint32_t status;

        ct = nfct_new();
        if (!ct) {
            perror("nfct_new");    
            return -1;    
        }    

        ct_result = nfct_new();
        if (!ct_result) {
            perror("nfct_new");
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
            perror("nfct_open");   
            nfct_destroy(ct);    
            return -1;    
        }         

        nfct_callback_register(h, NFCT_T_ALL, cb, ct_result);

        ret = nfct_query(h, NFCT_Q_GET, ct);

        if (ret != -1) {
            ret = 0;
            orig_ip_src = nfct_get_attr_u32(ct_result, ATTR_ORIG_IPV4_SRC);
            inet_ntop(AF_INET, &orig_ip_src, orig_s_ip_src, INET_ADDRSTRLEN);
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
        }

        nfct_callback_unregister(h);
        nfct_close(h);
        nfct_destroy(ct);
        nfct_destroy(ct_result);

        return ret;
}

