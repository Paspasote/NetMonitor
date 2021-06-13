#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <libiptc/libiptc.h>
#include <linux/netfilter/xt_multiport.h>
#include <linux/netfilter/xt_tcpudp.h>
#include <linux/netfilter/xt_physdev.h>
#include <linux/netfilter/xt_conntrack.h>
#include <linux/netfilter/xt_state.h>

#include <iptables.h>

// Global vars
struct xtc_handle *h_iptables = NULL;

// Prototype functions
int match_multiport(struct ipt_entry_match *match, u_int16_t sport, u_int16_t dport);
int match_icmp(struct ipt_entry_match *match, u_int8_t type, u_int8_t code);
int match_tcp(struct ipt_entry_match *match, u_int16_t sport, u_int16_t dport, u_int8_t flags);
int match_udp(struct ipt_entry_match *match, u_int16_t sport, u_int16_t dport);
int match_physdev(struct ipt_entry_match *match, char *net_device);
int match_conntrack(struct ipt_entry_match *match, int new_connection);
int match_rule(char *net_device, uint8_t proto, uint32_t s_address, u_int16_t sport, uint32_t d_address, u_int16_t dport, u_int8_t flags_type, u_int8_t code, int new_connection, const struct ipt_entry *entry);

void initIPtables()
{
   // Initialization
    h_iptables = iptc_init("filter");
    if (h_iptables == NULL) 
    {
        fprintf(stderr, "Can't initialize: %s\n", iptc_strerror(errno));
        exit(EXIT_FAILURE);
    }
}

int match_multiport(struct ipt_entry_match *match, u_int16_t sport, u_int16_t dport)
{
    struct xt_multiport *m_multiport;
    int match_sport, match_dport;
    int i;

    m_multiport = (struct xt_multiport *)match->data;
    switch (m_multiport->flags)
    {
        case XT_MULTIPORT_SOURCE:
            // Match source port ?
            for (i=0; i<m_multiport->count; i++)
            {
                if (sport == m_multiport->ports[i])
                {
                    return 1;
                }
            }
            return 0;
        case XT_MULTIPORT_DESTINATION:
            // Match destination port ?
            for (i=0; i<m_multiport->count; i++)
            {
                if (dport == m_multiport->ports[i])
                {
                    return 1;
                }
            }
            return 0;
        default:
            // Match both ports ?
            match_sport = 0;
            match_dport = 0;
            for (i=0; i<m_multiport->count; i++)
            {
                if (sport == m_multiport->ports[i])
                {
                    match_sport = 1;
                }
                if (dport == m_multiport->ports[i])
                {
                    match_dport = 1;
                }
            }
            return match_sport && match_dport;
    }
}

int match_icmp(struct ipt_entry_match *match, u_int8_t type, u_int8_t code)
{
    struct ipt_icmp *m_icmp;
    int inverse;
    int match_icmp;

    m_icmp = (struct ipt_icmp *)match->data;

    inverse = m_icmp->invflags & IPT_ICMP_INV;
    match_icmp = (m_icmp->type == type && code >= m_icmp->code[0] && code <= m_icmp->code[1]) || m_icmp->type == 0xFF;
    if (inverse)
    {
        match_icmp = !match_icmp;
    }
    return match_icmp;
}

int match_tcp(struct ipt_entry_match *match, u_int16_t sport, u_int16_t dport, u_int8_t flags)
{
    struct xt_tcp *m_tcp;
    int inverse;
    int match_flags, match_sport, match_dport;

    m_tcp = (struct xt_tcp *)match->data;

    inverse = m_tcp->invflags & XT_TCP_INV_FLAGS;
    if (inverse || m_tcp->flg_mask)
    {
        // Match the flags ?
        match_flags = (flags & m_tcp->flg_mask) == m_tcp->flg_cmp;
        if (inverse)
        {
            match_flags = !match_flags;
        }
        if (!match_flags)
        {
            return 0;
        }
    }

    // TCP OPTIONS NOT SUPPORTED YET !!!!!! TO DO !!!!
    inverse = m_tcp->invflags & XT_TCP_INV_OPTION;
    if (inverse || m_tcp->option)
    {
        // Match the tcp options?
    }

    inverse = m_tcp->invflags & XT_TCP_INV_SRCPT;
    if (inverse || m_tcp->spts[0] || m_tcp->spts[1] != 0xFFFF) 
    {
        // Match source port ?
        match_sport = sport >= m_tcp->spts[0] && sport <= m_tcp->spts[1];
        if (inverse)
        {
            match_sport = !match_sport;
        }
        if (!match_sport)
        {
            return 0;
        }
    }

    inverse = m_tcp->invflags & XT_TCP_INV_DSTPT;
    if (inverse || m_tcp->dpts[0] || m_tcp->dpts[1] != 0xFFFF) 
    {
        // Match destination port ?
        match_dport = dport >= m_tcp->dpts[0] && dport <= m_tcp->dpts[1];
        if (inverse)
        {
            match_dport = !match_dport;
        }
        if (!match_dport)
        {
            return 0;
        }
    }

    return 1;
}

int match_udp(struct ipt_entry_match *match, u_int16_t sport, u_int16_t dport)
{
    struct xt_udp *m_udp;
    int inverse;
    int match_sport, match_dport;

    m_udp = (struct xt_udp *)match->data;

    inverse = m_udp->invflags & XT_UDP_INV_SRCPT;
    if (inverse || m_udp->spts[0] || m_udp->spts[1] != 0xFFFF) 
    {
        // Match source port ?
        match_sport = sport >= m_udp->spts[0] && sport <= m_udp->spts[1];
        if (inverse)
        {
            match_sport = !match_sport;
        }
        if (!match_sport)
        {
            return 0;
        }
    }

    inverse = m_udp->invflags & XT_UDP_INV_DSTPT;
    if (inverse || m_udp->dpts[0] || m_udp->dpts[1] != 0xFFFF) 
    {
        // Match destination port ?
        match_dport = dport >= m_udp->dpts[0] && dport <= m_udp->dpts[1];
        if (inverse)
        {
            match_dport = !match_dport;
        }
        if (!match_dport)
        {
            return 0;
        }
    }

    return 1;
}

int match_physdev(struct ipt_entry_match *match, char *net_device)
{
    struct xt_physdev_info *m_physdev;
    int inverse;
    int match_physdev = 0;

    m_physdev = (struct xt_physdev_info *)match->data;

    inverse = m_physdev->invert & XT_PHYSDEV_OP_IN;
    if (m_physdev->bitmask & XT_PHYSDEV_OP_IN) 
    {
        match_physdev = !strcasecmp(net_device, m_physdev->physindev);
        if (inverse)
        {
            match_physdev = !match_physdev;
        }
        return match_physdev;
    }

    inverse = m_physdev->invert & XT_PHYSDEV_OP_ISOUT;
    if (m_physdev->bitmask & XT_PHYSDEV_OP_ISOUT) 
    {
        return 0;
    }
    inverse = m_physdev->invert & XT_PHYSDEV_OP_OUT;
    if (m_physdev->bitmask & XT_PHYSDEV_OP_OUT) 
    {
        return 0;
    }

    inverse = m_physdev->invert & XT_PHYSDEV_OP_ISIN;
    if (m_physdev->bitmask & XT_PHYSDEV_OP_ISIN) 
    {
        return -1;
    }

    return -1;
}

int match_conntrack(struct ipt_entry_match *match, int new_connection)
{
    //struct xt_conntrack_info *m_conntrack;
    struct xt_conntrack_mtinfo3 *m_conntrack;
    int inverse;
    int match_state = 0;

    //m_conntrack = (struct xt_conntrack_info *)match->data;
    m_conntrack = (struct xt_conntrack_mtinfo3 *)match->data;

    inverse = m_conntrack->invert_flags & XT_CONNTRACK_STATE;
	if (m_conntrack->match_flags & XT_CONNTRACK_STATE) 
    {
        // New connection 
        if (m_conntrack->state_mask & XT_CONNTRACK_STATE_BIT(IP_CT_NEW)) {
            match_state = match_state || new_connection;
        }

        // Related or Established connection
        if ((m_conntrack->state_mask & XT_CONNTRACK_STATE_BIT(IP_CT_RELATED)) ||
             m_conntrack->state_mask & XT_CONNTRACK_STATE_BIT(IP_CT_ESTABLISHED))
        {
            match_state = match_state || !new_connection;
        }

        if (inverse)
        {
            match_state = !match_state;
        }
        if (!match_state)
        {
            return 0;
        }
    }
    
	if (m_conntrack->match_flags & XT_CONNTRACK_PROTO) 
    {
        return -1;
	}

	if (m_conntrack->match_flags & XT_CONNTRACK_ORIGSRC) 
    {
        return -1;
	}

	if (m_conntrack->match_flags & XT_CONNTRACK_ORIGDST) 
    {
        return -1;
	}

	if (m_conntrack->match_flags & XT_CONNTRACK_REPLSRC) 
    {
        return -1;
	}

	if (m_conntrack->match_flags & XT_CONNTRACK_REPLDST) 
    {
        return -1;
	}

	if (m_conntrack->match_flags & XT_CONNTRACK_STATUS) 
    {
        return -1;
	}

	if (m_conntrack->match_flags & XT_CONNTRACK_EXPIRES) 
    {
        return -1;
	}

	if (m_conntrack->match_flags & XT_CONNTRACK_DIRECTION) 
    {
        return -1;
	}

    return 1;
}

int match_rule(char *net_device, uint8_t proto, uint32_t s_address, u_int16_t sport, uint32_t d_address, u_int16_t dport, 
               u_int8_t flags_type, u_int8_t code, int new_connection, const struct ipt_entry *entry)
{
    int inv_interface_in, inv_proto, inv_s_address, inv_d_address;
    int match_interface, match_proto, match_saddress, match_daddress;
    u_int16_t current_offset;
    struct ipt_entry_match *match;
    int processed_module;
   
    // process negated fields
    inv_interface_in = entry->ip.invflags & IPT_INV_VIA_IN;
    inv_proto = entry->ip.invflags & IPT_INV_PROTO;
    inv_s_address = entry->ip.invflags & IPT_INV_SRCIP;
    inv_d_address = entry->ip.invflags & IPT_INV_DSTIP;
    
    // Network interface match?
    match_interface = (entry->ip.iniface == NULL || !strcmp(entry->ip.iniface, ""))  || 
                      !strcasecmp(net_device, entry->ip.iniface);
    if (inv_interface_in)
    {
        match_interface = !match_interface;
    }
    if (!match_interface)
    {
        return 0;
    }

    // Match protocol ?
    match_proto = entry->ip.proto == IPPROTO_IP || proto == entry->ip.proto;
    if (inv_proto)
    {
        match_proto = !match_proto;
    }
    if (!match_proto)
    {
        return 0;
    }

    // Match source address ?
    match_saddress = (s_address & entry->ip.smsk.s_addr) == entry->ip.src.s_addr;
    if (inv_s_address)
    {
        match_saddress = !match_saddress;
    }
    if (!match_saddress)
    {
        return 0;
    }

    // Match destination address ?
    match_daddress = (d_address & entry->ip.dmsk.s_addr) == entry->ip.dst.s_addr;
    if (inv_d_address)
    {
        match_daddress = !match_daddress;
    }
    if (!match_daddress)
    {
        return 0;
    }

    // Are there match extensions in the rule?
    match = (struct ipt_entry_match *)entry->elems;
    current_offset = 0;
    while (strcmp(match->u.user.name, ""))
    {
        processed_module = 0;
        if (!strcasecmp(match->u.user.name, "multiport"))
        {
            if (!match_multiport(match, sport, dport))
            {
                return 0;
            }
            processed_module = 1;
        }
        if (!strcasecmp(match->u.user.name, "icmp"))
        {
            if (!match_icmp(match, flags_type, code))
            {
                return 0;
            }
            processed_module = 1;
        }
        if (!strcasecmp(match->u.user.name, "tcp"))
        {
            if (!match_tcp(match, sport, dport, flags_type))
            {
                return 0;
            }
            processed_module = 1;
        }
        if (!strcasecmp(match->u.user.name, "udp"))
        {
            if (!match_udp(match, sport, dport))
            {
                return 0;
            }
            processed_module = 1;
        }
        if (!strcasecmp(match->u.user.name, "physdev"))
        {
            if (!match_physdev(match, net_device))
            {
                return 0;
            }
            processed_module = 1;
        }
        if (!strcasecmp(match->u.user.name, "conntrack"))
        {
            if (!match_conntrack(match, new_connection))
            {
                return 0;
            }
            processed_module = 1;
        }
        if (!strcasecmp(match->u.user.name, "log") || !(strcasecmp(match->u.user.name, "reject")))
        {
            processed_module = 1;
        }
        if (!processed_module)
        {
            // Module not supported
            return -1;
        }
        
        current_offset += match->u.match_size;
        match = (struct ipt_entry_match *)(entry->elems+current_offset);
    }
    return 1;
}

int actionIncoming(char *net_device, uint8_t proto, uint32_t s_address, u_int16_t sport, uint32_t d_address, u_int16_t dport, 
                   u_int8_t flags_type, u_int8_t code, int new_connection, const char *chain_name)
{
    struct xtc_handle *p;
    const struct ipt_entry *entry;
    const char *target;
    int matched;
    FILE *f;
	char s_ip_src[INET_ADDRSTRLEN], s_ip_dst[INET_ADDRSTRLEN];

    // Initialization
    p = iptc_init("filter");
    if (p == NULL) {
        fprintf(stderr, "Can't initialize: %s\n", iptc_strerror(errno));
        exit(EXIT_FAILURE);
    }

    f = fopen("iptables.log", "at");

    // Iterate all rules in chain
    entry = iptc_first_rule(chain_name, p);
    while (entry != NULL) {
        // Rule match ?
        matched = match_rule(net_device, proto, s_address, sport, d_address, dport, flags_type, code, new_connection, entry);
        if (matched == -1)
        {
            // A not supported rule was found
            inet_ntop(AF_INET, &(s_address), s_ip_src, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(d_address), s_ip_dst, INET_ADDRSTRLEN);
            fprintf(f, "Error al validar conexión: Dev: %s  Proto: %d  SAddr: %s  SPort: %0u  DAddr: %s  DPort: %0u  Flags_TCP/ICMP_Type: %0u  ICMP_Code: %0u  New: %0d\n",
                    net_device, proto, s_ip_src, sport, s_ip_dst, dport, flags_type, code, new_connection);
            fclose(f);
            return -1;
        }
        // A match rule has been founded?
        if (matched)
        {
            // Get the target of this rule
            target = iptc_get_target(entry, p);
            // Is it a chain?
            if (iptc_is_chain(target, p))
            {
                // Yes
                matched = actionIncoming(net_device, proto, s_address, sport, d_address, dport, flags_type, code, new_connection, target);
                if (matched)
                {
                    return matched;
                }
            }
            else
            {
                // Target is not a chain
                if (!strcasecmp(target, "RETURN"))
                {
                    return 0;
                }
                if (!strcasecmp(target, "ACCEPT"))
                {
                    return 1;
                }
                if (!strcasecmp(target, "DROP"))                
                {
                    if (!strcasecmp(chain_name, BLACKLIST_CHAIN))
                    {
                        return 4;
                    }
                    return 2;
                }
                if (!strcasecmp(target, "REJECT"))
                {
                    if (!strcasecmp(chain_name, BLACKLIST_CHAIN))
                    {
                        return 4;
                    }
                    return 3;
                }
            }
        }

        // Next rule
        entry = iptc_next_rule(entry, p);
    }

    // Not matched rule found
    if (!strcasecmp(chain_name, "INPUT"))
    {
        struct ipt_counters counters;
        const char *default_target;

        default_target = iptc_get_policy("INPUT", &counters, p);
        if (!strcasecmp(default_target, "ACCEPT"))
        {
            return 1;
        }
        if (!strcasecmp(default_target, "DROP"))                
        {
            return 2;
        }
        if (!strcasecmp(default_target, "REJECT"))
        {
            return 3;
        }
        return -1;
}
    return 0;
}