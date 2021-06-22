#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <netinet/ip.h>

#include <Configuration.h>
#include <misc.h>
#include <debug.h>

// Function prototypes
void processServiceConfig(dictionary *d, char *filename);
void processServiceLine(dictionary d, char *filename, char *line, unsigned n_line);
void processHostConfig(sorted_list *l, char *filename);
void processHostLine(sorted_list l, char *filename, char *line, unsigned n_line);
void processServiceAlias(dictionary *d, char *filename);
void processLineAlias(dictionary d, char *filename, char *line, unsigned n_line);
int compareService(void *val1,  void *val2);
int compareServicePort(struct value_dict *info1, struct value_dict *info2);
int compareAddress(void *val1,  void *val2);
int compareAddress2(void *val1, void *val2);
int compareServiceAlias(struct value_dict *info1, struct value_dict *info2);
int config_PortInRange(struct value_dict *info1, struct value_dict *info2);
int config_PortInRangeAlias(struct value_dict *info1, struct value_dict *info2);


// EXTERNAL Global vars
#ifdef DEBUG
extern struct const_global_vars c_globvars;
extern struct write_global_vars w_globvars;
#endif

// Global vars
dictionary incoming_services_allow;
dictionary incoming_services_warning;
dictionary incoming_services_alert;
dictionary incoming_services_deny;
dictionary outgoing_services_allow;
dictionary outgoing_services_warning;
dictionary outgoing_services_alert;
dictionary outgoing_services_deny;
sorted_list outgoing_hosts_allow;
sorted_list outgoing_hosts_warning;
sorted_list outgoing_hosts_alert;
sorted_list outgoing_hosts_deny;
dictionary services_alias;


void Configuration() {
	processServiceConfig(&incoming_services_allow, "incoming_services_whitelist.txt");
	processServiceConfig(&incoming_services_warning, "incoming_services_warning.txt");
	processServiceConfig(&incoming_services_alert, "incoming_services_alert.txt");
	processServiceConfig(&incoming_services_deny, "incoming_services_blacklist.txt");
	processServiceConfig(&outgoing_services_allow, "outgoing_services_whitelist.txt");
	processServiceConfig(&outgoing_services_warning, "outgoing_services_warning.txt");
	processServiceConfig(&outgoing_services_alert, "outgoing_services_alert.txt");
	processServiceConfig(&outgoing_services_deny, "outgoing_services_blacklist.txt");

	processHostConfig(&outgoing_hosts_allow, "outgoing_hosts_allow.txt");
	processHostConfig(&outgoing_hosts_warning, "outgoing_hosts_warning.txt");
	processHostConfig(&outgoing_hosts_alert, "outgoing_hosts_alert.txt");
	processHostConfig(&outgoing_hosts_deny, "outgoing_hosts_deny.txt");

	processServiceAlias(&services_alias, "services_alias.txt");

#ifdef DEBUG
    c_globvars.cont_is_allow = size_dict(incoming_services_allow);
    c_globvars.cont__is_warning = size_dict(incoming_services_warning);
    c_globvars.cont_is_alert = size_dict(incoming_services_alert);
    c_globvars.cont_is_deny = size_dict(incoming_services_deny);
    c_globvars.cont_os_allow = size_dict(outgoing_services_allow);
    c_globvars.cont_os_warning = size_dict(outgoing_services_warning);
    c_globvars.cont_os_alert = size_dict(outgoing_services_alert);
    c_globvars.cont_os_deny = size_dict(outgoing_services_deny);
    c_globvars.cont_oh_allow = size_sorted_list(outgoing_hosts_allow);
    c_globvars.cont_oh_warning = size_sorted_list(outgoing_hosts_warning);
    c_globvars.cont_oh_alert = size_sorted_list(outgoing_hosts_alert);
    c_globvars.cont_oh_deny = size_sorted_list(outgoing_hosts_deny);
    c_globvars.cont_services_alias = size_dict(services_alias);
#endif
}

int incoming_packetAllowed(unsigned protocol, unsigned port) {
	struct ports_range info;

	info.lower = port;
	info.upper = port;

	if (find_dict(incoming_services_deny, (void *)&protocol, (void *)&info, config_PortInRange) != NULL) 
	{
		// Service found in black list. Do not process it!
		return 0;
	}

	if (find_dict(incoming_services_alert, (void *)&protocol, (void *)&info, config_PortInRange) != NULL) 
	{
		return 3;
	}

	if (find_dict(incoming_services_warning, (void *)&protocol, (void *)&info, config_PortInRange) != NULL)
	{
		return 2;
	}

	if (find_dict(incoming_services_allow, (void *)&protocol, (void *)&info, config_PortInRange) != NULL)
	{
		return 1;
	}

	return 0;
}

int outgoing_packetAllowed(struct in_addr address, unsigned protocol, unsigned port, int no_tcp_udp) {
	struct ports_range info;
	int priority_address=0, priority_service=0;

	info.lower = port;
	info.upper = port;
	
	// Check if source address is allowed
	if (find_sorted_list(outgoing_hosts_deny, (void *)&address, compareAddress2) != NULL) 
	{
		// Address found in black list. Do not process it!
		return 0;
	}
	if (find_sorted_list(outgoing_hosts_alert, (void *)&address, compareAddress2) != NULL) 
	{
		priority_address = 3;
	}

	if (find_sorted_list(outgoing_hosts_warning, (void *)&address, compareAddress2) != NULL)
	{
		priority_address = 2;
	}

	if (find_sorted_list(outgoing_hosts_allow, (void *)&address, compareAddress2) != NULL)
	{
		priority_address = 1;
	}

	
	if (no_tcp_udp) {
		return priority_address;
	}
	

	// Check if service is allowed
	if (find_dict(outgoing_services_deny, (void *)&protocol, (void *)&info, config_PortInRange) != NULL) 
	{
		// Service found in black list. Do not process it!
		return 0;
	}

	if (find_dict(outgoing_services_alert, (void *)&protocol, (void *)&info, config_PortInRange) != NULL) 
	{
		priority_service = 3;
	}

	if (find_dict(outgoing_services_warning, (void *)&protocol, (void *)&info, config_PortInRange) != NULL)
	{
		priority_service = 2;
	}

	if (find_dict(outgoing_services_allow, (void *)&protocol, (void *)&info, config_PortInRange) != NULL)
	{
		priority_service = 1;
	}

	if (!priority_address || !priority_service) {
		return 0;
	}
	else {
		return max(priority_address, priority_service);
	}
}

char *serviceAlias(unsigned protocol, unsigned port) {
	struct node_sorted_list *node;
	struct info_alias info;
	struct info_alias *result_info;
	struct value_dict *pair;

	info.lower = port;
	info.upper = port;
	info.alias = NULL;

	node = find_dict(services_alias, (void *)&protocol, (void *)&info, config_PortInRangeAlias);

	if (node == NULL) {
		return NULL;
	}
	else {		
		pair = (struct value_dict *)node->info;
		result_info = (struct info_alias *)pair->value;
		return result_info->alias;
	}
}

char *serviceShortAlias(unsigned protocol, unsigned port) {
	struct node_sorted_list *node;
	struct info_alias info;
	struct info_alias *result_info;
	struct value_dict *pair;

	info.lower = port;
	info.upper = port;
	info.alias = NULL;

	node = find_dict(services_alias, (void *)&protocol, (void *)&info, config_PortInRangeAlias);

	if (node == NULL) {
		return NULL;
	}
	else {		
		pair = (struct value_dict *)node->info;
		result_info = (struct info_alias *)pair->value;
		return result_info->short_alias;
	}
}

void processServiceConfig(dictionary *d, char *filename) {
	FILE *fe;
	char line[100];
	unsigned n_line = 0;

	init_dict(d, compareServicePort, compareService);
#ifdef DEBUG
	w_globvars.allocated_config += sizeof(struct info_dict) + sizeof(struct info_sorted_list);
#endif

	fe = fopen(filename, "rt");

	if (fe == NULL) {
		return;
	}

	while (fgets(line, sizeof(line)-1, fe) != NULL) {
		n_line++;
		processServiceLine(*d, filename, line, n_line);
	}

	fclose(fe);
}

void processServiceLine(dictionary d, char *filename, char *line, unsigned n_line) {
	char *seps = "\t ";
	char *delim1 = "/";
	char *delim2 = ":";
	char *s_protocol, *ports_range, *port;
	int protocol;
	unsigned *key;
	int low_port, upper_port;
	struct ports_range *info;

	line = ltrim(line, NULL);
	line = rtrim(line, NULL);

	if (!strcmp(line, "")) {
		// Empty line
		return;
	}

	// Is It a comment?
	if (line[0] == '#') {
		// Comment line
		return;
	}

	// Only one word??
	if (strtok(line, seps) != NULL && strtok(NULL, seps) != NULL) {
		fprintf(stderr, "Bad config file (%s) at line %u: Must be only one word\n", filename, n_line);
		exit(1);
	}

	// Extract Protocol
	s_protocol = strtok(line, delim1);
	if (s_protocol == NULL) {
		fprintf(stderr, "Bad config file (%s) at line %u: Couldn't get protocol\n", filename, n_line);
		exit(1);		
	}
	if (isdigit(s_protocol[0])) {
		// Protocol nnumber
		if (sscanf(s_protocol, "%d", &protocol) != 1) {
			fprintf(stderr, "Bad config file (%s) at line %u: Protocol number must be unsigned int\n", filename, n_line);
			exit(1);					
		}
		if (protocol <=0 || protocol > 255) {
			fprintf(stderr, "Bad config file (%s) at line %u: Protocol number must be between 1 and 255\n", filename, n_line);
			exit(1);								
		}
	}
	else {
		// Protocol by name
		if (!strcmp(s_protocol, "tcp")) {
			protocol = IPPROTO_TCP;		
		}
		else {
			if (!strcmp(s_protocol, "udp")) {
				protocol = IPPROTO_UDP;
			}
			else {
				fprintf(stderr, "Bad config file (%s) at line %u: Protocol name is not valid\n", filename, n_line);
				exit(1);												
			}
		}
	}

	// Extract ports range
	ports_range = strtok(NULL, delim1);
	if (ports_range == NULL) {
		fprintf(stderr, "Bad config file (%s) at line %u: Couldn't get port range\n", filename, n_line);
		exit(1);		
	}

	// No more tokens?
	if (strtok(NULL, delim1) != NULL) {
		fprintf(stderr, "Bad config file (%s) at line %u\n", filename, n_line);
		exit(1);		
	}

	// Single port or range port?
	port = strtok(ports_range, delim2);
	if (sscanf(port, "%d", &low_port) != 1) {
		fprintf(stderr, "Bad config file (%s) at line %u: Couldn't get single port\n", filename, n_line);
		exit(1);					
	}
	port = strtok(NULL, delim2);
	if (port == NULL) {
		// Single port
		upper_port = low_port;
	}
	else {
		// Range port
		if (sscanf(port, "%d", &upper_port) != 1) {
			fprintf(stderr, "Bad config file (%s) at line %u: Upper port must be unsigned int\n", filename, n_line);
			exit(1);					
		}
		if (upper_port <=0 || upper_port > 65535) {
			fprintf(stderr, "Bad config file (%s) at line %u: Upper port must be between 1 and 65535\n", filename, n_line);
			exit(1);								
		}
		if (upper_port <= low_port) {
			fprintf(stderr, "Bad config file (%s) at line %u: Upper port must be greater than lower port\n", filename, n_line);
			exit(1);								
		}
	}

	key = (unsigned *) malloc(sizeof(unsigned));
	if (key == NULL)
	{
		fprintf(stderr,"processServiceLine: Could not allocate memory for key!!\n");
		exit(1);		
	}
#ifdef DEBUG
	w_globvars.allocated_config += sizeof(unsigned);
#endif

	info = (struct ports_range *) malloc(sizeof(struct ports_range));
	if (info == NULL)
	{
		fprintf(stderr,"processServiceLine: Could not allocate memory for value!!\n");
		exit(1);		
	}
#ifdef DEBUG
	w_globvars.allocated_config += sizeof(struct ports_range);
#endif

	*key = protocol;
	info->lower = (unsigned) low_port;
	info->upper = (unsigned) upper_port;

	insert_dict(d, (void *)key, (void *)info);
#ifdef DEBUG
	w_globvars.allocated_config += sizeof(struct value_dict) + sizeof(struct node_sorted_list);
#endif
}

void processHostConfig(sorted_list *l, char *filename) {
	FILE *fe;
	char line[100];
	unsigned n_line = 0;

	init_sorted_list(l, compareAddress);
#ifdef DEBUG
	w_globvars.allocated_config += sizeof(struct info_sorted_list);
#endif

	fe = fopen(filename, "rt");

	if (fe == NULL) {
		return;
	}

	while (fgets(line, sizeof(line)-1, fe) != NULL) {
		n_line++;
		processHostLine(*l, filename, line, n_line);
	}

	fclose(fe);
}

void processHostLine(sorted_list l, char *filename, char *line, unsigned n_line) {
	char *seps = "\t ";
	char *delim1 = "/";
	char *delim2 = ".";
	char *s_address, s_address_aux[100], *s_mask, *s_byte;
	unsigned i, cont_byte, byte;
	struct address_mask *info;
	struct in_addr address_aux;
	in_addr_t mask;
	 

	line = ltrim(line, NULL);
	line = rtrim(line, NULL);

	if (!strcmp(line, "")) {
		// Empty line
		return;
	}

	// Is It a comment?
	if (line[0] == '#') {
		// Comment line
		return;
	}

	// Only one word??
	if (strtok(line, seps) != NULL && strtok(NULL, seps) != NULL) {
		fprintf(stderr, "Bad config file (%s) at line %u: Must be only one word\n", filename, n_line);
		exit(1);
	}

	// Extract Address
	s_address = strtok(line, delim1);

	// Mask?
	s_mask = strtok(NULL, delim1);
	if (s_mask != NULL) {
		// More tokens ?
		if (strtok(NULL, delim1) != NULL) {
			fprintf(stderr, "Bad config file (%s) at line %u: Bad IP address (%s)\n", filename, n_line, line);
			exit(1);
		}
	}

	// Check address format
	strcpy(s_address_aux, s_address);
	cont_byte = 0;
	s_byte = strtok(s_address_aux, delim2);
	while (s_byte != NULL && cont_byte < 4) {
		cont_byte++;
		for (i=0; i<strlen(s_byte); i++) {
			if (!isdigit(s_byte[i])) {
				fprintf(stderr, "Bad config file (%s) at line %u: Bad IP address (%s)\n", filename, n_line, s_address);
				exit(1);		
			}
		}
		if (sscanf(s_byte, "%u", &byte) != 1 || byte > 255) {
			fprintf(stderr, "Bad config file (%s) at line %u: Bad IP address (%s)\n", filename, n_line, s_address);
			exit(1);		
		}
		s_byte = strtok(NULL, delim2);
	}
	if (s_byte != NULL || cont_byte != 4) {
		fprintf(stderr, "Bad config file (%s) at line %u: Bad IP address (%s)\n", filename, n_line, s_address);
		exit(1);		
	}
	if (s_address[strlen(s_address)-1] == '.') {
		fprintf(stderr, "Bad config file (%s) at line %u: Bad IP address (%s)\n", filename, n_line, s_address);
		exit(1);		
	}

	// Check mask
	if (s_mask != NULL) {
		for (i=0; i<strlen(s_mask); i++) {
			if (!isdigit(s_mask[i])) {
				fprintf(stderr, "Bad config file (%s) at line %u: Bad Mask address (%s)\n", filename, n_line, s_mask);
				exit(1);		
			}
		}
		if (sscanf(s_mask, "%u", &byte) != 1 || byte > 32) {
			fprintf(stderr, "Bad config file (%s) at line %u: Bad Mask address (%s)\n", filename, n_line, s_mask);
			exit(1);		
		}
		if (byte != 32) {
			// Check network address. Host part of the address must be zero
			inet_pton(AF_INET, s_address, &address_aux);
			mask = 0xFFFFFFFF;
			mask = mask >> byte;
			if (ntohl(address_aux.s_addr) & mask) {
				fprintf(stderr, "Bad config file (%s) at line %u: Bad network address (%s/%s)\n", filename, n_line, s_address, s_mask);
				exit(1);		
			}
		}
	}

	// Save address/mask
	info = (struct address_mask *) malloc(sizeof(struct address_mask));
	if (info == NULL)
	{
		fprintf(stderr,"processHostLine: Could not allocate memory for value!!\n");
		exit(1);		
	}
#ifdef DEBUG
	w_globvars.allocated_config += sizeof(struct address_mask);
#endif
	inet_pton(AF_INET, s_address, &info->address);
	if (s_mask != NULL) {
		info->mask = byte;
	}
	else {
		info->mask = 32;
	}
	insert_sorted_list(l, info);
#ifdef DEBUG
	w_globvars.allocated_config += sizeof(struct node_sorted_list);
#endif
}

void processServiceAlias(dictionary *d, char *filename) {
	FILE *fe;
	char line[200];
	unsigned n_line = 0;

	init_dict(d, compareServiceAlias, compareService);
#ifdef DEBUG
	w_globvars.allocated_config += sizeof(struct info_dict) + sizeof(struct info_sorted_list);
#endif

	fe = fopen(filename, "rt");

	if (fe == NULL) {
		return;
	}

	while (fgets(line, sizeof(line)-1, fe) != NULL) {
		n_line++;
		processLineAlias(*d, filename, line, n_line);
	}

	fclose(fe);
}


void processLineAlias(dictionary d, char *filename, char *line, unsigned n_line) {
	char *delim1 = "/";
	char *delim2 = ":";
	char *s_protocol, *ports_range, *port;
	char *p, short_alias[200] = "", alias[200], line_backup[200];
	int protocol;
	unsigned *key;
	unsigned pos;
	int low_port, upper_port;
	struct info_alias *info;

	line = ltrim(line, NULL);
	line = rtrim(line, NULL);

	if (!strcmp(line, "")) {
		// Empty line
		return;
	}

	// Is It a comment?
	if (line[0] == '#') {
		// Comment line
		return;
	}

	strcpy(line_backup, line);

	// Extract Protocol
	s_protocol = strtok(line, delim1);
	if (s_protocol == NULL) {
		fprintf(stderr, "Bad config file (%s) at line %u: Couldn't get protocol\n", filename, n_line);
		exit(1);		
	}
	if (isdigit(s_protocol[0])) {
		// Protocol nnumber
		if (sscanf(s_protocol, "%d", &protocol) != 1) {
			fprintf(stderr, "Bad config file (%s) at line %u: Protocol number must be unsigned int\n", filename, n_line);
			exit(1);					
		}
		if (protocol <=0 || protocol > 255) {
			fprintf(stderr, "Bad config file (%s) at line %u: Protocol number must be between 1 and 255\n", filename, n_line);
			exit(1);								
		}
	}
	else {
		// Protocol by name
		if (!strcmp(s_protocol, "tcp")) {
			protocol = IPPROTO_TCP;		
		}
		else {
			if (!strcmp(s_protocol, "udp")) {
				protocol = IPPROTO_UDP;
			}
			else {
				fprintf(stderr, "Bad config file (%s) at line %u: Protocol name is not valid\n", filename, n_line);
				exit(1);												
			}
		}
	}

	// Extract ports range
	ports_range = strtok(NULL, delim1);
	if (ports_range == NULL) {
		fprintf(stderr, "Bad config file (%s) at line %u: Couldn't get port range\n", filename, n_line);
		exit(1);		
	}

	// No more tokens?
	if (strtok(NULL, delim1) != NULL) {
		fprintf(stderr, "Bad config file (%s) at line %u\n", filename, n_line);
		exit(1);		
	}

	// Single port or range port?
	port = strtok(ports_range, delim2);
	if (sscanf(port, "%d", &low_port) != 1) {
		fprintf(stderr, "Bad config file (%s) at line %u: Couldn't get single port\n", filename, n_line);
		exit(1);					
	}
	port = strtok(NULL, delim2);
	if (port == NULL) {
		// Single port
		upper_port = low_port;
	}
	else {
		// Range port
		if (sscanf(port, "%d", &upper_port) != 1) {
			fprintf(stderr, "Bad config file (%s) at line %u: Upper port must be unsigned int\n", filename, n_line);
			exit(1);					
		}
		if (upper_port <=0 || upper_port > 65535) {
			fprintf(stderr, "Bad config file (%s) at line %u: Upper port must be between 1 and 65535\n", filename, n_line);
			exit(1);								
		}
		if (upper_port <= low_port) {
			fprintf(stderr, "Bad config file (%s) at line %u: Upper port must be greater than lower port\n", filename, n_line);
			exit(1);								
		}
	}

	// Move to begin of alias
	p = strchr(line_backup, '"');
	if (p == NULL) {
		fprintf(stderr, "Bad config file (%s) at line %u: Couldn't get alias\n", filename, n_line);
		exit(1);				
	}


	// Get alias characters until quotes reached
	pos = 0;
	p++;
	while(p[0] && p[0] != '"') {
		alias[pos] = p[0];
		pos++;
		p++;
	}
	if (!p[0]) {
		fprintf(stderr, "Bad config file (%s) at line %u: Alias final quotes missed\n", filename, n_line);
		exit(1);				
	}
	alias[pos] = '\0';

	//  Try to move to begin of short alias
	p = strchr(p+1, '"');
	if (p != NULL) {
		// Get short alias characters until quotes reached
		pos = 0;
		p++;
		while(p[0] && p[0] != '"') {
			short_alias[pos] = p[0];
			pos++;
			p++;
		}
		if (!p[0]) {
			fprintf(stderr, "Bad config file (%s) at line %u: Short alias final quotes missed\n", filename, n_line);
			exit(1);				
		}
		short_alias[pos] = '\0';
	}

	key = (unsigned *) malloc(sizeof(unsigned));
	if (key == NULL)
	{
		fprintf(stderr,"processLineAlias: Could not allocate memory for key!!\n");
		exit(1);		
	}
#ifdef DEBUG
	w_globvars.allocated_config += sizeof(unsigned);
#endif
	info = (struct info_alias *) malloc(sizeof(struct info_alias));
	if (info == NULL)
	{
		fprintf(stderr,"processLineAlias: Could not allocate memory for port value!!\n");
		exit(1);		
	}
#ifdef DEBUG
	w_globvars.allocated_config += sizeof(struct info_alias);
#endif
	info->alias = (char *) malloc(strlen(alias)+1);
	if (info->alias == NULL) {
		fprintf(stderr,"processLineAlias: Could not allocate memory for alias!!\n");
		exit(1);				
	}
#ifdef DEBUG
	w_globvars.allocated_config += strlen(alias)+1;
#endif
	info->short_alias = malloc(strlen(short_alias)+1);
	if (info->short_alias == NULL) {
		fprintf(stderr,"processLineAlias: Could not allocate memory for short alias!!\n");
		exit(1);				
	}
#ifdef DEBUG
	w_globvars.allocated_config += strlen(short_alias)+1;
#endif

	*key = protocol;
	info->lower = (unsigned) low_port;
	info->upper = (unsigned) upper_port;
	strcpy(info->alias, alias);
	strcpy(info->short_alias, short_alias);


	insert_dict(d, (void *)key, (void *)info);
#ifdef DEBUG
	w_globvars.allocated_config += sizeof(struct value_dict) + sizeof(struct node_sorted_list);
#endif
}

int compareService(void *val1,  void *val2) {
    struct value_dict *info1, *info2;
    unsigned key1, key2;

    info1 = (struct value_dict *)val1;
    info2 = (struct value_dict *)val2;

    key1 = *(unsigned *)(info1->key);
    key2 = *(unsigned *)(info2->key);

    if (key1 < key2) {
    	return -1;    	
    }
    else {
    	if (key1 == key2) {
    		return 0;
    	}
    	else {
    		return 1;
    	}
    }
}

int compareServicePort(struct value_dict *info1,  struct value_dict *info2) {
    unsigned key1, key2;
    struct ports_range *value1, *value2;

    key1 = *(unsigned *)(info1->key);
    key2 = *(unsigned *)(info2->key);
	value1 = (struct ports_range *)(info1->value);
	value2 = (struct ports_range *)(info2->value);

	if (key1 < key2) {
		return -1;
	}
	else {
		if (key1 > key2) {
			return 1;
		}
	}

	// Keys are equal. Checking values
	if (value1->lower == value2->lower && value1->upper == value2->upper) {
		return 0;
	}
	else {
		if (value1->upper < value2->lower)
		{
			return -1;
		}
		else {
			return 1;
		}
	}
}

int compareAddress(void *val1,  void *val2) {
	struct address_mask *value1, *value2;
	in_addr_t address1, address2;

	value1 = (struct address_mask *)val1;
	value2 = (struct address_mask *)val2;

	// Get address1 
	address1 = ntohl(value1->address.s_addr);
	// Get address2
	address2 = ntohl(value2->address.s_addr);

	// Addresses are in decremental ordering
	// First hosts, then general networks
	if (address1 > address2) {
		return -1;
	}
	else {
		if (address1 < address2) {
			return 1;
		}
		else {
			return 0;
		}
	}
}

int compareAddress2(void *val1,  void *val2) {
	struct in_addr *in_address1;
	struct address_mask *value2;
	in_addr_t address1, address2, mask;
	unsigned mask_bits;

	in_address1 = (struct in_addr *)val1;
	value2 = (struct address_mask *)val2;

	// Get address1 in decimal format
	address1 = ntohl(in_address1->s_addr);

	// Get address2 in decimal format
	address2 = ntohl(value2->address.s_addr);

	// Is address2 a network address?
	if (value2->mask != 32) {
		// address2 is network address
		// Extract network address of address1
		mask = 0xFFFFFFFF;
		mask_bits = 32 - value2->mask;
		mask = mask << mask_bits;
		address1 = address1 & mask;
	}	

	if (address1 > address2) {
		return -1;
	}
	else {
		if (address1 < address2) {
			return 1;
		}
		else {
			return 0;
		}
	}	
}

int compareServiceAlias(struct value_dict *info1, struct value_dict *info2) {
    unsigned key1, key2;
    struct info_alias *value1, *value2;

    key1 = *(unsigned *)(info1->key);
    key2 = *(unsigned *)(info2->key);
	value1 = (struct info_alias *)(info1->value);
	value2 = (struct info_alias *)(info2->value);

	if (key1 < key2) {
		return -1;
	}
	else {
		if (key1 > key2) {
			return 1;
		}
	}

	// Keys are equal. Checking values
	if (value1->lower == value2->lower && value1->upper == value2->upper && !strcmp(value1->alias, value2->alias)) {
		return 0;
	}
	else {
		if (value1->upper < value2->lower)
		{
			return -1;
		}
		else {
			return 1;
		}
	}
}

int config_PortInRange(struct value_dict *info1, struct value_dict *info2) {
    unsigned key1, key2;
    struct ports_range *value1, *value2;

    key1 = *(unsigned *)(info1->key);
    key2 = *(unsigned *)(info2->key);
	value1 = (struct ports_range *)(info1->value);
	value2 = (struct ports_range *)(info2->value);

	if (key1 < key2) {
		return -1;
	}
	else {
		if (key1 > key2) {
			return 1;
		}
		else {
			if (value1->lower >= value2->lower && value1->lower <= value2->upper) {
				return 0;
			}
			else {
				return 1;
			}
		}
	}
}

int config_PortInRangeAlias(struct value_dict *info1, struct value_dict *info2) {
    unsigned key1, key2;
    struct info_alias *value1, *value2;

    key1 = *(unsigned *)(info1->key);
    key2 = *(unsigned *)(info2->key);
	value1 = (struct info_alias *)(info1->value);
	value2 = (struct info_alias *)(info2->value);

	if (key1 < key2) {
		return -1;
	}
	else {
		if (key1 > key2) {
			return 1;
		}
		else {
			if (value1->lower >= value2->lower && value1->lower <= value2->upper) {
				return 0;
			}
			else {
				return 1;
			}
		}
	}
}
