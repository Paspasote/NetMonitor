#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <netinet/ip.h>

#include <Configuration.h>
#include <debug.h>

// Function prototypes
void ProcessServiceConfig(dictionary *d, char *filename);
void ProcessLine(dictionary d, char *filename, char *line, unsigned n_line);
void ProcessServiceAlias(dictionary *d, char *filename);
void ProcessLineAlias(dictionary d, char *filename, char *line, unsigned n_line);
int compareService(void *val1,  void *val2);
int compareServicePort(void *val1,  void *val2);
int compareServiceAlias(void *val1,  void *val2);
int Config_PortInRange(void *val1, void *val2);
int Config_PortInRangeAlias(void *val1, void *val2);
char *ltrim(char *str, const char *seps);
char *rtrim(char *str, const char *seps);

/********************************* DEBUG *******************
void printPairPortDic(void *v_pair, void *param);
/***********************************************************/


// Global vars
dictionary services_allow;
dictionary services_warning;
dictionary services_alert;
dictionary services_deny;
dictionary services_alias;

void Configuration() {
	ProcessServiceConfig(&services_allow, "services_whitelist.txt");
	ProcessServiceConfig(&services_warning, "services_warning.txt");
	ProcessServiceConfig(&services_alert, "services_alert.txt");
	ProcessServiceConfig(&services_deny, "services_blacklist.txt");

	ProcessServiceAlias(&services_alias, "services_alias.txt");

	/******************* DEBUG **********************************
	printConfDict(services_allow);
	/************************************************************/
}

int packetAllowed(unsigned protocol, unsigned port) {
	struct ports_range info;

	info.lower = port;
	info.upper = port;

	if (find_dict(services_deny, (void *)&protocol, (void *)&info, Config_PortInRange) != NULL) 
	{
		// Service found in black list. Do not process it!
		return 0;
	}

	if (find_dict(services_alert, (void *)&protocol, (void *)&info, Config_PortInRange) != NULL) 
	{
		return 3;
	}

	if (find_dict(services_warning, (void *)&protocol, (void *)&info, Config_PortInRange) != NULL)
	{
		return 2;
	}

	if (find_dict(services_allow, (void *)&protocol, (void *)&info, Config_PortInRange) != NULL)
	{
		return 1;
	}

	return 0;
}

char *serviceAlias(unsigned protocol, unsigned port) {
	struct node_sorted_list *node;
	struct info_alias info;
	struct info_alias *result_info;
	struct value_dict *pair;

	info.lower = port;
	info.upper = port;
	info.alias = NULL;

	node = find_dict(services_alias, (void *)&protocol, (void *)&info, Config_PortInRangeAlias);

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

	node = find_dict(services_alias, (void *)&protocol, (void *)&info, Config_PortInRangeAlias);

	if (node == NULL) {
		return NULL;
	}
	else {		
		pair = (struct value_dict *)node->info;
		result_info = (struct info_alias *)pair->value;
		return result_info->short_alias;
	}
}

void ProcessServiceConfig(dictionary *d, char *filename) {
	FILE *fe;
	char line[100];
	unsigned n_line = 0;

	init_dict(d, compareServicePort, compareService);

	fe = fopen(filename, "rt");

	if (fe == NULL) {
		return;
	}

	while (fgets(line, sizeof(line)-1, fe) != NULL) {
		n_line++;
		ProcessLine(*d, filename, line, n_line);
	}

	fclose(fe);
}

void ProcessLine(dictionary d, char *filename, char *line, unsigned n_line) {
	char *seps = "\t ";
	char *delim1 = "/";
	char *delim2 = ":";
	char *s_protocol, *ports_range, *port;
	unsigned protocol;
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
	if (strtok(line, seps) == NULL && strtok(NULL, seps) != NULL) {
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

	key = malloc(sizeof(unsigned));
	if (key == NULL)
	{
		fprintf(stderr,"ProcessLine: Could not allocate memory for key!!\n");
		exit(1);		
	}
	info = malloc(sizeof(struct ports_range));
	if (info == NULL)
	{
		fprintf(stderr,"ProcessLine: Could not allocate memory for value!!\n");
		exit(1);		
	}

	*key = protocol;
	info->lower = (unsigned) low_port;
	info->upper = (unsigned) upper_port;

	insert_dict(d, (void *)key, (void *)info);
}

void ProcessServiceAlias(dictionary *d, char *filename) {
	FILE *fe;
	char line[200];
	unsigned n_line = 0;

	init_dict(d, compareServiceAlias, compareService);

	fe = fopen(filename, "rt");

	if (fe == NULL) {
		return;
	}

	while (fgets(line, sizeof(line)-1, fe) != NULL) {
		n_line++;
		ProcessLineAlias(*d, filename, line, n_line);
	}

	fclose(fe);
}


void ProcessLineAlias(dictionary d, char *filename, char *line, unsigned n_line) {
	char *seps = "\t ";
	char *delim1 = "/";
	char *delim2 = ":";
	char *s_protocol, *ports_range, *port;
	char *p, short_alias[200] = "", alias[200], line_backup[200];
	unsigned protocol;
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

	key = malloc(sizeof(unsigned));
	if (key == NULL)
	{
		fprintf(stderr,"ProcessLineAlias: Could not allocate memory for key!!\n");
		exit(1);		
	}
	info = malloc(sizeof(struct info_alias));
	if (info == NULL)
	{
		fprintf(stderr,"ProcessLineAlias: Could not allocate memory for port value!!\n");
		exit(1);		
	}
	info->alias = malloc(strlen(alias));
	if (info->alias == NULL) {
		fprintf(stderr,"ProcessLineAlias: Could not allocate memory for alias!!\n");
		exit(1);				
	}
	info->short_alias = malloc(strlen(short_alias));
	if (info->short_alias == NULL) {
		fprintf(stderr,"ProcessLineAlias: Could not allocate memory for short alias!!\n");
		exit(1);				
	}

	*key = protocol;
	info->lower = (unsigned) low_port;
	info->upper = (unsigned) upper_port;
	strcpy(info->alias, alias);
	strcpy(info->short_alias, short_alias);


	insert_dict(d, (void *)key, (void *)info);
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

int compareServicePort(void *val1,  void *val2) {
    struct value_dict *info1, *info2;
    unsigned key1, key2;
    struct ports_range *value1, *value2;

    info1 = (struct value_dict *)val1;
    info2 = (struct value_dict *)val2;

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

int compareServiceAlias(void *val1,  void *val2) {
    struct value_dict *info1, *info2;
    unsigned key1, key2;
    struct info_alias *value1, *value2;

    info1 = (struct value_dict *)val1;
    info2 = (struct value_dict *)val2;

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

int Config_PortInRange(void *val1, void *val2) {
    struct value_dict *info1, *info2;
    unsigned key1, key2;
    struct ports_range *value1, *value2;

    info1 = (struct value_dict *)val1;
    info2 = (struct value_dict *)val2;

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

int Config_PortInRangeAlias(void *val1, void *val2) {
    struct value_dict *info1, *info2;
    unsigned key1, key2;
    struct info_alias *value1, *value2;

    info1 = (struct value_dict *)val1;
    info2 = (struct value_dict *)val2;

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

char *ltrim(char *str, const char *seps)
{
    size_t totrim;
    if (seps == NULL) {
        seps = "\t\n\v\f\r ";
    }
    totrim = strspn(str, seps);
    if (totrim > 0) {
        size_t len = strlen(str);
        if (totrim == len) {
            str[0] = '\0';
        }
        else {
            memmove(str, str + totrim, len + 1 - totrim);
        }
    }
    return str;
}

char *rtrim(char *str, const char *seps)
{
    int i;
    if (seps == NULL) {
        seps = "\t\n\v\f\r ";
    }
    i = strlen(str) - 1;
    while (i >= 0 && strchr(seps, str[i]) != NULL) {
        str[i] = '\0';
        i--;
    }
    return str;
}

/******************************************  DEBUG *******************************
void printPairPortDic(void *v_pair, void *param) {
    struct value_dict *pair;
    unsigned key;
    struct ports_range *value;
    char line[100];
    char s_protocol[8];

    pair = (struct value_dict *)v_pair;
    key = *(unsigned *)pair->key;
    value = (struct ports_range *)pair->value;

    // Protocol?
    switch (key) {
        case IPPROTO_TCP:
            strcpy(s_protocol, "tcp");
            break;
        case IPPROTO_UDP:
            strcpy(s_protocol, "udp");
            break;
    }
    sprintf(line, "%s/%u-%u\n" , s_protocol, value->lower, value->upper);
    debugMessage(line, NULL, 2);
}

void printConfDict(dictionary d) {
    for_each_dict(d, printPairPortDic, NULL);
}

/*************************************************************************************/