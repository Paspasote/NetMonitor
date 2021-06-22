#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <curses.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <debug.h>
#include <GlobalVars.h>
#include <Configuration.h>
#include <SharedSortedList.h>
#include <Dictionary.h>
#include <WhoIs.h>
#include <interface.h>
#include <DefaultView.h>
#include <IPGroupedView.h>

// EXTERNAL Global vars
struct write_global_vars w_globvars;

// Global vars
dictionary bd_whois = NULL;
unsigned cont_whois_threads = 0;
int cont_threads_per_tic = 0;
time_t last_requests_tic = 0;
#ifdef DEBUG
unsigned cont_fallos1 = 0, cont_fallos2 = 0, cont_fallos3 = 0, cont_repetidos = 0;
#endif

// Function prototypes
int getInfoWhoIs(char ip_src[INET_ADDRSTRLEN], struct t_key *key, struct t_value *value);

char *readLine(int fd, char *line, int max);
int noCaseComp(char *s1, char *s2);

int compareWhois(struct value_dict *pair1, struct value_dict *pair2);
int compareWhoIsKeys(void *data_key1, void *data_key2);

void readCurrentRequests();
void writeCurrentRequests();
void writePair(struct value_dict *info, void *param);

void showPair(struct value_dict *info, int current_register);

void *whoIs(void *ptr_paramt) 
{
    uint32_t ip_address;
	char s_ip_address[INET_ADDRSTRLEN];
    struct t_key *key;
    struct t_value *value;

    // Get address 
    ip_address = *((uint32_t *)ptr_paramt);
    free(ptr_paramt);
#ifdef DEBUG
    w_globvars.allocated_whois -= sizeof(uint32_t);
#endif

    // Get string address
	inet_ntop(AF_INET, &ip_address, s_ip_address, INET_ADDRSTRLEN);

    // Launch whois
    key = (struct t_key *)malloc(sizeof(struct t_key));
	if (key == NULL) {
		fprintf(stderr,"whoIs: Could not allocate memory!!\n");
		exit(1);				
	}
#ifdef DEBUG
    w_globvars.allocated_whois += sizeof(struct t_key);
#endif
    value = (struct t_value *)malloc(sizeof(struct t_value));
	if (value == NULL) {
		fprintf(stderr,"whoIs: Could not allocate memory!!\n");
		exit(1);				
	}
#ifdef DEBUG
    w_globvars.allocated_whois += sizeof(struct t_value);
#endif
    if (getInfoWhoIs(s_ip_address, key, value))
    {
        // Insert the value in dictionary
        if (sem_wait(&w_globvars.mutex_bd_whois)) 
        {
            perror("whoIs: sem_wait with mutex_bd_whois");
            exit(1);
        }

        // Is info already inserted?
        if (find_key_dict(bd_whois, key, NULL) == NULL)
        {
            // No. Insert it
            value->updated = time(NULL);
            insert_dict(bd_whois, key, value);
#ifdef DEBUG
            w_globvars.allocated_whois += sizeof(struct value_dict) + sizeof(struct node_sorted_list);
#endif
        }
        else
        {
#ifdef DEBUG            
            cont_repetidos++;
            /***************************  DEBUG ****************************/
            {
                char m[255];
                sprintf(m, "Sin datos: %5d   Sin rango: %5d    Mal dirs: %5d  Repetidos: %5d    ", cont_fallos1, cont_fallos2, cont_fallos3, cont_repetidos);
                debugMessageXY(6, 0, m, NULL, 1);
            }
#endif
            /*****************************************************************/
            // The info is already inserted in dictionary
            free(key);
            free(value);
#ifdef DEBUG
            w_globvars.allocated_whois -= sizeof(struct t_key);
            w_globvars.allocated_whois -= sizeof(struct t_value);
#endif
        }
        if (sem_post(&w_globvars.mutex_bd_whois))
        {
            perror("whoIs: sem_post with mutex_bd_whois");
            exit(1);
        }
    }
    else 
    {
        // whois command couldn't get any info
        free(key);
        free(value);
#ifdef DEBUG
        w_globvars.allocated_whois -= sizeof(struct t_key);
        w_globvars.allocated_whois -= sizeof(struct t_value);
#endif
    }
    
    // One thread less
    if (sem_wait(&w_globvars.mutex_cont_whois_threads)) 
    {
        perror("whoIs: sem_wait with mutex_cont_whois_threads");
        exit(1);
    }
    cont_whois_threads--;
    if (sem_post(&w_globvars.mutex_cont_whois_threads))
    {
        perror("whoIs: sem_post with w_globvars.mutex_cont_whois_threads");
        exit(1);
    }
   
	pthread_exit(NULL);
}

int getInfoWhoIs(char ip_src[INET_ADDRSTRLEN], struct t_key *key, struct t_value *value) {
    int pipe_fd[2];
    pid_t pid;
	char local_country[MAX_LEN_COUNTRY+1] = "";
	char local_netname[MAX_LEN_NETNAME+1] = "";
    char s_initial_addr[INET_ADDRSTRLEN] = "";
    char s_final_addr[INET_ADDRSTRLEN] = "";
    char line[200];
    char delim1[2] = ":";
    char delim2[3] = " \t";
    char *p;

    // Create a unnamed pipe to get whois output
    if (pipe(pipe_fd) == -1)
    {
		perror("getInfoWhoIs: ");
		exit(1);
    }

    // Create a child to execute whois
    pid = fork();
    if (pid == -1) 
    {
		perror("getInfoWhoIs: ");
		exit(1);
    }

    if (pid) 
    {
        // One more whois request
        if (sem_wait(&w_globvars.mutex_cont_requests)) 
        {
            perror("getInfoWhoIs: sem_wait with w_globvars.mutex_cont_whois_threads");
            exit(1);
        }
        w_globvars.cont_requests++;
        if (sem_post(&w_globvars.mutex_cont_requests))
        {
            perror("getInfoWhoIs: sem_post with w_globvars.mutex_cont_whois_threads");
            exit(1);
        }

        // Original thread (process)
        // Not using the write part of the pipe
        close(pipe_fd[1]);

        // Read lines until found country: or netname: or EOF
        while (readLine(pipe_fd[0], line, 200) != NULL)
        {
            // Line beggining with inetnum: or NetRange: ?
            if (noCaseComp(line, "inetnum:") || noCaseComp(line, "netrange:"))
            {
                // Yes. Get string after tag:
                p = strtok(line, delim1);
                p = strtok(NULL, delim1);
                if (p != NULL) {
                    // Got it! Get initial address
                    p = strtok(p, delim2);
                    if (p != NULL) {
                        // Got it! Save initial address
                        strncpy(s_initial_addr, p, INET_ADDRSTRLEN);
                    }
                    // Get - char
                    p = strtok(NULL, delim2);
                    if (p != NULL && !strcmp(p, "-"))
                    {
                        // Got it! Get final address
                        p = strtok(NULL, delim2);
                        if (p != NULL)
                        {
                            // Got it! Save final address
                            strncpy(s_final_addr, p, INET_ADDRSTRLEN);
                        }
                        else 
                        {
                            // Bad range address. Reset initial address
                            strcpy(s_initial_addr, "");
                        }
                    }
                    else 
                    {
                        // Bad range address. Reset initial address
                        strcpy(s_initial_addr, "");
                    }
                }                
            }

            // Line beggining with country: ?
            if (noCaseComp(line, "country:"))
            {
                // Yes. Get string after country:
                p = strtok(line, delim1);
                p = strtok(NULL, delim1);
                if (p != NULL) {
                    // Got it! Get country code
                    p = strtok(p, delim2);
                    if (p != NULL) {
                        // Got it! Save country code
                        strncpy(local_country, p, MAX_LEN_COUNTRY);
                    }
                }
            }
             
           // Line beggining with netname: ?
            if (noCaseComp(line, "netname:"))
            {
                // Yes. Get string after netname:
                p = strtok(line, delim1);
                p = strtok(NULL, delim1);
                if (p != NULL) {
                    // Got it! Get net name
                    p = strtok(p, delim2);
                    if (p != NULL) {
                        // Got it! Save net name
                        if (noCaseComp(p, "private-address-"))
                        {
                            strncpy(local_netname, "INTRANET", MAX_LEN_NETNAME);
                        }
                        else
                        {
                            strncpy(local_netname, p, MAX_LEN_NETNAME);
                        }
                    }
                }
            }
        }
    }
    else
    {
        // Child process
        // standard output is now the pipe
        close(1);
        dup(pipe_fd[1]);
        // Not using the read part of the pipe
        close(pipe_fd[0]);
        // Exec whois with source IP address
        execlp("whois", "whois", ip_src, NULL);
        // If exec fail then close pipe and exit
        close(1);
        close(pipe_fd[1]);
        exit(1);
    }

    // Wait until child finish
    waitpid(pid, NULL, 0);
#ifdef DEBUG
 	/***************************  DEBUG ****************************/
	{
		char m[255];
		sprintf(m, "Llamadas a whois: %0u  Nº items en BD: %0u          ", w_globvars.cont_requests, size_dict(bd_whois));
		debugMessageXY(5, 0, m, NULL, 1);
	}
	/*****************************************************************/
#endif
    // Close pipe
    close(pipe_fd[0]);

    // Did we got any info?
    if (!strcmp(local_country, "") && !strcmp(local_netname, ""))
    {
#ifdef DEBUG
        cont_fallos1++;
        /***************************  DEBUG ****************************/
        {
            char m[255];
            sprintf(m, "Sin datos: %5d   Sin rango: %5d    Mal dirs: %5d  Repetidos: %5d                        ", cont_fallos1, cont_fallos2, cont_fallos3, cont_repetidos);
            debugMessageXY(6, 0, m, NULL, 1);
        }
        /*****************************************************************/
#endif
        // No, return
        return 0;
    }

    // Did we got address range?
    if (!strcmp(s_initial_addr, "") || !strcmp(s_final_addr, ""))
    {
#ifdef DEBUG
        cont_fallos2++;
        /***************************  DEBUG ****************************/
        {
            char m[255];
            sprintf(m, "Sin datos: %5d   Sin rango: %5d  (%s)  Mal dirs: %5d  Repetidos: %5d     ", cont_fallos1, cont_fallos2, ip_src, cont_fallos3, cont_repetidos);
            debugMessageXY(6, 0, m, NULL, 1);
        }
        /*****************************************************************/
#endif
        // No, return
        return 0;
    }

    // Save range address
    if (!inet_pton(AF_INET, s_initial_addr, &key->initial_address))
    {
#ifdef DEBUG
        cont_fallos3++;
        /***************************  DEBUG ****************************/
        {
            char m[255];
            sprintf(m, "Sin datos: %5d   Sin rango: %5d    Mal dirs: %5d  Repetidos: %5d                          ", cont_fallos1, cont_fallos2, cont_fallos3, cont_repetidos);
            debugMessageXY(6, 0, m, NULL, 1);
        }
        /*****************************************************************/
#endif
        // Bad initial address. Return
        return 0;
    }
    if (!inet_pton(AF_INET, s_final_addr, &key->end_address))
    {
#ifdef DEBUG
        cont_fallos3++;
        /***************************  DEBUG ****************************/
        {
            char m[255];
            sprintf(m, "Sin datos: %5d   Sin rango: %5d    Mal dirs: %5d  Repetidos: %5d                         ", cont_fallos1, cont_fallos2, cont_fallos3, cont_repetidos);
            debugMessageXY(6, 0, m, NULL, 1);
        }
        /*****************************************************************/
#endif
        // Bad final address. Return
        return 0;
    }

    // If it is a private address reset country
    if (!strncmp(local_netname, "INTRANET", MAX_LEN_NETNAME))
    {
        strcpy(local_country, "");
    }

    // Save country and net name
    strcpy(value->country, local_country);
    strcpy(value->netname, local_netname);

    return 1;
}

struct t_value * findAdressWhois(uint32_t ip_address) 
{
    struct t_key key;
    struct node_sorted_list *node;

    // Find ip_source in dictionary
    key.initial_address = ip_address;
    key.end_address = ip_address;
    node = find_key_dict(bd_whois, &key, NULL);

    // Found it?
    if (node != NULL)
    {
        // Yes. Return value
        return (struct t_value *)(((struct value_dict *)node->info)->value);
    }
    return NULL;
}

void updateWhoisInfo(struct node_shared_sorted_list *node, uint32_t address, char *country, char *netname)
{
	struct t_value *info_whois;
	pthread_t thread_whois;
    char local_netname[MAX_LEN_NETNAME+1];
    char local_country[MAX_LEN_COUNTRY+1];
    uint32_t *param_address;
    time_t now;

    now = time(NULL);

    // Try to get whois info from dictionary
    if (sem_wait(&w_globvars.mutex_bd_whois)) 
    {
        perror("updateWhoisInfo: sem_wait with w_globvars.mutex_bd_whois");
        exit(1);
    }
    info_whois = findAdressWhois(address);
    if (info_whois != NULL)
    {
        // We have the info. Store it
        strcpy(local_country, info_whois->country);
        strcpy(local_netname, info_whois->netname);
        if (sem_post(&w_globvars.mutex_bd_whois))
        {
            perror("updateWhoisInfo: sem_post with w_globvars.mutex_bd_whois");
            exit(1);
        }
        leaveReadNode_shared_sorted_list(node);
        requestWriteNode_shared_sorted_list(node);
        strcpy(country, local_country);
        strncpy(netname, local_netname, MAX_VISIBLE_NETNAME);
        leaveWriteNode_shared_sorted_list(node);
        requestReadNode_shared_sorted_list(node);
    }
    else
    {
        if (sem_post(&w_globvars.mutex_bd_whois))
        {
            perror("updateWhoisInfo: sem_post with w_globvars.mutex_bd_whois");
            exit(1);
        }
        // We don't have the info. Launch a whois in a new thread
        // if don't reach the max threads or the max threads per tic or max requests
        if (sem_wait(&w_globvars.mutex_cont_whois_threads)) 
        {
            perror("updateWhoisInfo: sem_wait with w_globvars.mutex_cont_whois_threads");
            exit(1);
        }
        // Can we reset cont_threads_per_tic?
        if (now - last_requests_tic > DELAY_BETWEEN_REQUESTS)
        {
            cont_threads_per_tic = 0;
            last_requests_tic = now;
        }
        if (cont_whois_threads >= MAX_WHOIS_THREADS || cont_threads_per_tic >= MAX_WHOIS_THREADS)
        {
            if (sem_post(&w_globvars.mutex_cont_whois_threads))
            {
                perror("updateWhoisInfo: sem_post with w_globvars.mutex_cont_whois_threads");
                exit(1);
            }
            return;
        }
        if (sem_wait(&w_globvars.mutex_cont_requests)) 
        {
            perror("updateWhoisInfo: sem_wait with w_globvars.mutex_cont_requests");
            exit(1);
        }
        if (w_globvars.cont_requests >= MAX_WHOIS_REQUESTS)
        {
            if (sem_post(&w_globvars.mutex_cont_requests))
            {
                perror("updateWhoisInfo: sem_post with w_globvars.mutex_cont_requests");
                exit(1);
            }
            if (sem_post(&w_globvars.mutex_cont_whois_threads))
            {
                perror("updateWhoisInfo: sem_post with w_globvars.mutex_cont_whois_threads");
                exit(1);
            }
            return;
        }
        if (sem_post(&w_globvars.mutex_cont_requests))
        {
            perror("updateWhoisInfo: sem_post with w_globvars.mutex_cont_requests");
            exit(1);
        }
        cont_whois_threads++;
        cont_threads_per_tic++;
        if (sem_post(&w_globvars.mutex_cont_whois_threads))
        {
            perror("updateWhoisInfo: sem_post with w_globvars.mutex_cont_whois_threads");
            exit(1);
        }
        param_address = (uint32_t *)malloc(sizeof(uint32_t));
        if (param_address == NULL) {
            fprintf(stderr,"updateWhoisInfo: Could not allocate memory!!\n");
            exit(1);				
        }
#ifdef DEBUG
        w_globvars.allocated_whois += sizeof(uint32_t);
#endif
        *param_address = address;
        pthread_create(&thread_whois, NULL, whoIs, param_address);
        pthread_detach(thread_whois);
    }
}

char *readLine(int fd, char *line, int max)
{
    char c;
    int cont  = 0;
    int end = 0;
    int readed;

    // Read characters from file until reach \n or max characters of EOF

    readed = read(fd, &c, 1);
    while (readed == 1 && !end && cont < max)
    {
        end = c == '\n';

        if (!end) {
            line[cont] = c;
            cont++;
            readed = read(fd, &c, 1);
        }
    }

    // End of File and no characters readed?
    if (!end && cont == 0)
    {
        // Yes
        return NULL;
    }

    // Null char terminated
    line[cont] = '\0';

    // Max characters readed?
    if (!end)
    {
        // Yes. We have to continue reading until \n
        readed = read(fd, &c, 1);
        while (readed == 1 && !end)
        {
            end = c == '\n';
            if (!end)
            {
                readed = read(fd, &c, 1);
            }
        }
    }

    // Return line
    return line;
}

int noCaseComp(char *s1, char *s2)
{
    int cont = 0;
    int equals = 1;

    while (s1[cont] && s2[cont] && equals)
    {
        equals = tolower(s1[cont]) == tolower(s2[cont]);
        cont++;
    }

    return equals && cont == (int)strlen(s2);
}

int compareWhois(struct value_dict *pair1, struct value_dict *pair2) {
    struct t_key *key1, *key2;
    uint32_t initial_address1, final_address1, initial_address2, final_address2;

    // Get both keys
    key1 = (struct t_key *)pair1->key;
    key2 = (struct t_key *)pair2->key;

    // To compare adressed we need them to be in host order
    initial_address1 = ntohl(key1->initial_address);
    final_address1 = ntohl(key1->end_address);
    initial_address2 = ntohl(key2->initial_address);
    final_address2 = ntohl(key2->end_address);

    if (initial_address1 < initial_address2)
    {
        return -1;
    }

    if (final_address1 <= final_address2)
    {
        return 0;
    }

    return 1;
}

int compareWhoIsKeys(void *data_key1, void *data_key2)
{
    struct t_key *key1, *key2;
    uint32_t initial_address1, final_address1, initial_address2, final_address2;

    // Get both keys
    key1 = (struct t_key *)data_key1;
    key2 = (struct t_key *)data_key2;

    // To compare adressed we need them to be in host order
    initial_address1 = ntohl(key1->initial_address);
    final_address1 = ntohl(key1->end_address);
    initial_address2 = ntohl(key2->initial_address);
    final_address2 = ntohl(key2->end_address);

    if (initial_address1 < initial_address2)
    {
        return -1;
    }

    if (final_address1 <= final_address2)
    {
        return 0;
    }

    return 1;
}

void readDatabaseWhois()
{
    FILE *f;
    struct t_key *key;
    struct t_value *val;

    // Initialize whois database
    init_dict(&bd_whois, compareWhois, compareWhoIsKeys);
#ifdef DEBUG
    w_globvars.allocated_whois += sizeof(struct info_dict) + sizeof(struct info_sorted_list);
#endif

    // Database file exist?
    if (access("Whois.data", F_OK) != 0)
    {
        // File Database does not exist.
        return;
    }

    // Try to open file for reading
    f = fopen("Whois.data", "rb");
    if (f == NULL) 
    {
        perror("readDatabaseWhois: Can't open whois file database for reading");
        exit(EXIT_FAILURE);
    }

    // Read pairs (key, value) until EOF is reached
    key = (struct t_key *)malloc(sizeof(struct t_key));
	if (key == NULL) {
		fprintf(stderr,"readDatabaseWhois: Could not allocate memory!!\n");
		exit(1);				
	}
#ifdef DEBUG
    w_globvars.allocated_whois += sizeof(struct t_key);
#endif
    val = (struct t_value *)malloc(sizeof(struct t_value));
	if (val == NULL) {
		fprintf(stderr,"readDatabaseWhois: Could not allocate memory!!\n");
		exit(1);				
	}
#ifdef DEBUG
    w_globvars.allocated_whois += sizeof(struct t_value);
#endif
    while (fread(key, sizeof(struct t_key), 1, f) == 1)
    {
        // Try to read value
        if (fread(val, sizeof(struct t_value), 1, f) != 1)
        {
            // Error. Can't read value
            perror("readDatabaseWhois: Whois database file has a bad format. Can't read value");
            exit(EXIT_FAILURE);
        }

        // We have the full pair (key, value). Insert it in dictionary
        insert_dict(bd_whois, key, val);
#ifdef DEBUG
        w_globvars.allocated_whois += sizeof(struct value_dict) + sizeof(struct node_sorted_list);
#endif

        // Read next pair
        key = (struct t_key *)malloc(sizeof(struct t_key));
        if (key == NULL) {
            fprintf(stderr,"readDatabaseWhois: Could not allocate memory!!\n");
            exit(1);				
        }
#ifdef DEBUG
        w_globvars.allocated_whois += sizeof(struct t_key);
#endif
        val = (struct t_value *)malloc(sizeof(struct t_value));
        if (val == NULL) {
            fprintf(stderr,"readDatabaseWhois: Could not allocate memory!!\n");
            exit(1);				
        }
#ifdef DEBUG
        w_globvars.allocated_whois += sizeof(struct t_value);
#endif
    }

    // If we reached EOF all is OK
    if (!feof(f)) {
            perror("readDatabaseWhois: Whois database file has a bad format. Can't read key");
            exit(EXIT_FAILURE);
    }

    // Free last unused pair
    free(key);
    free(val);
#ifdef DEBUG
    w_globvars.allocated_whois -= sizeof(struct t_key);
    w_globvars.allocated_whois -= sizeof(struct t_value);
#endif

    // Close the file
    fclose(f);

    // Initializa current requests
    readCurrentRequests();
}

void readCurrentRequests()
{
    FILE *f;
    char line[100];
    int req_year, req_mon, req_day;
    unsigned requests;
    time_t now;
    struct tm *rt;

    // Current requests file exist?
    if (access("WhoisRequests.txt", F_OK) != 0)
    {
        // File Database does not exist.
        // Is database empty?
        if (!isEmpty_dict(bd_whois))
        {
            // The file should exist!!
            perror("readCurrentRequests: Current requests file does not exist!! First line of this file should have the following format: yyyy/mm/dd:#requests");
            exit(EXIT_FAILURE);
        }
/*             // We are going to considered that a half of max requests have been reached
            cont_requests = MAX_WHOIS_REQUESTS / 2;
*/
        else
        {
            w_globvars.cont_requests = 0;
        }
        return;
    }

    // Try to open file for reading
    f = fopen("WhoisRequests.txt", "rt");
    if (f == NULL) 
    {
        perror("readCurrentRequests: Can't open whois current requests file for reading");
        exit(EXIT_FAILURE);
    }

    // Read first line (file should only have one)
    if (fgets(line, 100, f) == NULL)
    {
        // Error. Can't read line
        perror("readCurrentRequests: Current requests file has a bad format. Can't read first line");
        exit(EXIT_FAILURE);
    }

    // Try to read data from line
    if (sscanf(line, "%d/%d/%d:%u", &req_year, &req_mon, &req_day, &requests) != 4)
    {
        // Error. Bad format
        perror("readCurrentRequests: First line of current requests file has a bad format. It should be yyyy/mm/dd:#requests");
        exit(EXIT_FAILURE);
    }

    // Initialize the current number of whois requests.
    // Get the current date
    now = time(NULL);
    rt = localtime(&now);
    if (rt == NULL)
    {
        perror("readCurrentRequests: Can't get current time!!");
        exit(EXIT_FAILURE);
    }
    if (req_year == rt->tm_year+1900 && req_mon == rt->tm_mon+1 && req_day == rt->tm_mday)
    {
        // We already have requests this day
        w_globvars.cont_requests = requests;
    }
    else
    {
        w_globvars.cont_requests = 0;
    }

    // Close the file
    fclose(f);
}

void writePair(struct value_dict *info, void *param)
{
    struct t_key *key;
    struct t_value *val;
    FILE *f;

    // Get element (pair)
    key = (struct t_key *)info->key;
    val = (struct t_value *)info->value;

    // Get file
    f = (FILE *)param;

    // Try to write key to file
    if (fwrite(key, sizeof(struct t_key), 1, f) != 1)
    {
        // Try to recover backup database
        fclose(f);
        remove("Whois.data");
        if (rename("Whois.data.bak", "Whois.data") != 0)
        {
            // Error.
            perror("writePair: Error writing new data to database. CAN'T RECOVER OLD ONE!!");
            exit(EXIT_FAILURE);
        }
        perror("writePair: Can't write key in Whois database filename");
        exit(EXIT_FAILURE);       
    }

    // Try to write val to file
    if (fwrite(val, sizeof(struct t_value), 1, f) != 1)
    {
        // Try to recover backup database
        fclose(f);
        remove("Whois.data");
        if (rename("Whois.data.bak", "Whois.data") != 0)
        {
            // Error.
            perror("writePair: Error writing new data to database. CAN'T RECOVER OLD ONE!!");
            exit(EXIT_FAILURE);
        }
        perror("writePair: Can't write value in Whois database filename");
        exit(EXIT_FAILURE);       
    }
}

void writeDatabaseWhois()
{
    FILE *f;

    // Database file exist?
    if (access("Whois.data", F_OK) == 0)
    {
        // File Database exist. Creating a backup
        // Is there already a backup file?
        if (access("Whois.data.bak", F_OK) == 0) 
        {
            // Yes. Remove it
            if (remove("Whois.data.bak") != 0)
            {
                // Error.
                perror("writeDatabaseWhois: Can't remove old database backup");
                exit(EXIT_FAILURE);
            }
        }

        // Renaming to backup file
        if (rename("Whois.data", "Whois.data.bak") != 0)
        {
                // Error.
                perror("writeDatabaseWhois: Can't rename old database file to backup file");
                exit(EXIT_FAILURE);
        }
    }

    // Try to open file for writing
    f = fopen("Whois.data", "wb");
    if (f == NULL) 
    {
        // Try to recover backup database
        remove("Whois.data");
        if (rename("Whois.data.bak", "Whois.data") != 0)
        {
                // Error.
                perror("writeDatabaseWhois: Can't open whois database for writing. CAN'T RECOVER OLD DATABASE!!");
                exit(EXIT_FAILURE);
        }
        perror("writeDatabaseWhois: Can't open whois file database for writing");
        exit(EXIT_FAILURE);
    }

    // Iterate the dictionary and write elements (pairs) to file
    for_each_dict(bd_whois, writePair, f);

    // Close file
    fclose(f);

    // Save current requests
    writeCurrentRequests();
}

void writeCurrentRequests()
{
    FILE *f;
    time_t now;
    struct tm *rt;

    // Database file exist?
    if (access("WhoisRequests.txt", F_OK) == 0)
    {
        // File Database exist. Creating a backup
        // Is there already a backup file?
        if (access("WhoisRequests.bak", F_OK) == 0) 
        {
            // Yes. Remove it
            if (remove("WhoisRequests.bak") != 0)
            {
                // Error.
                perror("writeCurrentRequests: Can't remove old current requests file backup");
                exit(EXIT_FAILURE);
            }
        }

        // Renaming to backup file
        if (rename("WhoisRequests.txt", "WhoisRequests.bak") != 0)
        {
            // Error.
            perror("writeCurrentRequests: Can't rename old current requests file to backup file");
            exit(EXIT_FAILURE);
        }
    }

    // Try to open file for writing
    f = fopen("WhoisRequests.txt", "wt");
    if (f == NULL) 
    {
        // Try to recover backup file
        remove("WhoisRequests.txt");
        if (rename("WhoisRequests.bak", "WhoisRequests.txt") != 0)
        {
            // Error.
            perror("writeCurrentRequests: Can't open whois requests file for writing. CAN'T RECOVER OLD FILE!!");
            exit(EXIT_FAILURE);
        }
        perror("writeCurrentRequests: Can't open whois requests file for writing");
        exit(EXIT_FAILURE);
    }

    // Get current date
    now = time(NULL);
    rt = localtime(&now);
    if (rt == NULL)
    {
        perror("writeCurrentRequests: Can't get current time!!");
        exit(EXIT_FAILURE);
    }

    // Save current date and who requests to file
    if (fprintf(f, "%04d/%02d/%02d:%0u\n", rt->tm_year+1900, rt->tm_mon+1, rt->tm_mday, w_globvars.cont_requests) <= 0)
    {
        perror("writeCurrentRequests: Can't write current time and whois requests to file!!");
        exit(EXIT_FAILURE);
    }

    // Close file
    fclose(f);
}

void showDatabase(int first_register, int max_registers)
{
    struct node_sorted_list *p;
    int current_register;
    int cont_registers;

     if (sem_wait(&w_globvars.mutex_bd_whois)) 
    {
        perror("showWhoisDatabase: sem_wait with w_globvars.mutex_bd_whois");
        exit(1);
    }
    p = first_dict(bd_whois);
    current_register = 0;
    while (p != end_dict(bd_whois) && current_register < first_register)
    {
        current_register++;
        p = next_dict(p);
    }

    cont_registers = 0;
    while (p != end_dict(bd_whois) && cont_registers < max_registers)
    {
        // Show current register info
        showPair(p->info, current_register);
        current_register++;
        cont_registers++;
        p = next_dict(p);
    }
    if (sem_post(&w_globvars.mutex_bd_whois))
    {
        perror("showWhoisDatabase: sem_post with w_globvars.mutex_bd_whois");
        exit(1);
    }  
}

void showPair(struct value_dict *info, int current_register)
{
    struct t_key *key;
    struct t_value *val;
	struct tm *t;
	char s_time[20];
   	char s_initial_address[INET_ADDRSTRLEN], s_final_address[INET_ADDRSTRLEN];
	char line[WHOIS_COLS+1];

    // Get element (pair)
    key = (struct t_key *)info->key;
    val = (struct t_value *)info->value;

    // Get update time
	t = localtime(&val->updated);
	sprintf(s_time, "%02d/%02d/%4d", t->tm_mday, t->tm_mon, 1900+t->tm_year);

    // Get initial and final addresss
	inet_ntop(AF_INET, &(key->initial_address), s_initial_address, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(key->end_address), s_final_address, INET_ADDRSTRLEN);

    // Generate line info
    sprintf(line, "%05d  %s  %15s:%-15s %-32s  %-2s\n", current_register, s_time, s_initial_address, s_final_address, val->netname, val->country);
   	writeLineOnWhois(line, COLOR_PAIR(0), 0);
}

int numberOfWhoisRegisters()
{
    int ret;

    if (sem_wait(&w_globvars.mutex_bd_whois)) 
    {
        perror("numberOfRegisters: sem_wait with w_globvars.mutex_bd_whois");
        exit(1);
    }
    ret = size_dict(bd_whois);
    if (sem_post(&w_globvars.mutex_bd_whois))
    {
        perror("numberOfRegisters: sem_post with w_globvars.mutex_bd_whois");
        exit(1);
    }
    return ret;
}