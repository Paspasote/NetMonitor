#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <unistd.h>
#include <time.h>
#include <semaphore.h>
#include <pthread.h>

#include <misc.h>
#include <Configuration.h>
#include <GlobalVars.h>
#include <NetMonitor.h>
#include <PacketList.h>
#include <DefaultView.h>
#include <IPGroupedView.h>
#include <OutNATView.h>
#ifdef DEBUG
#include <debug.h>
#endif

#include <interface.h>


// EXTERNAL global vars
extern struct const_global_vars c_globvars;
extern struct write_global_vars w_globvars;


// global vars
int reEntry = 0;
int no_output = 0;
int temp_display_seconds;
char temp_message[RESULT_COLS+1];
attr_t temp_attr;
int temp_highlight;

int result_selected_row = -1;
int result_start_posY;
int result_end_posY;
int result_visible_rows;
int result_top_row = 0;
int info_start_posY;
int info_end_posY;
int info_visible_rows;
int info_top_row = 0;
int whois_start_posY;
int whois_end_posY;
int whois_start_posX;
int whois_end_posX;
int whois_visible_rows;
int whois_visible_cols;
int whois_top_row = 0;
int whois_visible = 0;
int terminal_rows;
#ifdef DEBUG
int debug_start_posY;
int debug_end_posY;
int debug_visible_rows = 0;
int debug_top_row = 0;
#endif

WINDOW *main_screen, *info_panel, *result_panel, *whois_panel, *d_whois_window;

// Function prototypes
void user_interface();
void refreshTop();
void getPanelDimensions();
int getTextAttrLine(int row, chtype **text);
int getTextLine(int row, char **text, int max_size);
int extractIPAddress(char *text, char *address1, char *address2);
void clearSelection();
void setSelection();
void selectionDown();
void selectionUp();
void selectionPageDown();
void selectionPageUp();
void selectionStart();
void selectionEnd();
void resetInterface();
void quitInterface();
void changeView();
void UI_banIP(int ban); 
void showWhoisDatabase();

void *interface(void *ptr_paramt) {
    unsigned long cont = 0;
	while (1)
	{
        if (w_globvars.visual_mode != -1) {
            refreshTop();
            while (cont < SCREEN_REFRESH_DELAY) {
                user_interface();
                usleep(USER_INTERFACE_DELAY);
                cont += USER_INTERFACE_DELAY;
            }
            cont = 0;
        }
        else {            
            // Debug mode. Prints all info
            PL_show_info(1);
        }
	}
}

void user_interface()
{
	int key;

	// User has pressed a key?
	key = wgetch(result_panel);

    switch (key) {
        case 'q':
        case 'Q':
            quitInterface();
            pthread_exit(0);
            break;

        case 'f':
        case 'F':
            no_output = !no_output;
            break;

        case 'r':
        case 'R':
            resetInterface();
            break;

        case 'v':
        case 'V':
            if (info_visible_rows >= 2)
            {
                changeView();
            }
            break;

        case 'b':
        case 'B':
            UI_banIP(1);
            break;

        case 'u':
        case 'U':
            UI_banIP(0);
            break;

        case 'w':
        case 'W':
            showWhoisDatabase();
            break;

        case KEY_DOWN:
            selectionDown();
            break;

        case KEY_UP:
            selectionUp();
            break;

        case KEY_NPAGE:
            selectionPageDown();
            break;

        case KEY_PPAGE:
            selectionPageUp();
            break;

        case KEY_END:
            selectionEnd();
            break;

        case KEY_HOME:
            selectionStart();
            break;
    }
}

void init_curses()
{
	// Initialize curses
	main_screen = initscr();
   	start_color();
	noecho();
	cbreak();
	//halfdelay(10);
	keypad(main_screen, TRUE);

	// Create panels
	info_panel = newpad(INFO_LINES, INFO_COLS);
	result_panel =  newpad(RESULT_LINES, RESULT_COLS);
	nodelay(info_panel, FALSE);
	nodelay(result_panel, TRUE);
	keypad(info_panel, TRUE);
	keypad(result_panel, TRUE);

	// Create color attributes
    init_pair(1, COLOR_CYAN, COLOR_BLACK);
	init_pair(2, COLOR_YELLOW, COLOR_BLACK);
    init_pair(3, COLOR_RED, COLOR_BLACK);


#ifdef DEBUG
	// Create debug panel
    init_debug_panel(INFO_LINES);
#endif

	// Resize panels
	getPanelDimensions();
}

void writeLineOnResult(char *text, attr_t attr, int highlight) 
{
    int x, y;

   // Get current cursor position
    getyx(result_panel, y, x);

    // Check if there are free lines
    if (y >= RESULT_LINES-1) {
        return;
    }

    // Write message on panel
    if (attr) {
        wattrset(result_panel, attr);
    }
    if (highlight) {
        wattron(result_panel, A_BOLD);
    }

    waddstr(result_panel, text);


    if (attr || highlight) {
    	wattrset(result_panel, 0);
    }
}

void writeLineOnInfo(char *text, attr_t attr, int highlight, int seconds)
{
    strncpy(temp_message , text, RESULT_COLS);
    if (strlen(text) > RESULT_COLS)
    {
        temp_message[RESULT_COLS] = '\0';
    }
    temp_attr = attr;
    temp_highlight = highlight;
    temp_display_seconds = seconds;
}

void writeLineOnWhois(char *text, attr_t attr, int highlight) 
{
    int x, y;

   // Get current cursor position
    getyx(whois_panel, y, x);

    // Check if there are free lines
    if (y >= whois_visible_rows -1) {
        return;
    }

    wmove(whois_panel, y, x+1);

    // Write message on panel
    if (attr) {
        wattrset(whois_panel, attr);
    }
    if (highlight) {
        wattron(whois_panel, A_BOLD);
    }

    waddstr(whois_panel, text);


    if (attr || highlight) {
    	wattrset(whois_panel, 0);
    }
}

void refreshTop()
{
    time_t now;
	struct tm *t;
	char s[150];
    unsigned req;

#ifdef DEBUG
 	/***************************  DEBUG ****************************/
	{
		char m[255];
        int i;
        unsigned long cont_internet, cont_intranet, cont_internet_in, cont_internet_out, cont_intranet_in, cont_intranet_out, total_intranet, total_internet;
        unsigned long total_intranet_purged, total_internet_purged;

        /*
        if (pthread_mutex_lock(&w_globvars.mutex_debug_stats)) 
        {
            perror("refreshTop: pthread_mutex_lock with mutex_debug_stats");
            exit(1);
        }        
		sprintf(m, "Config mem.: %0lu   Inbound mem.: %0lu   Outbound mem.: %0lu   Whois mem.: %0lu   Otros mem.: %0lu", w_globvars.allocated_config, w_globvars.allocated_packets_inbound, w_globvars.allocated_packets_outbound, w_globvars.allocated_whois, w_globvars.allocated_others);
		if (pthread_mutex_unlock(&w_globvars.mutex_debug_stats))
		{
			perror("refreshTop: pthread_mutex_unlock with mutex_debug_stats");
			exit(1);		
		}
		debugMessageXY(1, 0, m, NULL, 1);
        */
        sprintf(m, "is_allow: %-5u  is_warning: %-5u  is_alert: %-5u  is_deny: %-5u  os_allow: %-5u  os_warning: %-5u  os_alert: %-5u  os_deny: %-5u",
                c_globvars.cont_is_allow, c_globvars.cont__is_warning, c_globvars.cont_is_alert, c_globvars.cont_is_deny, c_globvars.cont_os_allow, c_globvars.cont_os_warning, c_globvars.cont_os_alert, c_globvars.cont_os_deny);
		debugMessageModule(INTERFACE_STATS, m, NULL, 1);
        sprintf(m, "oh_allow: %-5u  oh_warning: %-5u  oh_alert: %-5u  oh_deny: %-5u  Serv_alias: %-5u",
                c_globvars.cont_oh_allow, c_globvars.cont_oh_warning, c_globvars.cont_oh_alert, c_globvars.cont_oh_deny, c_globvars.cont_services_alias);
		debugMessageModule(INTERFACE_STATS_EXTRA1, m, NULL, 1);

        if (pthread_mutex_lock(&w_globvars.mutex_debug_stats)) 
        {
            perror("refreshTop: pthread_mutex_lock with mutex_debug_stats");
            exit(1);
        }        
        total_internet = w_globvars.internet_packets_processed;
        total_intranet = w_globvars.intranet_packets_processed;
        total_internet_purged = w_globvars.internet_packets_purged;
        total_intranet_purged = w_globvars.intranet_packets_purged;
		if (pthread_mutex_unlock(&w_globvars.mutex_debug_stats))
		{
			perror("refreshTop: pthread_mutex_unlock with mutex_debug_stats");
			exit(1);		
		}

        cont_internet = 0;
        if (w_globvars.internet_packets_buffer != NULL)
        {
            cont_internet = size_double_list(w_globvars.internet_packets_buffer);
        }
        cont_intranet = 0;
        if (w_globvars.intranet_packets_buffer != NULL)
        {
            cont_intranet = size_double_list(w_globvars.intranet_packets_buffer);
        }
        cont_internet_in = 0;
        cont_internet_out = 0;
        cont_intranet_in = 0;
        cont_intranet_out = 0;
        for (i=0; i<65536; i++)
        {
            if (w_globvars.conn_internet_in[i] != NULL)
            {
                cont_internet_in += size_shared_sorted_list(w_globvars.conn_internet_in[i]);
            }
            if (w_globvars.conn_internet_out[i] != NULL)
            {
                cont_internet_out += size_shared_sorted_list(w_globvars.conn_internet_out[i]);
            }
            if (c_globvars.intranet_dev != NULL) {
                if (w_globvars.conn_intranet_in[i] != NULL)
                {
                    cont_intranet_in += size_shared_sorted_list(w_globvars.conn_intranet_in[i]);
                }
                if (w_globvars.conn_intranet_out[i] != NULL)
                {
                    cont_intranet_out += size_shared_sorted_list(w_globvars.conn_intranet_out[i]);
                }
            }
        }
        if (c_globvars.intranet_dev == NULL) {
            sprintf(m, "Pending Internet Packets: %-8lu  Internet IN: %-8lu  Internet OUT: %-8lu", cont_internet, cont_internet_in, cont_internet_out);
            debugMessageModule(INTERFACE_STATS_EXTRA2, m, NULL, 1);
            sprintf(m, "Internet Packets processed: %-10lu  Internet Packets purged: %-10lu", total_internet, total_internet_purged);
            debugMessageModule(INTERFACE_STATS_EXTRA3, m, NULL, 1);
        }
        else {
            sprintf(m, "Pending Internet Packets: %-8lu  Pending Intranet Packets: %-8lu  Internet IN: %-8lu  Internet OUT: %-8lu  Intranet IN: %-8lu  Intranet OUT: %-8lu", 
                    cont_internet, cont_intranet, cont_internet_in, cont_internet_out, cont_intranet_in, cont_intranet_out);
            debugMessageModule(INTERFACE_STATS_EXTRA2, m, NULL, 1);
            sprintf(m, "Internet Packets processed: %-10lu  Intranet Packets processed: %-10lu  Internet Packets purged: %-10lu  Intranet Packets purged: %-10lu", 
                    total_internet, total_intranet, total_internet_purged, total_intranet_purged);
            debugMessageModule(INTERFACE_STATS_EXTRA3, m, NULL, 1);
        }
	}
	/*****************************************************************/
#endif
    // Avoid reentries
    if (reEntry)
    {
#ifdef DEBUG
        debugMessage("RE-ENTRY!!!!", COLOR_PAIR(0), 1);
#endif
        return;
    }
    else
    {
        reEntry = 1;
    }

    // Calculate panel dimensions
    getPanelDimensions();

    // Clear panels
    werase(info_panel);
    if (!no_output) {
        werase(result_panel);
    }
    wmove(info_panel, 0, 0);
    wmove(result_panel, 0, 0);

    // Show info on info panel
    if (pthread_mutex_lock(&w_globvars.mutex_cont_requests)) 
    {
        perror("refreshTop: pthread_mutex_lock with mutex_cont_requests");
        exit(1);
    }
    req = w_globvars.cont_requests;
    if (pthread_mutex_unlock(&w_globvars.mutex_cont_requests))
    {
        perror("refreshTop: pthread_mutex_unlock with mutex_cont_requests");
        exit(1);
    }
    now = time(NULL);
	t = localtime(&now);
    if (!no_output)
    {
	    sprintf(s, "%02d/%02d/%4d %02d:%02d:%02d   # Connections: %-4d   Whois requests this day: %-4u \n", t->tm_mday, t->tm_mon, 1900+t->tm_year, t->tm_hour, t->tm_min, t->tm_sec, w_globvars.result_count_lines, req);
    }
    else
    {
        strcpy(s, "                                        SCREEN FREEZED !!!!                                      \n");
    }
    mvwaddstr(info_panel, 0, 0, s);

    // Show menu on info panel
    waddstr(info_panel, "V-Change View  W-Toggle Whois database view  Q-Quit\n");

    // Show temporal info on message (if any)
    if (temp_display_seconds)
    {
        if (temp_attr) {
            wattrset(info_panel, temp_attr);
        }
        if (temp_highlight) {
            wattron(info_panel, A_BOLD);
        }

        waddstr(info_panel, temp_message);


        if (temp_attr || temp_highlight) {
            wattrset(info_panel, 0);
        }
        temp_display_seconds--;
    }
    waddstr(info_panel, "\n");

    // Show info with the view selected by user or with the default view
    switch (w_globvars.visual_mode) {
        case 0:
            // Default view. 
            // Show header
 	        sprintf(s, "%-10s %-8s  %-7s %-13s %-15s  %15s:%-5s %-5s  %-2s  %-16s  %-15s %-s\n", "DATE", "TIME", "# HITS", "TOTAL TRANS.", "BANDWIDTH", "SOURCE IP", "PORT", "FLAGS", "CT", "NET NAME", "DEST. IP", "SERVICE");
            waddstr(info_panel, s);
           
            // Show horizontal line
            whline(info_panel, 0, INFO_COLS);

            if (!no_output) {
                // Show incoming connections sorted by # hits and recent hits
                DV_ShowInfo();
            }
            break;
        case 1:
            // Source IP grouped view. 
            // Show header
 	        sprintf(s, "%-10s %-8s  %-7s %-13s %-15s  %15s  %-2s  %-16s    %-5s %-s\n", "DATE", "TIME", "# HITS", "TOTAL TRANS.", "BANDWIDTH", "SOURCE IP", "CT", "NET NAME", "FLAGS", "[#HITS]SERVICE");
            waddstr(info_panel, s);
           
            // Show horizontal line
            whline(info_panel, 0, INFO_COLS);

            if (!no_output) {
                // Show incoming connections grouped by IP and sorted by # hits and recent hits
                IPG_ShowInfo();
            }
            break;
        case 2:
            // Outbound view
            // Show header
 	        sprintf(s, "%-10s %-8s  %-7s %-13s %-15s  %15s  %15s %-5s  %-2s  %-16s  %-s\n", "DATE", "TIME", "# HITS", "TOTAL TRANS.", "BANDWIDTH", "SOURCE IP", "DESTINATION IP", "FLAGS", "CT", "NET NAME", "SERVICE");
            waddstr(info_panel, s);
           
            // Show horizontal line
            whline(info_panel, 0, INFO_COLS);

            if (!no_output) {
                // Show outgoing intranet connections sorted by bandwidth and recent hits
                ONATV_ShowInfo();
            }
            break;
    }

    // _We never allow that selected row be after total rows
    if (result_selected_row > w_globvars.result_count_lines-1) {
        result_selected_row = w_globvars.result_count_lines-1;
    }
    // If a row is selected on result panel, highlight it
    if (result_selected_row != -1)
    {
        setSelection();
    }

    if (result_visible_rows > 0)
    {
        mvwhline(result_panel, result_top_row+result_visible_rows-1, 0, 0, RESULT_COLS);
        pnoutrefresh(result_panel, result_top_row, 0, result_start_posY, 0, result_end_posY, min(RESULT_COLS-1, COLS-1));
    }
    if (info_visible_rows > 0)
    {
        pnoutrefresh(info_panel, 0, 0, 0, 0, min(INFO_LINES-1, LINES-1), min(INFO_COLS-1, COLS-1));
    }
    if (whois_visible_rows > 2 && whois_visible_cols > 2)
    {
        box(d_whois_window, 0, 0);
        touchwin(whois_panel);
        pnoutrefresh(d_whois_window, 0, 0, whois_start_posY, whois_start_posX, whois_end_posY, whois_end_posX);
    }

    // Refresh physical screen
    if (pthread_mutex_lock(&w_globvars.mutex_screen)) 
    {
        perror("refreshTop: pthread_mutex_lock with mutex_screen");
        exit(1);
    }
    doupdate();
    if (pthread_mutex_unlock(&w_globvars.mutex_screen))
    {
        perror("refreshTop: pthread_mutex_unlock with mutex_screen");
        exit(1);        
    }

    reEntry = 0;

   return;
}

void getPanelDimensions()
{
    int remaining_rows;

    // terminal was vertically resized?
    if (terminal_rows != LINES)
    {
        terminal_rows = LINES;
        result_selected_row = -1;
    }

    // Calculate visible rows for every panel
    info_visible_rows = min(LINES, INFO_LINES);
    remaining_rows = LINES-info_visible_rows;
    if (remaining_rows > 0)
    {
#ifdef DEBUG
        if (DEBUG > 0)
        {
            if ((int)(remaining_rows*DEBUG_SIZE) > 0)
            {
                debug_visible_rows = min(DEBUG_LINES, (int)(remaining_rows*DEBUG_SIZE));
            }
            else
            {
                debug_visible_rows = 1;
            }
            remaining_rows = remaining_rows - debug_visible_rows;
        }
#endif
        result_visible_rows = remaining_rows;
        if (whois_visible)
        {
            whois_visible_rows = max(0, result_visible_rows - 4);
        }
        else
        {
            whois_visible_rows = 0;
        }
    }
    else
    {
#ifdef DEBUG
        if (DEBUG > 0)
        {
            debug_visible_rows = 0;
        }
#endif
        result_visible_rows = 0;
    }

    // Calculate the terminal row where every panel starts
    info_start_posY = 0;
#ifdef DEBUG
    if (debug_visible_rows > 0)
    {
        debug_start_posY = info_visible_rows + result_visible_rows;
    }
    else
    {
        debug_start_posY = -1;
    }
#endif
    if (result_visible_rows > 0)
    {
        result_start_posY = info_visible_rows;
    }
    else
    {
        result_start_posY = -1;
    }
    if (whois_visible_rows > 0)
    {
        whois_visible_cols = min(WHOIS_COLS-1, COLS-1);
        whois_start_posX = (COLS-whois_visible_cols)/2;
        whois_end_posX = whois_start_posX + whois_visible_cols - 1;
        whois_start_posY = result_start_posY + 2;
    }
    else
    {
        whois_start_posY = -1;
    }

    // Calculate the terminal row where every panel ends
    info_end_posY = info_start_posY + info_visible_rows - 1;
#ifdef DEBUG
    if (debug_start_posY >= 0)
    {
        debug_end_posY = debug_start_posY + debug_visible_rows - 1;
    }
    else
    {
        debug_end_posY = -1;
    }
#endif
    if (result_start_posY >= 0)
    {
        result_end_posY = result_start_posY + result_visible_rows - 1;
    }
    else
    {
        result_end_posY = -1;
    }
    if (whois_start_posY >= 0)
    {
        whois_end_posY = whois_start_posY + whois_visible_rows - 1;
    }
    else
    {
        whois_end_posY = -1;
    }
}

int getTextAttrLine(int row, chtype **text) {
    int nchars;

    getPanelDimensions();
    if (*text == NULL) {
        *text = (chtype *)malloc(min(RESULT_COLS-1, COLS-1) * sizeof(chtype));
        if (*text == NULL) {
            fprintf(stderr,"getTextAttrLine: Could not allocate memory!!\n");
            exit(1);				
        }
#ifdef DEBUG
        w_globvars.allocated_others += min(RESULT_COLS-1, COLS-1) * sizeof(chtype);
#endif
    }

    nchars = mvwinchnstr(result_panel, row, 0, *text, min(RESULT_COLS-1, COLS-1));
    return nchars;
}

int getTextLine(int row, char **text, int max_size) 
{
    int i, size, nchars;
    chtype *attr_text;

    getPanelDimensions();
    attr_text = (chtype *)malloc(min(RESULT_COLS-1, COLS-1) * sizeof(chtype));
    if (attr_text == NULL) {
        fprintf(stderr,"getTextLine: Could not allocate memory!!\n");
        exit(1);				
    }

    nchars = mvwinchnstr(result_panel, row, 0, attr_text, min(RESULT_COLS-1, COLS-1));

    if (max_size != -1)
    {
        size = min(nchars, max_size);
    }
    else
    {
        size = nchars;
    }

    if (*text == NULL)
    {
        *text = (char *)malloc(size+1);
        if (*text == NULL)
        {
            fprintf(stderr,"getTextLine: Could not allocate memory!!\n");
            exit(1);				
        }
    }

    for (i=0; i < size; i++)
    {
        (*text)[i] = attr_text[i] & A_CHARTEXT;
    }
    (*text)[i] = '\0';

    free(attr_text);
    return nchars;
}

int extractIPAddress(char *text, char *address1, char *address2)
{
    int i, pos;
    char IP_pattern[] = "^.*[ \t]+([0-9]+[.][0-9]+[.][0-9]+[.][0-9]+).*$";
    char IP2_pattern[] = "^.*[ \t]+([0-9]+[.][0-9]+[.][0-9]+[.][0-9]+).*[ \t]+([0-9]+[.][0-9]+[.][0-9]+[.][0-9]+).*$";
    regex_t IP_regex;
    regmatch_t match[3];
    int count = 0;

    // First try with two IPs
    if (regcomp(&IP_regex, IP2_pattern, REG_EXTENDED))
    {
        fprintf(stderr, "extractIPAddress: Can't compile regular expression for 2 IP addresses\n");
        exit(EXIT_FAILURE);
    }
    if (!regexec(&IP_regex, text, 3, match, 0))
    {
        count = 2;
    }
    else
    {
        // Second try with one IP
        regfree(&IP_regex);
        if (regcomp(&IP_regex, IP_pattern, REG_EXTENDED))
        {
            fprintf(stderr, "extractIPAddress: Can't compile regular expression for 1 IP address\n");
            exit(EXIT_FAILURE);
        }
        if (!regexec(&IP_regex, text, 2, match, 0))
        {
            count = 1;
        }
        else
        {
            regfree(&IP_regex);
            return 0;
        }
    }

    if (match[1].rm_so == -1)
    {
        fprintf(stderr, "extractIPAddress: No match saved!\n");
        exit(EXIT_FAILURE);
    }
    if (match[1].rm_eo - match[1].rm_so >= INET_ADDRSTRLEN)
    {
        fprintf(stderr, "extractIPAddress: Extracted IP address 1 is too long!!\n");
        exit(EXIT_FAILURE);
    }
    for (i=0, pos=match[1].rm_so; pos < match[1].rm_eo; i++, pos++)
    {
        address1[i] = text[pos];
    }
    address1[i] = '\0';

    if (count == 2)
    {
        if (match[2].rm_so == -1)
        {
            regfree(&IP_regex);
            return 1;
        }
        if (match[2].rm_eo - match[2].rm_so >= INET_ADDRSTRLEN)
        {
            fprintf(stderr, "extractIPAddress: Extracted IP address 2 is too long!!\n");
            exit(EXIT_FAILURE);
        }
        for (i=0, pos=match[2].rm_so; pos < match[2].rm_eo; i++, pos++)
        {
            address2[i] = text[pos];
        }
        address2[i] = '\0';
    }

    regfree(&IP_regex);
    return count;
}

void clearSelection() {
    chtype c, attr, color;

    c = mvwinch(result_panel, result_selected_row, 0);
    color = (c & A_COLOR) >> 8;
    attr = c & A_ATTRIBUTES;
    attr = attr & (~A_COLOR);
    attr = attr & (~A_REVERSE);
    mvwchgat(result_panel, result_selected_row, 0, -1, attr, color, NULL);
}

void setSelection() {
    chtype c, attr, color;

    c = mvwinch(result_panel, result_selected_row, 0);
    color = (c & A_COLOR) >> 8;
    attr = c & A_ATTRIBUTES;
    attr = attr & (~A_COLOR);
    attr = attr | A_REVERSE;
    mvwchgat(result_panel, result_selected_row, 0, -1, attr, color, NULL);
}

void selectionDown()
{
    getPanelDimensions();

    // Is Whois window visible?
    if (whois_visible_rows > 2 && whois_visible_cols > 2)
    {
        // Yes. One line down
        if (whois_top_row + whois_visible_rows-2 < numberOfWhoisRegisters())
        {
            whois_top_row++;
            werase(whois_panel);
            showDatabase(whois_top_row, whois_visible_rows-2);
        }
        return;
    }

    if (result_selected_row >= w_globvars.result_count_lines-1)
    {
        return;
    }

    if (result_visible_rows <= 0)
    {
        return;
    }

    if (result_selected_row == -1)
    {
        result_top_row = 0;
    	result_selected_row = 0;
    }
    else
    {
        // Clear selection to the line
        clearSelection();

        result_selected_row++;
        // Have to scroll ?
        if (result_selected_row - result_top_row + 1 == result_visible_rows)
        {
        	result_top_row++;
        }
    }

    // _We never allow that selected row be after total rows
    if (result_selected_row > w_globvars.result_count_lines-1) {
        result_selected_row = w_globvars.result_count_lines-1;
    }

    // Apply selection to the line
    setSelection();
}

void selectionUp()
{
    getPanelDimensions();

    // Is Whois window visible?
    if (whois_visible_rows > 2 && whois_visible_cols > 2)
    {
        // Yes. One line up
        if (whois_top_row > 0)
        {
            whois_top_row--;
            werase(whois_panel);
            showDatabase(whois_top_row, whois_visible_rows-2);
        }
        return;
    }

    if (result_selected_row < 0) 
    {
        return;
    }

    if (result_visible_rows <= 0)
    {
        return;
    }

    // Clear selection to the line
    clearSelection();

    if (result_selected_row == 0) {
    	result_selected_row = -1;
    }
    else
    {
        // Have to scroll ?
        if (result_selected_row == result_top_row)
        {
        	result_top_row--;
        }
        result_selected_row--;

        // Apply selection to the line
        setSelection();
    }
}

void selectionPageDown()
{
    int last_visible;

    getPanelDimensions();

    // Is Whois window visible?
    if (whois_visible_rows > 2 && whois_visible_cols > 2)
    {
        // Yes. One page down
        if (whois_top_row + whois_visible_rows-2 < numberOfWhoisRegisters())
        {
            whois_top_row += whois_visible_rows-3;
            werase(whois_panel);
            showDatabase(whois_top_row, whois_visible_rows-2);
        }
        return;
    }

    if (result_selected_row >= w_globvars.result_count_lines-1) 
    {
        return;
    }

    if (result_visible_rows <= 0)
    {
        return;
    }

    if (result_selected_row == -1) {
        result_top_row = 0;
        result_selected_row = 0;
    }
    else {
        // Clear selection to the line
        clearSelection();

        // Calculate last visible row
        last_visible = result_top_row + result_visible_rows;

        // Have to scroll ?
        if (last_visible < w_globvars.result_count_lines - 1) {
            // We have to scroll
            result_selected_row = min(w_globvars.result_count_lines-1, result_selected_row + result_visible_rows-1);
            result_top_row = result_top_row + result_visible_rows;
        }
        else {
            // Scroll is not needed. We just go to last row 
            result_selected_row = w_globvars.result_count_lines - 1;
        }
    }

    // Apply selection to the line
    setSelection();
}

void selectionPageUp()
{
    getPanelDimensions();

    // Is Whois window visible?
    if (whois_visible_rows > 2 && whois_visible_cols > 2)
    {
        // Yes. One page up
        if (whois_top_row > 0)
        {
            whois_top_row = max(0, whois_top_row - (whois_visible_rows-3));
            werase(whois_panel);
            showDatabase(whois_top_row, whois_visible_rows-2);
        }
        return;
    }

    if (result_selected_row < 0) 
    {
        return;
    }

    if (result_visible_rows <= 0)
    {
        return;
    }

    // Clear selection to the line
    clearSelection();

   if (result_selected_row == 0)
    {
    	result_selected_row = -1;
    }
    else
    {
        // Have to scroll ?
        if (result_top_row > 0) {
            // We have to scroll
            result_selected_row = max(0, result_selected_row - result_visible_rows);
            result_top_row = result_top_row - result_visible_rows;
        }
        else {
            // Scroll is not needed. We just go to first row
            result_selected_row = 0;
        }
        // Apply selection to the line
        setSelection();
    }
}

void selectionStart()
{
    getPanelDimensions();

    // Is Whois window visible?
    if (whois_visible_rows > 2 && whois_visible_cols > 2)
    {
        // Yes. At the beggining
        if (whois_top_row > 0)
        {
            whois_top_row = 0;
            werase(whois_panel);
            showDatabase(whois_top_row, whois_visible_rows-2);
        }
        return;
    }

    if (result_selected_row <= 0) 
    {
        return;
    }

    if (result_visible_rows <= 0)
    {
        return;
    }

    // Clear selection to the line
    clearSelection();       

	result_selected_row = 0;
	result_top_row = 0;

    // Apply selection to the line
    setSelection();
}

void selectionEnd()
{
    getPanelDimensions();

    // Is Whois window visible?
    if (whois_visible_rows > 2 && whois_visible_cols > 2)
    {
        // Yes. At the end
        if (whois_top_row + whois_visible_rows-2 < numberOfWhoisRegisters())
        {
            whois_top_row = max(0, numberOfWhoisRegisters() - (whois_visible_rows-2));
            werase(whois_panel);
            showDatabase(whois_top_row, whois_visible_rows-2);
        }
        return;
    }

    if (result_selected_row >= w_globvars.result_count_lines-1) 
    {
        return;
    }

    if (result_visible_rows <= 0)
    {
        return;
    }

    if (result_selected_row != -1)  {
        // Clear selection to the line
        clearSelection();
    }

    result_selected_row = w_globvars.result_count_lines-1;
    result_top_row =  max(0, w_globvars.result_count_lines - result_visible_rows);

    // Apply selection to the line
    setSelection();
}
    
void resetInterface()
{
    // Paneles:
    // info_panel
    // result_panel
    // debug_panel  (solo si DEBUG > 0)
    clearok(main_screen,  true);
    //  wclear(main_screen);
    wrefresh(main_screen);
}

void quitInterface()
{
    //rt.stop()
    nocbreak();
    keypad(main_screen, FALSE);
    echo();
    endwin();
    //f_log.close()
}

void changeView() 
{
    char key;
    int new_visual_mode;

    mvwaddstr(info_panel, 2, 0, "1-Default view   2-Grouped by source IP   3-NAT view  (Any other key to abort)\n");

    // Refresh panels
    getPanelDimensions();

    if (pthread_mutex_lock(&w_globvars.mutex_screen)) 
    {
        perror("changeView: pthread_mutex_lock with mutex_screen");
        exit(1);
    }
    prefresh(info_panel, 0, 0, 0, 0, min(INFO_LINES-1, LINES-1), min(INFO_COLS-1, COLS-1));
    if (pthread_mutex_unlock(&w_globvars.mutex_screen))
    {
        perror("changeView: pthread_mutex_unlock with mutex_screen");
        exit(1);        
    }

    key = wgetch(info_panel);

    // We do nothing if view has not been changed or key is not valid
    new_visual_mode = key - '1';
    if (new_visual_mode == w_globvars.visual_mode || key < '1' || key > '3') {
        return;
    }

    // If visual mode needs intranet device and it doesn't set then return
    if (new_visual_mode == 2 && c_globvars.intranet_dev == NULL) {
        // Can't do NAT view. There is not intranet device
        return;
    }

    // Reset current view
    switch (w_globvars.visual_mode) {
        case 0:
            // Default view
            // Can't do NAT view. There is not intranet device
            //DV_Reset();
            break;

        case 1:
            // Grouped source IP view
            // Can't do NAT view. There is not intranet device
            //IPG_Reset();
            break;

        case 2:
            // NAT view
            // Can't do NAT view. There is not intranet device
            //OV_Reset();
            break;
    }

    // Change view
    w_globvars.view_started = time(NULL);
    w_globvars.visual_mode = new_visual_mode;
}

void UI_banIP(int ban)
{
    int size;
    char *text;
    char s_address1[INET_ADDRSTRLEN], s_address2[INET_ADDRSTRLEN];
    int n_IPs;
    char *ip2ban = NULL;
    in_addr_t address1, address2;
    char m[100];


    // Any row selected?
    if (result_selected_row < 0)
    {
        return;
    }
    // Get selected text
    text = NULL;
    size = getTextLine(result_selected_row, &text, -1);
    if (size)
    {
        n_IPs = extractIPAddress(text, s_address1, s_address2);
        free(text);
        if (!n_IPs)
        {
            fprintf(stderr, "\nNO HAY NINGUNA IP!!!!\n");
            exit(EXIT_FAILURE);
        }

        inet_pton(AF_INET, s_address1, &address1);
        if (externalIP(address1))
        {
            ip2ban = s_address1;
        }
        else
        {
            if (n_IPs == 2)
            {
                inet_pton(AF_INET, s_address2, &address2);
                if (externalIP(address2))
                {
                    ip2ban = s_address2;
                }
            }
        }

        if (ip2ban != NULL)
        {
            if (ban)
            {
                if (banIP(ip2ban))
                {
                    sprintf(m, "IP address %s has been banned!!", ip2ban);
                    writeLineOnInfo(m, 0, 1, 5);
                }
                else
                {
                    sprintf(m, "Ups! Something failed when trying to ban IP address %s!!", ip2ban);
                    writeLineOnInfo(m, 0, 1, 5);
                }
            }
            else
            {
                if (unbanIP(ip2ban))
                {
                    sprintf(m, "IP address %s has been UNbanned!!", ip2ban);
                    writeLineOnInfo(m, 0, 1, 5);
                }
                else
                {
                    sprintf(m, "Ups! Something failed when trying to unban IP address %s!!", ip2ban);
                    writeLineOnInfo(m, 0, 1, 5);
                }
            }
        }
        else
        {
            // Internal address. Can't ban
            writeLineOnInfo("Can't ban/unban an internal address!!", 0, 1, 5);
        }
    }
}

void showWhoisDatabase()
{
    // Show/Hide Whois window
    whois_visible = !whois_visible;

    // Window visible?
    if (!whois_visible)
    {
        // Destroy the whois panel and its derivated
        if (whois_panel != NULL)
        {
            delwin(whois_panel);
        }
        if (d_whois_window != NULL)
        {
            delwin(d_whois_window);
        }
    }

    // Refresh panels
    getPanelDimensions();

    // Is Window visible and has more than 2 columns and 2 rows?
    if (whois_visible_rows > 2 && whois_visible_cols > 2)
    {
        // Create whois panel
        whois_panel = NULL;
        d_whois_window = NULL;
        whois_panel = newpad(whois_visible_rows, WHOIS_COLS);
        if (whois_panel == NULL)
        {
            fprintf(stderr, "showWhoisDatabase: Can't create whois window\n");
            exit(1);                   
        }

        // Create a subpanel to print a window border (box)
        d_whois_window = subpad(whois_panel, whois_visible_rows, whois_visible_cols, 0, 0);
        if (d_whois_window == NULL)
        {
            fprintf(stderr, "showWhoisDatabase: Can't create whois window with %0d lines and %0d cols\n", whois_visible_rows, whois_visible_cols);
            exit(1);                   
        }

        // Show Whois database info
        showDatabase(whois_top_row, whois_visible_rows-2);
    }
}
