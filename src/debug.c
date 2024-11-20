#ifdef DEBUG

#include <stdlib.h>
#include <string.h>
#include <ncurses.h>
#include <semaphore.h>

#include <misc.h>
#include <GlobalVars.h>
#include <debug.h>


// External Global vars
extern struct write_global_vars w_globvars;

// Global vars
WINDOW *debug_panel;
unsigned info_lines;

void init_debug_panel(unsigned lines) {
	if (DEBUG > 0)
	{
		info_lines = lines;

    	debug_panel = newpad(DEBUG_LINES, DEBUG_COLS);
    	nodelay(debug_panel, TRUE);
    	scrollok(debug_panel, TRUE);
    	idlok(debug_panel, TRUE);
    	keypad(debug_panel, TRUE);
    }
}

void debugMessage(char *message, attr_t *attr, unsigned prioridad)
{
    int posY_debug, debug_lines;

    // Message allowed?
    if (DEBUG < prioridad) {
    	return;
    }

    // Get exclusive use of the panel
    if (pthread_mutex_lock(&w_globvars.mutex_debug_panel)) 
    {
        perror("debugMessageXY: pthread_mutex_lock with mutex_debug_panel");
        exit(1);
    }

    // Calculate position of debug panel
    debug_lines = min(DEBUG_LINES, (int)((LINES-info_lines)*DEBUG_SIZE));
    posY_debug = LINES - debug_lines;

    // Write message on panel
    if (attr != NULL) {
        wattron(debug_panel, *attr);
    }
    else {
        wstandend(debug_panel);
    }
    waddstr(debug_panel, message);

    // Refresh debug panel
    if (pthread_mutex_lock(&w_globvars.mutex_screen)) 
    {
        perror("debugMessage: pthread_mutex_lock with mutex_screen");
        exit(1);
    }
    prefresh(debug_panel, 0, 0, posY_debug, 0, min(posY_debug+DEBUG_LINES-1, LINES-1), min(COLS, COLS-1));
    if (pthread_mutex_unlock(&w_globvars.mutex_screen))
    {
        perror("debugMessage: pthread_mutex_unlock with mutex_screen");
        exit(1);        
    }

    // Release panel
    if (pthread_mutex_unlock(&w_globvars.mutex_debug_panel))
    {
        perror("debugMessage: pthread_mutex_unlock with mutex_debug_panel");
        exit(1);        
    }
    //sleep(3);

}

void debugMessageXY(int row, int col, char *message, attr_t *attr, unsigned prioridad)
{
    int posY_debug, debug_lines;
    int x, y;


    // Message allowed?
    if (DEBUG < prioridad) {
        return;
    }

    // Get exclusive use of the panel
    if (pthread_mutex_lock(&w_globvars.mutex_debug_panel)) 
    {
        perror("debugMessageXY: pthread_mutex_lock with mutex_debug_panel");
        exit(1);
    }

    // Get current cursor position
    getyx(debug_panel, y, x);

    // Calculate position of debug panel
    debug_lines = min(DEBUG_LINES, (int)((LINES-info_lines)*DEBUG_SIZE));
    posY_debug = LINES - debug_lines;

    // Write message on Y,X position of the debug panel
    if (attr != NULL) {
        wattron(debug_panel, *attr);
    }
    else {
        wstandend(debug_panel);
    }
    mvwaddstr(debug_panel, row, col, message);

    // Restore cursor position
    wmove(debug_panel, y, x);


     // Refresh debug panel
    if (pthread_mutex_lock(&w_globvars.mutex_screen)) 
    {
        perror("debugMessage: pthread_mutex_lock with mutex_screen");
        exit(1);
    }
    prefresh(debug_panel, 0, 0, posY_debug, 0, min(posY_debug+DEBUG_LINES-1, LINES-1), min(COLS, COLS-1));
    if (pthread_mutex_unlock(&w_globvars.mutex_screen))
    {
        perror("debugMessage: pthread_mutex_unlock with mutex_screen");
        exit(1);        
    }

    // Release panel
    if (pthread_mutex_unlock(&w_globvars.mutex_debug_panel))
    {
        perror("debugMessageXY: pthread_mutex_unlock with mutex_debug_panel");
        exit(1);        
    }
    //sleep(3);
}

void debugMessageModule(int module, char *message, attr_t *attr, unsigned prioridad)
{
    int x, y;
    char msg[DEBUG_COLS+1];
    size_t i, size;

    // Calculate line size of the module
    if (module == WHOIS || module == WHOIS_EXTRA || module == INTERFACE_STATS ||
        module == INTERFACE_STATS_EXTRA1 || module == INTERFACE_STATS_EXTRA2 ||
        module == INTERFACE_STATS_EXTRA3)
    {
        size = DEBUG_COLS;
    }
    else
    {
        size = MODULE_MESSAGE_SIZE;
    }

    // Adjust message to exactly size characters
    if (strlen(message) > size)
    {
        strncpy(msg, message, size);
        msg[size] = '\0';
    }
    else
    {
        if (strlen(message) < size)
        {
            strcpy(msg, message);
            for (i=strlen(message); i<size; i++)
            {
                strcat(msg, " ");
            }
        }
        else
        {
            strcpy(msg, message);
        }
    }

    // Calculate X,Y position of the module
    switch (module)
    {
        case INTERNET_SNIFFER:
            x = SNIFFER_INTERNET_THREAD_COL;
            y = SNIFFER_THREAD_ROW;
            break;
        case INTRANET_SNIFFER:
            x = SNIFFER_INTRANET_THREAD_COL;
            y = SNIFFER_THREAD_ROW;
            break;
        case INTERNET_CONNECTIONS_TRACKER:
            x = INTERNET_TRACKER_THREAD_COL;
            y = TRACKER_THREAD_ROW;
            break;
        case INTERNET_CONNECTIONS_TRACKER_INFO:
            x = INTERNET_TRACKER_THREAD_COL;
            y = TRACKER_THREAD_ROW+1;
            break;
        case INTRANET_CONNECTIONS_TRACKER:
            x = INTRANET_TRACKER_THREAD_COL;
            y = TRACKER_THREAD_ROW;
            break;
        case INTRANET_CONNECTIONS_TRACKER_INFO:
            x = INTRANET_TRACKER_THREAD_COL;
            y = TRACKER_THREAD_ROW+1;
            break;
        case CONNECTIONS_PURGER:
            x = PURGE_THREAD_COL;
            y = PURGE_THREAD_ROW;
            break;
        case WHOIS:
            x = WHOIS_THREAD_COL;
            y = WHOIS_THREAD_ROW;
            break;
        case WHOIS_EXTRA:
            x = WHOIS_THREAD_EXTRA_COL;
            y = WHOIS_THREAD_ROW;
            break;
        case INTERFACE:
            x = INTERFACE_THREAD_COL;
            y = INTERFACE_THREAD_ROW;
            break;
        case INTERFACE_STATS:
            x = INTERFACE_THREAD_COL;
            y = INTERFACE_THREAD_STATS_ROW;
            break;
        case INTERFACE_STATS_EXTRA1:
            x = INTERFACE_THREAD_COL;
            y = INTERFACE_THREAD_STATS_ROW+1;
            break;
        case INTERFACE_STATS_EXTRA2:
            x = INTERFACE_THREAD_COL;
            y = INTERFACE_THREAD_STATS_ROW+2;
            break;
        case INTERFACE_STATS_EXTRA3:
            x = INTERFACE_THREAD_COL;
            y = INTERFACE_THREAD_STATS_ROW+3;
            break;
        default:
            return;
    }

    debugMessageXY(y, x, msg, attr, prioridad);

}

#endif