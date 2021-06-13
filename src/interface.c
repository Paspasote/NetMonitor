#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <semaphore.h>
#include <pthread.h>

#include <debug.h>
#include <misc.h>
#include <GlobalVars.h>
#include <NetMonitor.h>
#include <PacketList.h>
#include <DefaultView.h>
#include <IPGroupedView.h>
#include <OutboundView.h>

#include <interface.h>

// Constants

// Panel sizes
#define INFO_LINES		5
#define INFO_COLS		200
#define RESULT_LINES	10000
#define RESULT_COLS		200

// EXTERNAL global vars
extern struct const_global_vars c_globvars;
extern struct write_global_vars w_globvars;


// global vars
int reEntry = 0;
int no_output = 0;

int result_selected_row = -1;
int result_start_posY;
int result_end_posY;
int result_visible_rows;
int result_top_row = 0;
int info_start_posY;
int info_end_posY;
int info_visible_rows;
int info_top_row = 0;
int debug_start_posY;
int debug_end_posY;
int debug_visible_rows = 0;
int debug_top_row = 0;
int terminal_rows;

WINDOW *main_screen, *info_panel, *result_panel;

// Function prototypes
void user_interface();
void init_curses();
void refreshTop();
void getPanelDimensions();
int getTextAttrLine(int row, chtype **text);
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


void *interface(void *ptr_paramt) {
    if (w_globvars.visual_mode != -1) {
        init_curses();
    }

    /**************************************** DEBUG ****************************
    printConfDict(incoming_services_allow);
    printConfDict(incoming_services_warning);
    ***************************************************************************/

	while (1)
	{
        if (w_globvars.visual_mode != -1) {
            /***************************  DEBUG ****************************/
            char m[255];
            sprintf(m, "En el bucle principal del interface......                                ");
            debugMessageXY(3, 45, m, NULL, 1);
            /*****************************************************************/
    		user_interface();
            refreshTop();
            sleep(1);
        }
        else {            
            // Debug mode. Prints all info
            show_info();
        }
	}
}

void user_interface()
{
	int key;

 	/***************************  DEBUG ****************************/
	{
		char m[255];
		sprintf(m, "Entrando en user_interface...                                     ");
		debugMessageXY(3, 45, m, NULL, 1);
	}
	/*****************************************************************/

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

        case KEY_DOWN:
            if (result_selected_row < w_globvars.result_count_lines-1)
            {
                selectionDown();
            }
            break;

        case KEY_UP:
            if (result_selected_row >= 0) {
                selectionUp();
            }
            break;

        case KEY_NPAGE:
            if (result_selected_row < w_globvars.result_count_lines-1) {
                selectionPageDown();
            }
            break;

        case KEY_PPAGE:
            if (result_selected_row >= 0) {
                selectionPageUp();
            }
            break;

        case KEY_END:
            if (result_selected_row < w_globvars.result_count_lines-1) {
                selectionEnd();
            }
            break;

        case KEY_HOME:
            if (result_selected_row > 0) {
                selectionStart();
            }
            break;
    }

 	/***************************  DEBUG ****************************/
	{
		char m[255];
		sprintf(m, "Saliendo de user_interface...                                        ");
		debugMessageXY(3, 45, m, NULL, 1);
	}
	/*****************************************************************/


    /*
    // Want to see the history?
    if (DEPURACION > 0)
    {
    	if (key == 'R' || key == 'r')
    	{
         	no_output = TRUE;
            debugShowRecords(records);
            no_output = FALSE;
        }
    }
    */

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


	// Create debug panel
    init_debug_panel(INFO_LINES);

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


    if (attr) {
    	wattrset(result_panel, 0);
    }
 }

void refreshTop()
{
    time_t now;
	struct tm *t;
	char s[150];
    unsigned req;

 	/***************************  DEBUG ****************************/
	{
		char m[255];
		sprintf(m, "Entrando en refreshTop...                                        ");
		debugMessageXY(3, 45, m, NULL, 1);
	}
	/*****************************************************************/

    // Avoid reentries
    if (reEntry)
    {
        debugMessage("RE-ENTRY!!!!", COLOR_PAIR(0), 1);
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
    if (sem_wait(&w_globvars.mutex_cont_requests)) 
    {
        perror("refreshTop: sem_wait with mutex_cont_requests");
        exit(1);
    }
    req = w_globvars.cont_requests;
    if (sem_post(&w_globvars.mutex_cont_requests))
    {
        perror("refreshTop: sem_post with mutex_cont_requests");
        exit(1);
    }
    now = time(NULL);
	t = localtime(&now);
    if (!no_output)
    {
	    sprintf(s, "%02d/%02d/%4d %02d:%02d:%02d   # Connections: %-4d   Whois requests this day: %-4u\n", t->tm_mday, t->tm_mon, 1900+t->tm_year, t->tm_hour, t->tm_min, t->tm_sec, w_globvars.result_count_lines, req);
    }
    else
    {
        strcpy(s, "                                        SCREEN FREEZED !!!!                                      \n");
    }
    mvwaddstr(info_panel, 0, 0, s);

    // Show menu on info panel
    waddstr(info_panel, "V-Change View  Q-Exit\n\n");

    // Show info with the view selected by user or with the default view
    switch (w_globvars.visual_mode) {
        case 0:
            // Default view. 
            // Show header
 	        sprintf(s, "%-10s %-8s  %-7s %-13s %-15s  %15s:%-5s %-5s  %-2s  %-16s  %-s\n", "DATE", "TIME", "# HITS", "TOTAL TRANS.", "BANDWIDTH", "SOURCE IP", "PORT", "FLAGS", "CT", "NET NAME", "SERVICE");
            waddstr(info_panel, s);
           
            // Show horizontal line
            whline(info_panel, '-', INFO_COLS);

            // Clear timeout connections
            DV_Purge();

            if (!no_output) {
                // Show incoming connections sorted by # hits and recent hits
                DV_ShowInfo();
            }
            break;
        case 1:
            // Source IP grouped view. 
            // Show header
 	        sprintf(s, "%-10s %-8s  %-7s %-13s %-15s  %15s %-5s  %-2s  %-16s    %-s\n", "DATE", "TIME", "# HITS", "TOTAL TRANS.", "BANDWIDTH", "SOURCE IP", "FLAGS", "CT", "NET NAME", "[#HITS]SERVICE");
            waddstr(info_panel, s);
           
            // Show horizontal line
            whline(info_panel, '-', INFO_COLS);

            // Clear timeout connections
            IPG_Purge();

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
            whline(info_panel, '-', INFO_COLS);

            // Clear timeout connections
            OV_Purge();
            if (!no_output) {
                // Show outgoing intranet connections sorted by bandwidth and recent hits
                OV_ShowInfo();
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

    if (DEBUG > 0 && result_visible_rows > 0)
    {
        mvwhline(result_panel, result_top_row+result_visible_rows-1, 0, '_', RESULT_COLS);
    }
    else {
        mvwhline(result_panel, result_top_row+result_visible_rows-1, 0, '_', RESULT_COLS);
    }

    if (result_visible_rows > 0)
    {
        pnoutrefresh(result_panel, result_top_row, 0, result_start_posY, 0, result_end_posY, min(RESULT_COLS-1, COLS-1));
    }
    if (info_visible_rows > 0)
    {
        pnoutrefresh(info_panel, 0, 0, 0, 0, min(INFO_LINES-1, LINES-1), min(INFO_COLS-1, COLS-1));
    }

    // Refresh physical screen
    if (sem_wait(&w_globvars.mutex_screen)) 
    {
        perror("refreshTop: sem_wait with mutex_screen");
        exit(1);
    }
    doupdate();
    if (sem_post(&w_globvars.mutex_screen))
    {
        perror("refreshTop: sem_post with mutex_screen");
        exit(1);        
    }

    reEntry = 0;
  	/***************************  DEBUG ****************************/
	{
		char m[255];
		sprintf(m, "Saliendo de refreshTop...                                        ");
		debugMessageXY(3, 45, m, NULL, 1);
	}
	/*****************************************************************/

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
        result_visible_rows = remaining_rows;
    }
    else
    {
        if (DEBUG > 0)
        {
            debug_visible_rows = 0;
        }
        result_visible_rows = 0;
    }

    // Calculate the terminal row where every panel starts
    info_start_posY = 0;
    if (debug_visible_rows > 0)
    {
        debug_start_posY = info_visible_rows + result_visible_rows;
    }
    else
    {
        debug_start_posY = -1;
    }
    if (result_visible_rows > 0)
    {
        result_start_posY = info_visible_rows;
    }
    else
    {
        result_start_posY = -1;
    }

    // Calculate the terminal row where every panel ends
    info_end_posY = info_start_posY + info_visible_rows - 1;
    if (debug_start_posY >= 0)
    {
        debug_end_posY = debug_start_posY + debug_visible_rows - 1;
    }
    else
    {
        debug_end_posY = -1;
    }
    if (result_start_posY >= 0)
    {
        result_end_posY = result_start_posY + result_visible_rows - 1;
    }
    else
    {
        result_end_posY = -1;
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
    }

    nchars = mvwinchnstr(result_panel, row, 0, *text, min(RESULT_COLS-1, COLS-1));
    return nchars;
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
/* 
    // Refresh result panel with new selection
    if (sem_wait(&mutex_screen)) 
    {
        perror("selectionDown: sem_wait with mutex_screen");
        exit(1);
    }
    prefresh(result_panel, result_top_row, 0, result_start_posY, 0, result_end_posY, min(RESULT_COLS-1, COLS-1));
    if (sem_post(&mutex_screen))
    {
        perror("selectionDown: sem_post with mutex_screen");
        exit(1);        
    }
 */
}

void selectionUp()
{
    getPanelDimensions();

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

/*     // Refresh result panel with new selection
    if (sem_wait(&mutex_screen)) 
    {
        perror("selectionDown: sem_wait with mutex_screen");
        exit(1);
    }
    prefresh(result_panel, result_top_row, 0, result_start_posY, 0, result_end_posY, min(RESULT_COLS-1, COLS-1));
    if (sem_post(&mutex_screen))
    {
        perror("selectionDown: sem_post with mutex_screen");
        exit(1);        
    }
 */    
}

void selectionPageDown()
{
    int last_visible;

    getPanelDimensions();

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

/*     // Refresh result panel with new selection
    if (sem_wait(&mutex_screen)) 
    {
        perror("selectionDown: sem_wait with mutex_screen");
        exit(1);
    }
    prefresh(result_panel, result_top_row, 0, result_start_posY, 0, result_end_posY, min(RESULT_COLS-1, COLS-1));
    if (sem_post(&mutex_screen))
    {
        perror("selectionDown: sem_post with mutex_screen");
        exit(1);        
    }
 */    
}

void selectionPageUp()
{
    getPanelDimensions();

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

/*     // Refresh result panel with new selection
    if (sem_wait(&mutex_screen)) 
    {
        perror("selectionDown: sem_wait with mutex_screen");
        exit(1);
    }
    prefresh(result_panel, result_top_row, 0, result_start_posY, 0, result_end_posY, min(RESULT_COLS-1, COLS-1));
    if (sem_post(&mutex_screen))
    {
        perror("selectionDown: sem_post with mutex_screen");
        exit(1);        
    }
 */    
}

void selectionStart()
{
    getPanelDimensions();

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

/*     // Refresh result panel with new selection
    if (sem_wait(&mutex_screen)) 
    {
        perror("selectionDown: sem_wait with mutex_screen");
        exit(1);
    }
    prefresh(result_panel, result_top_row, 0, result_start_posY, 0, result_end_posY, min(RESULT_COLS-1, COLS-1));
    if (sem_post(&mutex_screen))
    {
        perror("selectionDown: sem_post with mutex_screen");
        exit(1);        
    }
 */    
}

void selectionEnd()
{
    getPanelDimensions();

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

/*     // Refresh result panel with new selection
    if (sem_wait(&mutex_screen)) 
    {
        perror("selectionDown: sem_wait with mutex_screen");
        exit(1);
    }
    prefresh(result_panel, result_top_row, 0, result_start_posY, 0, result_end_posY, min(RESULT_COLS-1, COLS-1));
    if (sem_post(&mutex_screen))
    {
        perror("selectionDown: sem_post with mutex_screen");
        exit(1);        
    }
 */    
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
    waddstr(info_panel, "IF VIEW CHANGES ALL INFO WILL BE RESET!!\n");

    // Refresh panels
    getPanelDimensions();

    if (sem_wait(&w_globvars.mutex_screen)) 
    {
        perror("changeView: sem_wait with mutex_screen");
        exit(1);
    }
    prefresh(info_panel, 0, 0, 0, 0, min(INFO_LINES-1, LINES-1), min(INFO_COLS-1, COLS-1));
    if (sem_post(&w_globvars.mutex_screen))
    {
        perror("changeView: sem_post with mutex_screen");
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
        /***************************  DEBUG ***************************/
        {
            char m[100];
            sprintf(m, "Can't change to NAT view. There is not intranet device");
            debugMessageXY(5, 0, m, NULL, 1);
        }
        /****************************************************************/
        return;
    }

    // Reset current view
    switch (w_globvars.visual_mode) {
        case 0:
            // Default view
            // Can't do NAT view. There is not intranet device
            /***************************  DEBUG ***************************/
            {
                char m[100];
                sprintf(m, "Resetting view 0");
                debugMessageXY(2, 0, m, NULL, 1);
            }
            /****************************************************************/
            DV_Reset();
            break;

        case 1:
            // Grouped source IP view
            // Can't do NAT view. There is not intranet device
            /***************************  DEBUG ***************************/
            {
                char m[100];
                sprintf(m, "Resetting view 1");
                debugMessageXY(2, 0, m, NULL, 1);
            }
            IPG_Reset();
            break;

        case 2:
            // NAT view
            // Can't do NAT view. There is not intranet device
            /***************************  DEBUG ***************************/
            {
                char m[100];
                sprintf(m, "Resetting view 2");
                debugMessageXY(2, 0, m, NULL, 1);
            }
            OV_Reset();
            break;
    }

    // Change view
    w_globvars.view_started = time(NULL);
    w_globvars.visual_mode = new_visual_mode;
}
