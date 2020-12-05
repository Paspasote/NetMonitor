#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <semaphore.h>
#include <pthread.h>

#include <debug.h>
#include <misc.h>
#include <PacketList.h>
#include <DefaultView.h>
#include <IPGroupedView.h>
#include <interface.h>

// Constants

// Panel sizes
#define INFO_LINES		3
#define INFO_COLS		200
#define RESULT_LINES	10000
#define RESULT_COLS		200

// Function prototypes
void user_interface();
void init_curses();
void refreshTop();
void getPanelDimensions();
void selectionDown();
void selectionUp();
void selectionPageDown();
void selectionPageUp();
void selectionStart();
void selectionEnd();
void quitInterface();
void changeView();

// global vars
extern sem_t mutex_screen;

int reEntry = 0;
int no_output = 0;
int visual_mode = 0;

int result_selected_row = -1;
int result_start_posY;
int result_end_posY;
int result_visible_rows;
int result_top_row = 0;
int result_count_lines;
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

void *interface()
{
    if (visual_mode != -1) {
        init_curses();
    }

    /**************************************** DEBUG ****************************
    printConfDict(services_allow);
    printConfDict(services_warning);
    ***************************************************************************/

	while (1)
	{
        if (visual_mode != -1) {
    		user_interface();
            refreshTop();
        }
        else {            
            // Debug mode. Prints all info
            show_info();
        }

        sleep(1);
	}
}

void user_interface()
{
	char key;

	// User has pressed a key?
	key = wgetch(result_panel);

    switch (key) {
        case 'q':
        case 'Q':
            quitInterface();
            exit(0);
            break;

        case 'v':
        case 'V':
            if (info_visible_rows >= 2)
            {
                changeView();
            }
            break;

        case (char)KEY_DOWN:
            if (result_selected_row < result_count_lines-1)
            {
                selectionDown();
            }
            break;

        case (char)KEY_UP:
            if (result_selected_row >= 0) {
                selectionUp();
            }
            break;

        case (char)KEY_NPAGE:
            if (result_selected_row < result_count_lines-1) {
                selectionPageDown();
            }
            break;

        case (char)KEY_PPAGE:
            if (result_selected_row >= 0) {
                selectionPageUp();
            }
            break;

        case (char)KEY_END:
            if (result_selected_row < result_count_lines-1) {
                selectionEnd();
            }
            break;

        case (char)KEY_HOME:
            if (result_selected_row > 0) {
                selectionStart();
            }
            break;
    }


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

void writeLineOnResult(char *text, attr_t *attr) 
{
    int x, y;

    // Get current cursor position
    getyx(result_panel, y, x);

    // Check if there are free lines
    if (y >= RESULT_LINES-1) {
        return;
    }

    // Write message on panel
    if (attr != NULL) {
        wattron(result_panel, *attr);
    }

    waddstr(result_panel, text);

    if (attr != NULL) {
    	wattroff(result_panel, *attr);
    }
 }

void refreshTop()
{
    time_t now;
	struct tm *t;
	char s_time[25];

    if (no_output)
    {
        debugMessage("OUTPUT FREEZEED!!!!", COLOR_PAIR(0), 1);
        return;
    }

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
    werase(result_panel);
    wmove(info_panel, 0, 0);
    wmove(result_panel, 0, 0);

    // Show time and options on info panel 
    now = time(NULL);
	t = localtime(&now);
	sprintf(s_time, "%02d/%02d/%4d %02d:%02d:%02d\n", t->tm_mday, t->tm_mon, 1900+t->tm_year, t->tm_hour, t->tm_min, t->tm_sec);
    mvwaddstr(info_panel, 0, 0, s_time);
    waddstr(info_panel, "V-Change View  Q-Exit\n");
    whline(info_panel, '-', INFO_COLS);

    // Show info with the view selected by user or with the default view
    switch (visual_mode) {
        case 0:
            // Default view. 
            DV_Purge();
            DV_ShowInfo();
            break;
        case 1:

            // Source IP grouped view. 
            IPG_Purge();
            IPG_ShowInfo();
            break;
    }

    // _We never allow that selected row be after total rows
    if (result_selected_row > result_count_lines-1) {
        result_selected_row = result_count_lines-1;
    }


    if (no_output)
    {
        reEntry = 0;
        return;
    }

    // If a row is selected on result panel, highlight it
    if (result_selected_row != -1)
    {
        mvwchgat(result_panel, result_selected_row, 0, -1, A_REVERSE, COLOR_BLACK, NULL);
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

    if (sem_wait(&mutex_screen)) 
    {
        perror("writeLineOnResult: sem_wait with mutex_screen");
        exit(1);
    }
    doupdate();
    if (sem_post(&mutex_screen))
    {
        perror("writeLineOnResult: sem_post with mutex_screen");
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
        result_selected_row++;
        // Have to scroll ?
        if (result_selected_row - result_top_row + 1 == result_visible_rows)
        {
        	result_top_row++;
        }
    }
    refreshTop();
}

void selectionUp()
{
    getPanelDimensions();

    if (result_visible_rows <= 0)
    {
        return;
    }

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
    }
    refreshTop();
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
        // Calculate last visible row
        last_visible = result_top_row + result_visible_rows;

        // Have to scroll ?
        if (last_visible < result_count_lines - 1) {
            // We have to scroll
            result_selected_row = min(result_count_lines-1, result_selected_row + result_visible_rows-1);
            result_top_row = result_top_row + result_visible_rows;
        }
        else {
            // Scroll is not needed. We just go to last row 
            result_selected_row = result_count_lines - 1;
        }
    }

    refreshTop();
}

void selectionPageUp()
{
    getPanelDimensions();

    if (result_visible_rows <= 0)
    {
        return;
    }

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
    }
    refreshTop();
}

void selectionStart()
{
    getPanelDimensions();

    if (result_visible_rows <= 0)
    {
        return;
    }

	result_selected_row = 0;
	result_top_row = 0;
    refreshTop();
}

void selectionEnd()
{
    getPanelDimensions();

    if (result_visible_rows <= 0)
    {
        return;
    }

    result_selected_row = result_count_lines-1;
    result_top_row =  max(0, result_count_lines - result_visible_rows);
    refreshTop();
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

    mvwaddstr(info_panel, 0, 0, "1-Default view   2-Grouped by source IP   (Any other key to abort)\n");
    waddstr(info_panel, "IF VIEW CHANGES ALL INFO WILL BE RESET!!\n");

    // Refresh panels
    getPanelDimensions();

    pnoutrefresh(info_panel, 0, 0, 0, 0, min(INFO_LINES-1, LINES-1), min(INFO_COLS-1, COLS-1));
 
    if (sem_wait(&mutex_screen)) 
    {
        perror("changeView: sem_wait with mutex_screen");
        exit(1);
    }
    doupdate();
    if (sem_post(&mutex_screen))
    {
        perror("changeView: sem_post with mutex_screen");
        exit(1);        
    }

    key = wgetch(info_panel);

    // We do nothing if view has not been changed or key is not valid
    if (key - '1' == visual_mode || key < '1' || key > '2') {
        return;
    }

    // Reset current view
    switch (visual_mode) {
        case 0:
            // Default view
            DV_Reset();
            break;

        case 1:
            // Grouped source IP view
            IPG_Reset();
            break;
    }

    // Change view
    visual_mode = key - '1';
}
