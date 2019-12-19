#include <stdlib.h>
#include <ncurses.h>
#include <semaphore.h>

#include <misc.h>
#include <debug.h>

// Global vars
extern sem_t mutex_screen;
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
    int x, y;

    // Message allowed?
    if (DEBUG < prioridad) {
    	return;
    }

    // Get current cursor position
    getyx(debug_panel, y, x);

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
    prefresh(debug_panel, 0, 0, posY_debug, 0, min(posY_debug+DEBUG_LINES-1, LINES-1), min(COLS, COLS-1));

    if (sem_wait(&mutex_screen)) 
    {
        perror("debugMessage: sem_wait with mutex_screen");
        exit(1);
    }
    doupdate();
    if (sem_post(&mutex_screen))
    {
        perror("debugMessage: sem_post with mutex_screen");
        exit(1);        
    }
}

void debugMessageXY(int row, int col, char *message, attr_t *attr, unsigned prioridad)
{
    int posY_debug, debug_lines;
    int x, y;


    // Message allowed?
    if (DEBUG < prioridad) {
        return;
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
    prefresh(debug_panel, 0, 0, posY_debug, 0, min(posY_debug+DEBUG_LINES-1, LINES-1), min(COLS, COLS-1));

    if (sem_wait(&mutex_screen)) 
    {
        perror("debugMessageXY: sem_wait with mutex_screen");
        exit(1);
    }
    doupdate();
    if (sem_post(&mutex_screen))
    {
        perror("debugMessageXY: sem_post with mutex_screen");
        exit(1);        
    }

}