#ifndef __DEBUG_H
#define __DEBUG_H

#ifdef DEBUG

#include <ncurses.h>

// Constants

// Debug level (0 - No debug   >0 debug on)
//#define DEBUG			1
// Please, define this symbol and its value in the compiler options
// Example: -DDEBUG=1

// Panel size

#define DEBUG_LINES		10
#define DEBUG_COLS		150

// Aspect ratio for debug panel
#define DEBUG_SIZE		0.25

void init_debug_panel();
void debugMessage(char *message, attr_t *attr, unsigned prioridad);
void debugMessageXY(int row, int col, char *message, attr_t *attr, unsigned prioridad);

#endif

#endif
