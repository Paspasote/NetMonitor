#ifndef __INTERFACE_H
#define __INTERFACE_H

#include <curses.h>

#include <WhoIs.h>
#include <PacketList.h>

// Constants

// Panel sizes
#define INFO_LINES		5
#define INFO_COLS		250
#define RESULT_LINES	500
#define RESULT_COLS		250
#define WHOIS_COLS      MAX_LEN_COUNTRY + MAX_LEN_NETNAME + 56


// Function prototypes
void *interface();
void init_curses();
void writeLineOnResult(char *text, attr_t attr, int bold);
void writeLineOnWhois(char *text, attr_t attr, int bold);
void writeLineOnInfo(char *text, attr_t attr, int highlight, int seconds);
#endif