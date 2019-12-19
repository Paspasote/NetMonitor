#ifndef __INTERFACE_H
#define __INTERFACE_H

#include <curses.h>

#include <PacketList.h>

// Function prototypes
void *interface();
void writeLineOnResult(char *text, attr_t *attr);


#endif