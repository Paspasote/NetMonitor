#ifndef __DOUBLE_LIST_H
#define __DOUBLE_LIST_H


struct node_double_list
{
	void * info;
	struct node_double_list *next;
	struct node_double_list *prev;
};

typedef struct info_double_list {
	struct node_double_list *header;
	struct node_double_list *tail;
	unsigned long n_elements;
} *double_list;

// Function prototypes
void init_double_list(double_list *l);
/* NEEDS: A double_list var with NULL value
   MODIFY: l with an empty list
*/

int isEmpty_double_list(double_list l);
/* NEEDS: A list already initialized
   RETURNS: 1 if list is empty or 0 in another case
   ERROR: If list is not initialized
*/

unsigned long size_double_list(double_list l);
/* NEEDS: A list already initialized
   RETURNS: The number of elements in the list
   ERROR: If list is not initialized
*/

void * front_double_list(double_list l);
/* NEEDS: A list already initialized
   RETURNS: The element at the beginning of the list
   ERROR: If list is empty or not initialized
*/

void * tail_double_list(double_list l);
/* NEEDS: A list already initialized
   RETURNS: The element at the end of the list
   ERROR: If list is empty or not initialized
*/

struct node_double_list * find_double_list(double_list l, void *val, int (*compare)(void *, void*) );
/* NEEDS: A list already initialized
          A value
		  A compare function with two elements of the list as arguments. Must return 1 (true) if the two elements are equal,
		  or 0 in another case
   ERROR: If list is not initialized
   RETURN: The node of the list with element val or NULL if there are none
*/

void clear_all_double_list(double_list l, int free_info, void (*f)(void *, void *), void *param);
/* NEEDS: A list already initialized
          A boolean (int)
          A function (or NULL)
          An extra param for the function (or NULL)
   MODIFIES: Remove all elements of the list.
             The function f is called (if not NULL) before remove every element. This functions is called with the following
             arguments: element of the list to be removed and param
             if free_info is 1 then the free operation will be applied to every element.
   ERROR: If list is not initialized
*/

void insert_front_double_list(double_list l, void *data);
/* 	NEEDS: A list already initialized
          data to be inserted in the liist
    MODIFIES: Insert a new element (data) at the beginning of the list
	ERROR: If list is not initialized or can not allocate memory for the new element
*/

void insert_tail_double_list(double_list l, void *data);
/* 	NEEDS: A list already initialized
          data to be inserted in the liist
    MODIFIES: Insert a new element (data) at the end of the list
	ERROR: If list is not initialized or can not allocate memory for the new element
*/

void remove_front_double_list(double_list l, int free_info);
/* 	NEEDS: A list already initialized
           A boolean (int)
    MODIFIES: Remove the element at the beginning of the list.
              If free_info is 1 then the free operation will be applied to element.
	ERROR: If list is not initialized or list is empty
*/

void remove_tail_double_list(double_list l, int free_info);
/* 	NEEDS: A list already initialized
           A boolean (int)
    MODIFIES: Remove the element at the end of the list.
              If free_info is 1 then the free operation will be applied to element.
	ERROR: If list is not initialized or list is empty
*/

void remove_double_list(double_list l, void *val, int free_info, int (*compare)(void *, void*));
/* NEEDS: A list already initialized
          A value
          A boolean (int)
		  A compare function with two elements of the list as arguments. Must return 1 (true) if the two elements are equal,
		  or 0 in another case
   MODIFIES: Remove the node with the value val (if any). 
             If free_info is 1 the free operation over info node will be called before remove
   ERROR: If list is not initialized or list is empty
*/

void removeNode_double_list(double_list l, struct node_double_list *node, int free_info);
/* NEEDS: A list already initialized
          A node of the list
          A boolean (int)
   MODIFIES: Remove the node. If free_info is 1 the free operation over info node will be called before remove
   ERROR: If list is not initialized
*/

void for_each_double_list(double_list l, void (*f)(void *, void *), void *param);
/* NEEDS: A list already initialized
          A function
   MODIFIES: Calls the function with every element of the list and param as second argument
   NOTE1: The list is iterated from beginning to end
   ERROR: If list is not initialized
*/

void for_each_reverse_double_list(double_list l, void (*f)(void *, void *), void *param);
/* NEEDS: A list already initialized
          A function
   MODIFIES: Calls the function with every element of the list and param as second argument
   NOTE1: The list is iterated from end to beginning
   ERROR: If list is not initialized
*/

#endif