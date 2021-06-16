#ifndef __SORTED_LIST_H
#define __SORTED_LIST_H

struct node_sorted_list 
{
	void * info;
	struct node_sorted_list *next;
	struct node_sorted_list *prev;
};

typedef struct info_sorted_list {
	struct node_sorted_list *header;
	struct node_sorted_list *tail;
	unsigned n_elements;
	int (*f_compare)(void *, void *);
} *sorted_list;

// Function prototypes
void init_sorted_list(sorted_list *l, int (*compare)(void *, void*) );
/* NEEDS: A shared_sorted_list var with NULL value
          The function to compare two elements of the list (for sorting)
		  This function must return -1 if first value is less than second one,
		  0 if both values are equal and 1 in another case.
   MODIFY: l with an empty list
   ERROR: If l is not NULL
*/

int isEmpty_sorted_list(sorted_list l);
/* NEEDS: A list already initialized
   RETURNS: 1 if list is empty or 0 in another case
   ERROR: If list is not initialized
*/

unsigned size_sorted_list(sorted_list l);
/* NEEDS: A list already initialized
   RETURNS: The number of elements in the list
   ERROR: If list is not initialized
*/

struct node_sorted_list * find_sorted_list(sorted_list l, void *val, int (*compare)(void *, void*) );
/* NEEDS: A list already initialized
          A value
		  A compare function or NULL (the compare function of the list will be used in this case)
   RETURNS: The node of the list with the value or NULL if there are none
   ERROR: If list is not initialized
*/

void clear_all_sorted_list(sorted_list l, int free_info, void (*f)(void *, void *), void *param);
/* NEEDS: A list already initialized
          A boolean (int)
          A function (or NULL)
          An extra param for the function (or NULL)
   MODIFIES: Remove all elements of the list.
             The function f is called (if not NULL) before remove every element. This functions is called with the following
             arguments: element of the list, param
             if free_info is 1 then the free operation will be applied to every element.
   ERROR: If list is not initialized
*/

void insert_sorted_list(sorted_list l,  void *val);
/* NEEDS: A list already initialized
          A val
   MODIFIES: Insert a new node in the list with the val value
   ERROR: If list is not initialized or can not allocate memory for new element
*/

void remove_sorted_list(sorted_list l, void *val, int free_info, int (*compare)(void *, void*));
/* NEEDS: A list already initialized
          A value
          A boolean (int)
		  A compare function or NULL (the compare function of the list will be used in this case)
   MODIFIES: Remove the node with the value (if any). 
             If free_info is 1 the free operation over info node will be called before remove
   ERROR: If list is not initialized
*/

void removeNode_sorted_list(sorted_list l, struct node_sorted_list *node, int free_info);
/* NEEDS: A list already initialized
          A node of the list
          A boolean (int)
   MODIFIES: Remove the node. If free_info is 1 the free operation over info node will be called before remove
   ERROR: If list is not initialized
*/

void updateNode_sorted_list(sorted_list l, struct node_sorted_list *node);
/* NEEDS: A list already initialized
          A node of the list
   MODIFIES: The list to reubicate the node in its correct position (according with its value)
   ERROR: If list is not initialized
*/

struct node_sorted_list * first_sorted_list(sorted_list l);
/* NEEDS: A list already initialized
   RETURN: A pointer to the first element (node) of the list or NULL if there is one
   ERROR: If list is not initialized
*/

struct node_sorted_list * next_sorted_list(struct node_sorted_list *node);
/* NEEDS: A pointer to one elment of the list (node)
   RETURN: The next element on the list (the next node) or NULL if there is none
   ERROR: If node is NULL
*/

struct node_sorted_list * previous_sorted_list(struct node_sorted_list *node);
/* NEEDS: A pointer to one elment of the list (node)
   RETURN: The previous element on the list (the previous node) or NULL if there is none
   ERROR: If node is NULL
*/

struct node_sorted_list * end_sorted_list(sorted_list l);
/* NEEDS: A list already initialized
   RETURN: A pointer to the end of the list (NULL)
   ERROR: If list is not initialized
*/

void for_each_sorted_list(sorted_list l, void (*f)(void *, void *), void *param);
/* NEEDS: A list already initialized
          A function
		  An extra param for the function (or NULL)
   MODIFIES: Calls the function with every element of the list and param as second argument
   ERROR: If list is not initialized
*/

void resort_sorted_list(sorted_list l);
/* NEEDS A list already initialized
   MODIFIES: Resort the list with "Quick sort method"
   ERROR: If list is not initialized
*/

#endif