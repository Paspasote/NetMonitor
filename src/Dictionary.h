#ifndef __DICTIONARY_H
#define __DICTIONARY_H

#include <SortedList.h>

// Types
struct value_dict
{
	void * key;
	void * value;
};

typedef struct info_dict
{
	sorted_list list;
	int (*f_compare)(struct value_dict *, struct value_dict *);    // Function to compare full pairs (first keys and then values)
	int (*f_compare_key)(void *, void *); // Function to compare only keys (arguments are only keys)
} *dictionary;

struct free_info
{
	int free_key;
	int free_value;
	void (*f)(struct value_dict *, void *);
	void *param;
};

// Function prototypes
void init_dict(dictionary *dict, int (*compare)(struct value_dict *, struct value_dict *), int (*compare_key)(void *, void *));
/* NEEDS: A dictionary var with NULL value
		    The function to compare two elements (two pairs) of the dict (for sorting)
          The function to compare only keys (arguments are only keys)
		    Both functions must return -1 if first argument is less than second one,
		    0 if both arguments are equal and 1 in another case.
   MODIFY: dict with an empty dictionary
   ERROR: If dict is not NULL
*/

int isEmpty_dict(dictionary dict);
/* NEEDS: A dictionary already initialized
   RETURNS: 1 if dict is empty or 0 in another case
   ERROR: If dict is not initialized
*/

unsigned long size_dict(dictionary dict);
/* NEEDS: A dictionary already initialized
   RETURNS: The number of elements in the dict
   ERROR: If dict is not initialized
*/

void * get_value_dict(dictionary dict, void *key);
/* NEEDS: A dictionary already initialized
          A key value
   RETURN: The info value asociated with the key or NULL if the key is not in dict
   ERROR: If dict is not initialized
*/

struct node_sorted_list * first_dict(dictionary dict);
/* NEEDS: A dictionary already initialized
   RETURN: The first position (node of the list) of dict
   ERROR: If dict is not initialized
*/

struct node_sorted_list * next_dict(struct node_sorted_list *node);
/* NEEDS: A pointer to an element of the dict
   RETURN: The next element of the dict or NULL if there is none
   ERROR: If pointer is NULL
*/

struct node_sorted_list * previous_dict(struct node_sorted_list *node);
/* NEEDS: A pointer to an element of the dict
   RETURN: The previous element of the dict or NULL if there is none
   ERROR: If pointer is NULL
*/

struct node_sorted_list * end_dict(dictionary dict);
/* NEEDS: A dictionary already initialized
   RETURN: The end of the dict (NULL pointer)
   ERROR: If dict is not initialized
*/


struct node_sorted_list * lower_bound_dict(dictionary dict, void *key);
/* NEEDS: A dictionary already initialized
          A key value
   RETURN: The first position (node of the list) of dict with key or NULL if the key is not in dict
   ERROR: If dict is not initialized
*/

struct node_sorted_list * upper_bound_dict(dictionary dict, void *key);
/* NEEDS: A dictionary already initialized
          A key value
   RETURN: The first position (node of the list) of dict with key > key or NULL if there are none
   ERROR: If dict is not initialized
*/

struct node_sorted_list * find_dict(dictionary dict, void *key, void *val, int (*compare)(struct value_dict *, struct value_dict *));
/* NEEDS: A dictionary already initialized
          A key value
		    A val value
		    A compare function or NULL (the compare function of the dict will be used in this case)
   RETURN: The first position (node of the list) of dict with element (pair) (key, val) or NULL if there are none
   ERROR: If dict is not initialized
*/

struct node_sorted_list * find_key_dict(dictionary dict, void * key, int (*compare_key)(void *, void *));
/* NEEDS: A dictionary already initialized
          A key value
		    A compare function to compare only keys or NULL (the compare function of the dict will be used in this case)
   RETURN: The first position (node of the list) of dict with key or NULL if the key is not in dict
   ERROR: If dict is not initialized
*/

void clear_all_dict(dictionary dict, int free_key, int free_value, void (*f)(struct value_dict *, void *), void *param);
/* NEEDS: A dictionary already initialized
          Two booleans (int)
          A function (or NULL)
          An extra param for the function (or NULL)
   MODIFIES: Remove all elements of the dict.
             The function f is called (if not NULL) before remove every element. This functions is called with the following
             arguments: element (pair) of the dict, param
             if free_key is 1 then the free operation will be applied to the key of every element.
             if free_value is 1 then the free operation will be applied to the value of every element.
   ERROR: If dict is not initialized
*/

void insert_dict(dictionary dict, void *key, void *val);
/* NEEDS: A dictionary already initialized
          A key value
		    A val value
   MODIFIES: Insert a new pair (key, val) in the dict.
   ERROR: If dict is not initialized or can not allocate memory for new element
*/

void remove_dict(dictionary dict, void *key, void *val, int free_key, int free_value);
/* NEEDS: A list already initialized
          A key value
		    A val value
          Two booleans (int)
   MODIFIES: Remove the node with the pair (key, val) (if any). 
             If free_key is 1 the free operation will be applied to the key
             If free_value is 1 the free operation will be applied to the val
   ERROR: If dict is not initialized
*/

void for_each_dict(dictionary dict, void (*f)(struct value_dict *, void *), void *param);
/* NEEDS: A dictionary already initialized
          A function
		    An extra param for the function (or NULL)
   MODIFIES: Calls the function with every element (pair) of the dict and param as second argument
   ERROR: If dict is not initialized
*/

void for_each_dict_key(dictionary dict, void *key, void (*f)(struct value_dict *, void *), void *param);
/* NEEDS: A dictionary already initialized
		    A key value
          A function
		    An extra param for the function (or NULL)
   MODIFIES: Calls the function with every element (pair) of the dict (whose keys are equal to key) and param as second argument
   ERROR: If dict is not initialized
*/

#endif