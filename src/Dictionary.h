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
	int (*f_compare)(void *, void *);
	int (*f_compare_key)(void *, void *);
} *dictionary;

// Function prototypes
void init_dict(dictionary *dict, int (*compare)(void *, void*), int (*compare_key)(void *, void *));

void * get_value_dict(dictionary dict, void *key);
struct node_sorted_list * lower_bound_dict(dictionary dict, void *key, int (*compare_key)(void *, void *));
struct node_sorted_list * upper_bound_dict(dictionary dict, void *key, int (*compare_key)(void *, void *));
struct node_sorted_list * find_dict(dictionary dict, void *key, void *val, int (*compare)(void *, void *));
struct node_sorted_list * find_key_dict(dictionary dict, void * key, int (*compare_key)(void *, void *));

void clear_all_dict(dictionary dict);
void insert_dict(dictionary dict, void *key, void *val);
void remove_dict(dictionary dict, void *key, void *val, int (*compare)(void *, void *));

void for_each_dict(dictionary dict, void (*f)(void *, void *), void *param);
void for_each_dict_key(dictionary dict, void *key, int (*compare_key)(void *, void *), void (*f)(void *, void *), void *param);

#endif