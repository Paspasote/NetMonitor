#include <stdio.h>
#include <stdlib.h>

#include <Dictionary.h>

void init_dict(dictionary *dict, int (*compare)(void *, void*), int (*compare_key)(void *, void *) )
{
	if (*dict != NULL) 
	{
		fprintf(stderr,"init_dict: Dictionary must be NULL!!\n");
		exit(1);
	}
	*dict = malloc(sizeof(struct info_dict));
	if (*dict == NULL)
	{
		fprintf(stderr,"init_dict: Could not allocate memory!!\n");
		exit(1);		
	}

	(*dict)->list = NULL;
	init_sorted_list(&(*dict)->list, compare);
	(*dict)->f_compare = compare;
	(*dict)->f_compare_key = compare_key;
}

void * get_value_dict(dictionary dict, void *key) {
	struct node_sorted_list *p;

	if (dict == NULL) 
	{
		fprintf(stderr,"clear_all_dict: Dictionary is not valid!!\n");
		exit(1);
	}

	// Find the position of element with the key
	p = dict->list->header;
	while (p != NULL && (*dict->f_compare_key) (key, ((struct value_dict *)(p->info))->key) != 0)
	{
		p = p->next;
	}
	if (p != NULL)
	{
		return ((struct value_dict *)(p->info))->value;
	}
	else
	{
		return NULL;
	}
}

struct node_sorted_list * lower_bound_dict(dictionary dict, void *key, int (*compare_key)(void *, void *)) {
	if (dict == NULL) 
	{
		fprintf(stderr,"lower_bound_dict: Dictionary is not valid!!\n");
		exit(1);
	}
	return find_key_dict(dict, key, compare_key);
}

struct node_sorted_list * upper_bound_dict(dictionary dict, void *key, int (*compare_key)(void *, void *)) {
	int (*f)(void *, void *);
	struct node_sorted_list *node;
	struct value_dict info;

	if (dict == NULL) 
	{
		fprintf(stderr,"upper_bound_dict: Dictionary is not valid!!\n");
		exit(1);
	}

	if (compare_key == NULL) {
		f = dict->f_compare_key;
	}
	else {
		f = compare_key;
	}

	info.key = key;
	info.value = NULL;

	node = lower_bound_dict(dict, key, compare_key);
	while (node != NULL && (*f)((void *)&info, node->info)) {
		node = node->next;
	}

	return node;
}

struct node_sorted_list * find_dict(dictionary dict, void *key, void *val, int (*compare)(void *, void *)) {
	struct value_dict info;

	if (dict == NULL) 
	{
		fprintf(stderr,"find_dict: Dictionary is not valid!!\n");
		exit(1);
	}

	info.key = key;
	info.value = val;

	return find_sorted_list(dict->list, (void *)&info, compare);
}

struct node_sorted_list * find_key_dict(dictionary dict, void * key, int (*compare_key)(void *, void *)) {
	int (*f)(void *, void *);
	struct value_dict info;

	if (dict == NULL) 
	{
		fprintf(stderr,"find_key_dict: Dictionary is not valid!!\n");
		exit(1);
	}

	if (compare_key == NULL) {
		f = dict->f_compare_key;
	}
	else {
		f = compare_key;
	}

	info.key = key;
	info.value = NULL;

	return find_sorted_list(dict->list, (void *)&info, f);
}

void clear_all_dict(dictionary dict)
{
	if (dict == NULL) 
	{
		fprintf(stderr,"clear_all_dict: Dictionary is not valid!!\n");
		exit(1);
	}
	clear_all_sorted_list(dict->list);
}

void insert_dict(dictionary dict, void *key, void *val)
{
	struct value_dict *info;

	if (dict == NULL) 
	{
		fprintf(stderr,"clear_all_dict: Dictionary is not valid!!\n");
		exit(1);
	}

	info = malloc(sizeof(struct value_dict));
	if (info == NULL)
	{
		fprintf(stderr,"insert_dict: Could not allocate memory!!\n");
		exit(1);				
	}
	info->key = key;
	info->value = val;
	insert_sorted_list(dict->list,  (void *)info);
}

void remove_dict(dictionary dict, void *key, void *val, int (*compare)(void *, void *)) {
	struct value_dict info, *result;
	struct node_sorted_list *node;

	if (dict == NULL) 
	{
		fprintf(stderr,"clear_all_dict: Dictionary is not valid!!\n");
		exit(1);
	}

	info.key = key;
	info.value = val;

	node = find_sorted_list(dict->list, (void *)&info, compare);
	if (node != NULL) {
		result = (struct value_dict *)node;
		free(result->key);
		free(result->value);
		removeNode_sorted_list(dict->list, node);
	}
}

void for_each_dict(dictionary dict, void (*f)(void *, void *), void *param) {
	if (dict == NULL) 
	{
		fprintf(stderr,"for_each_dict: Dictionary is not valid!!\n");
		exit(1);
	}

	for_each_sorted_list(dict->list, f, param);
}

void for_each_dict_key(dictionary dict, void *key, int (*compare_key)(void *, void *), void (*f)(void *, void *), void *param) {
	struct node_sorted_list *node, *upper;


	node = lower_bound_dict(dict, key, compare_key);
	upper = upper_bound_dict(dict, key, compare_key);
	while (node != upper) {
		(*f)(node->info, param);
		node = node->next;
	}
}
