#include <stdio.h>
#include <stdlib.h>

#include <Dictionary.h>

// Prototypes
int compareKeys(struct value_dict *info1, struct value_dict *info2);
void freePair(void *val, void *param);

void init_dict(dictionary *dict, int (*compare)(struct value_dict *, struct value_dict *), int (*compare_key)(void *, void *) )
{
	if (*dict != NULL) 
	{
		fprintf(stderr,"init_dict: Dictionary must be NULL!!\n");
		exit(1);
	}
	*dict = (struct info_dict *) malloc(sizeof(struct info_dict));
	if (*dict == NULL)
	{
		fprintf(stderr,"init_dict: Could not allocate memory!!\n");
		exit(1);		
	}

	(*dict)->list = NULL;
	init_sorted_list(&(*dict)->list, (int (*) (void *, void *))compare);	
	(*dict)->f_compare = compare;
	(*dict)->f_compare_key = compare_key;
}

int isEmpty_dict(dictionary dict)
{
	if (dict == NULL) 
	{
		fprintf(stderr,"isEmpty_dict: Dictionary is not valid!!\n");
		exit(1);
	}

	return isEmpty_sorted_list(dict->list);
}

unsigned size_dict(dictionary dict)
{
	if (dict == NULL) 
	{
		fprintf(stderr,"size_dict: Dictionary is not valid!!\n");
		exit(1);
	}

	return size_sorted_list(dict->list);

}

void * get_value_dict(dictionary dict, void *key) {
	struct node_sorted_list *p;

	if (dict == NULL) 
	{
		fprintf(stderr,"clear_all_dict: Dictionary is not valid!!\n");
		exit(1);
	}

	// Find the position of element with the key
	p = find_key_dict(dict, key, NULL);
	if (p != NULL)
	{
		return ((struct value_dict *)(p->info))->value;
	}
	else
	{
		return NULL;
	}
}

struct node_sorted_list * lower_bound_dict(dictionary dict, void *key) {
	if (dict == NULL) 
	{
		fprintf(stderr,"lower_bound_dict: Dictionary is not valid!!\n");
		exit(1);
	}
	return find_key_dict(dict, key, NULL);
}

struct node_sorted_list * upper_bound_dict(dictionary dict, void *key) {
	struct node_sorted_list *node;

	if (dict == NULL) 
	{
		fprintf(stderr,"upper_bound_dict: Dictionary is not valid!!\n");
		exit(1);
	}

	node = lower_bound_dict(dict, key);
	while (node != NULL && (dict->f_compare_key)(((struct value_dict *)(node->info))->key, key) == 0) {
		node = node->next;
	}

	return node;
}

struct node_sorted_list * find_dict(dictionary dict, void *key, void *val, int (*compare)(struct value_dict *, struct value_dict *)) {
	struct value_dict info;

	if (dict == NULL) 
	{
		fprintf(stderr,"find_dict: Dictionary is not valid!!\n");
		exit(1);
	}

	info.key = key;
	info.value = val;

	return find_sorted_list(dict->list, &info, (int (*) (void *, void *))compare);
}

struct node_sorted_list * find_key_dict(dictionary dict, void * key, int (*compare_key)(void *, void *)) {
	struct value_dict info;

	if (dict == NULL)
	{
		fprintf(stderr,"find_key_dict: Dictionary is not valid!!\n");
		exit(1);
	}

	info.key = key;
	if (compare_key != NULL)
	{
		info.value = compare_key;        
	}
	else
	{
		info.value = dict->f_compare_key;
	}

	return find_sorted_list(dict->list, &info, (int (*) (void *, void *))compareKeys);
}

void clear_all_dict(dictionary dict, int free_key, int free_value, void (*f)(struct value_dict *, void *), void *param)
{
	struct free_info free_pair;

	if (dict == NULL) 
	{
		fprintf(stderr,"clear_all_dict: Dictionary is not valid!!\n");
		exit(1);
	}

	free_pair.free_key = free_key;
	free_pair.free_value = free_value;
	free_pair.f = f;
	free_pair.param = param;
	clear_all_sorted_list(dict->list, 1, freePair, &free_pair);
}

void insert_dict(dictionary dict, void *key, void *val)
{
	struct value_dict *info;

	if (dict == NULL) 
	{
		fprintf(stderr,"insert_dict: Dictionary is not valid!!\n");
		exit(1);
	}

	info = (struct value_dict *) malloc(sizeof(struct value_dict));
	if (info == NULL)
	{
		fprintf(stderr,"insert_dict: Could not allocate memory!!\n");
		exit(1);				
	}
	info->key = key;
	info->value = val;
	insert_sorted_list(dict->list, info);
}

void remove_dict(dictionary dict, void *key, void *val, int free_key, int free_value) {
	struct value_dict info, *result;
	struct node_sorted_list *node;

	if (dict == NULL) 
	{
		fprintf(stderr,"remove_dict: Dictionary is not valid!!\n");
		exit(1);
	}

	info.key = key;
	info.value = val;

	node = find_sorted_list(dict->list, &info, NULL);
	if (node != NULL) {
		result = (struct value_dict *)node->info;
		if (free_key)
		{
			free(result->key);
		}
		if (free_value)
		{
			free(result->value);
		}
		removeNode_sorted_list(dict->list, node, 1);
	}
}

void for_each_dict(dictionary dict, void (*f)(struct value_dict *, void *), void *param) {
	if (dict == NULL) 
	{
		fprintf(stderr,"for_each_dict: Dictionary is not valid!!\n");
		exit(1);
	}

	for_each_sorted_list(dict->list, (void (*) (void *, void *))f, param);
}

void for_each_dict_key(dictionary dict, void *key, void (*f)(struct value_dict *, void *), void *param) {
	struct node_sorted_list *node, *upper;


	node = lower_bound_dict(dict, key);
	upper = upper_bound_dict(dict, key);
	while (node != upper) {
		(*f)((struct value_dict *)node->info, param);
		node = node->next;
	}
}

int compareKeys(struct value_dict *info1, struct value_dict *info2) {
	void *key1, *key2;
	int (*f_compare_key)(void *, void *);

	key1 = info1->key;
	key2 = info2->key;
	f_compare_key = (int (*) (void *, void *))info1->value;
	return (*f_compare_key)(key1, key2);
}

void freePair(void *val, void *param)
{
	struct value_dict *info;
	struct free_info *free_pair;

	info = (struct value_dict *)val;
	free_pair = (struct free_info *)param;
	
	if (free_pair->f != NULL)
	{
		(free_pair->f)(val, free_pair->param);
	}

	if (free_pair->free_key)
	{
		free(info->key);
	}
	if (free_pair->free_value)
	{
		free(info->value);
	}
}
