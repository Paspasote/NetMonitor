#ifndef __SORTED_LIST_H
#define __SORTED_LIST_H

struct node_sorted_list 
{
	void * info;
	struct node_sorted_list *next;
};

typedef struct info_sorted_list {
	struct node_sorted_list *header;
	unsigned n_elements;
	int (*f_compare)(void *, void *);
} *sorted_list;

// Function prototypes
void init_sorted_list(sorted_list *l, int (*compare)(void *, void*) );

int isEmpty_sorted_list(sorted_list l);
unsigned size_sorted_list(sorted_list l);
struct node_sorted_list * find_sorted_list(sorted_list l, void *val, int (*compare)(void *, void*) );

void clear_all_sorted_list(sorted_list l);
void insert_sorted_list(sorted_list l,  void *val);
void remove_sorted_list(sorted_list l, void *val, int (*compare)(void *, void*));
void removeNode_sorted_list(sorted_list l, struct node_sorted_list *node);

void for_each_sorted_list(sorted_list l, void (*f)(void *, void *), void *param);

#endif