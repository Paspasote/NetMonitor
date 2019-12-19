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
	unsigned n_elements;
	int (*f_compare)(void *, void *);
} *double_list;

// Function prototypes
void init_double_list(double_list *l);

int isEmpty_double_list(double_list l);
unsigned size_double_list(double_list l);
void * front_double_list(double_list l);
void * tail_double_list(double_list l);
struct node_double_list * find_double_list(double_list l, void *val, int (*compare)(void *, void*) );

void clear_all_double_list(double_list l);
void insert_front_double_list(double_list l, void *data);
void insert_tail_double_list(double_list l, void *data);
void remove_front_double_list(double_list l);
void remove_tail_double_list(double_list l);
void remove_double_list(double_list l, void *val, int (*compare)(void *, void*));
void removeNode_double_list(double_list l, struct node_double_list *node);

void for_each_double_list(double_list l, void (*f)(void *, void *), void *param);
void for_each_reverse_double_list(double_list l, void (*f)(void *, void *), void *param);

#endif