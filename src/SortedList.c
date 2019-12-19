#include <stdio.h>
#include <stdlib.h>

#include <SortedList.h>


void init_sorted_list(sorted_list *l, int (*compare)(void *, void*) )
{
	if (*l != NULL) 
	{
		fprintf(stderr,"init_sorted_list: List must be NULL!!\n");
		exit(1);
	}
	*l = malloc(sizeof(struct info_sorted_list));
	if (*l == NULL)
	{
		fprintf(stderr,"init_sorted_list: Could not allocate memory!!\n");
		exit(1);		
	}
	(*l)->header = NULL;
	(*l)->n_elements = 0;
	(*l)->f_compare = compare;
}

int isEmpty_sorted_list(sorted_list l)
{
	if (l == NULL) 
	{
		fprintf(stderr,"isEmpty_sorted_list: List is not valid!!\n");
		exit(1);
	}

	return l->n_elements == 0;
}

unsigned size_sorted_list(sorted_list l)
{
	if (l == NULL) 
	{
		fprintf(stderr,"isEmpty_sorted_list: List is not valid!!\n");
		exit(1);
	}

	return l->n_elements;

}

struct node_sorted_list * find_sorted_list(sorted_list l, void *val, int (*compare)(void *, void*) ) {
	int (*f)(void *, void*);
	struct node_sorted_list *p;

	if (l == NULL) 
	{
		fprintf(stderr,"find_sorted_list: List is not valid!!\n");
		exit(1);
	}

	if (compare == NULL) {
		f = l->f_compare;
	}
	else {
		f = compare;
	}

	// Find the position of the element
	p = l->header;
	while (p != NULL && (*f)(val, p->info) == 1)
	{
		p = p->next;
	}

	if (p != NULL && (*f)(val, p->info) != 0) {
		p = NULL;
	}
	return p;
}

void clear_all_sorted_list(sorted_list l)
{
	struct node_sorted_list *p;

	if (l == NULL) 
	{
		fprintf(stderr,"clear_all_sorted_list: List is not valid!!\n");
		exit(1);
	}

	while (l->header != NULL)
	{
		p = l->header;
		l->header=p->next;
		free(p->info);
		free(p);
	}
	l->n_elements = 0;
}

void insert_sorted_list(sorted_list l,  void * val)
{
	struct node_sorted_list *new_node = NULL;
	struct node_sorted_list *p, *prev_p;

	if (l == NULL) 
	{
		fprintf(stderr,"insert_sorted_list: List is not valid!!\n");
		exit(1);
	}

	new_node = malloc(sizeof(struct node_sorted_list));
	if (new_node == NULL)
	{
		fprintf(stderr,"insert_sorted_list: Could not allocate memory!!\n");
		exit(1);		
	}

	// Find the position for the new node
	p = l->header;
	prev_p = NULL;
	while (p != NULL && (*l->f_compare)(val, p->info) == 1)
	{
		prev_p = p;
		p = p->next;
	}
	new_node->info = val;
	new_node->next = p;
	if (prev_p != NULL)
	{
		prev_p->next = new_node;
	}
	else
	{
		l->header = new_node;
	}

	l->n_elements++;
}

void remove_sorted_list(sorted_list l, void *val, int (*compare)(void *, void*))
{
	int (*f)(void *, void*);
	struct node_sorted_list *p, *prev_p;

	if (l == NULL) 
	{
		fprintf(stderr,"remove_sorted_list: List is not valid!!\n");
		exit(1);
	}

	if (l->n_elements == 0) 
	{
		fprintf(stderr,"remove_sorted_list: List is empty!!\n");
		exit(1);
	}

	if (compare == NULL) {
		f = l->f_compare;
	}
	else {
		f = compare;
	}

	// Find the position of the element to remove
	p = l->header;
	prev_p = NULL;
	while (p != NULL && (*f)(val, p->info)  == 1)
	{
		prev_p = p;
		p = p->next;
	}
	// Remove all elements equal to val
	while (p != NULL && !(*f)(val, p->info))
	{
		if (prev_p != NULL)
		{
			prev_p->next = p->next;
			free(p->info);
			free(p);
			p = prev_p->next;
		}
		else
		{
			l->header = p->next;
			free(p->info);
			free(p);
			p = l->header;
		}
		l->n_elements--;
	}
}

void removeNode_sorted_list(sorted_list l, struct node_sorted_list *node) 
{
	struct node_sorted_list *p, *prev_p;

	if (l == NULL) 
	{
		fprintf(stderr,"removeNode_sorted_list: List is not valid!!\n");
		exit(1);
	}

	if (l->n_elements == 0) 
	{
		fprintf(stderr,"removeNode_sorted_list: List is empty!!\n");
		exit(1);
	}

	// Find the position of the node to remove
	p = l->header;
	prev_p = NULL;
	while (p != NULL && p != node)
	{
		prev_p = p;
		p = p->next;
	}
	if (p != NULL)
	{
		if (prev_p != NULL)
		{
			prev_p->next = p->next;
			free(p->info);
			free(p);
		}
		else
		{
			l->header = p->next;
			free(p->info);
			free(p);
		}
		l->n_elements--;
	}
	else {
		fprintf(stderr,"removeNode_sorted_list: Node is not valid!!\n");
		exit(1);		
	}

}

void for_each_sorted_list(sorted_list l, void (*f)(void *, void *), void *param) {
	struct node_sorted_list *p;

	if (l == NULL) 
	{
		fprintf(stderr,"for_each_sorted_list: List is not valid!!\n");
		exit(1);
	}

	// Iterate the list and call f with every element
	p = l->header;
	while (p != NULL) {
		(*f)(p->info, param);
		p = p ->next;
	}
}
