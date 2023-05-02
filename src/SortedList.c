#include <stdio.h>
#include <stdlib.h>

#include <SortedList.h>

// Prototypes
void quicksort_sorted_list(sorted_list l, struct node_sorted_list *first, struct node_sorted_list *last);

void init_sorted_list(sorted_list *l, int (*compare)(void *, void*) )
{
	if (*l != NULL) 
	{
		fprintf(stderr,"init_sorted_list: List must be NULL!!\n");
		exit(1);
	}
	*l =(struct info_sorted_list *) malloc(sizeof(struct info_sorted_list));
	if (*l == NULL)
	{
		fprintf(stderr,"init_sorted_list: Could not allocate memory!!\n");
		exit(1);		
	}
	(*l)->header = NULL;
	(*l)->tail = NULL;
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

unsigned long size_sorted_list(sorted_list l)
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

void clear_all_sorted_list(sorted_list l, int free_info, void (*f)(void *, void *), void *param)
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
		if (f != NULL)
		{
			(*f)(p->info, param);
		}
		l->header=p->next;
		if (free_info)
		{
			free(p->info);
		}
		free(p);
	}
	l->tail = NULL;
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

	new_node = (struct node_sorted_list *) malloc(sizeof(struct node_sorted_list));
	if (new_node == NULL)
	{
		fprintf(stderr,"insert_sorted_list: Could not allocate memory!!\n");
		exit(1);		
	}
	new_node->info = val;

	// Special case: list is empty
	if (l->n_elements == 0) {
		new_node->prev = NULL;
		new_node->next = NULL;
		l->header = new_node;
		l->tail = new_node;
	}
	else {
		// List is not empty
		// Find the position for the new node
		p = l->header;
		prev_p = NULL;
		while (p != NULL && (*l->f_compare)(val, p->info) == 1)
		{
			prev_p = p;
			p = p->next;
		}
		new_node->next = p;
		new_node->prev = prev_p;
		if (prev_p == NULL) {
			// Inserting at the beginning
			l->header = new_node;
			p->prev = new_node;
		}
		else {
			prev_p->next = new_node;
			if (p == NULL) {
				// Inserting at the end
				l->tail = new_node;
			}
			else {
				// Inserting at the middle
				p->prev = new_node;
			}
		}

	}

	l->n_elements++;
}

void remove_sorted_list(sorted_list l, void *val, int free_info, int (*compare)(void *, void*))
{
	int (*f)(void *, void*);
	struct node_sorted_list *p, *prev_p, *next_p;

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
	while (p != NULL && (*f)(val, p->info)  == 1)
	{
		p = p->next;
	}
	// Remove all elements equal to val
	while (p != NULL && !(*f)(val, p->info))
	{
		prev_p = p->prev;
		next_p = p->next;
		if (prev_p == NULL) {
			// Removing at the beggining
			l->header = next_p;
		}
		else {
			prev_p->next = next_p;
		}
		if (next_p == NULL) {
			// Removing at the end
			l->tail = prev_p;
		}
		else {
			next_p->prev = prev_p;
		}
		if (free_info)
		{
			free(p->info);
		}
		free(p);
		l->n_elements--;

		// Next node
		p=next_p;
	}
}

void removeNode_sorted_list(sorted_list l, struct node_sorted_list *node, int free_info) 
{
	struct node_sorted_list *prev_node, *next_node;

	prev_node = node->prev;
	next_node = node->next;
	if (prev_node == NULL) {
		// Removing at the beggining
		l->header = next_node;
	}
	else {
		prev_node->next = next_node;
	}
	if (next_node == NULL) {
		// Removing at the end
		l->tail = prev_node;
	}
	else {
		next_node->prev = prev_node;
	}
	if (free_info)
	{
		free(node->info);
	}
	free(node);
	l->n_elements--;
}

void updateNode_sorted_list(sorted_list l, struct node_sorted_list *node) {
	struct node_sorted_list *p, *prev_p, *prev_node, *next_node;

	// Remove node without destroy it
	prev_node = node->prev;
	next_node = node->next;
	if (prev_node == NULL) {
		// Removing at the beggining
		l->header = next_node;
	}
	else {
		prev_node->next = next_node;
	}
	if (next_node == NULL) {
		// Removing at the end
		l->tail = prev_node;
	}
	else {
		next_node->prev = prev_node;
	}
	l->n_elements--;

	// Insert the node in its new position
	// Special case: list is empty
	if (l->n_elements == 0) {
		node->prev = NULL;
		node->next = NULL;
		l->header = node;
		l->tail = node;
	}
	else {
		// List is not empty
		// Find the position for the new node
		p = l->header;
		prev_p = NULL;
		while (p != NULL && (*l->f_compare)(node->info, p->info) == 1)
		{
			prev_p = p;
			p = p->next;
		}
		node->next = p;
		node->prev = prev_p;
		if (prev_p == NULL) {
			// Inserting at the beginning
			l->header = node;
			p->prev = node;
		}
		else {
			prev_p->next = node;
			if (p == NULL) {
				// Inserting at the end
				l->tail = node;
			}
			else {
				// Inserting at the middle
				p->prev = node;
			}
		}

	}

	l->n_elements++;
}

struct node_sorted_list * first_sorted_list(sorted_list l)
{
	if (l == NULL) 
	{
		fprintf(stderr,"first_sorted_list: List is not valid!!\n");
		exit(1);
	}
	return l->header;
}

struct node_sorted_list * next_sorted_list(struct node_sorted_list *node)
{
	if (node == NULL) 
	{
		fprintf(stderr,"next_sorted_list: Node is not valid!!\n");
		exit(1);
	}
	return node->next;
}

struct node_sorted_list * previous_sorted_list(struct node_sorted_list *node)
{
	if (node == NULL) 
	{
		fprintf(stderr,"previous_sorted_list: Node is not valid!!\n");
		exit(1);
	}
	return node->prev;
}

struct node_sorted_list * end_sorted_list(sorted_list l)
{
	if (l == NULL) 
	{
		fprintf(stderr,"end_sorted_list: List is not valid!!\n");
		exit(1);
	}
	return NULL;
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

void resort_sorted_list(sorted_list l) {
	if (l == NULL) 
	{
		fprintf(stderr,"resort_sorted_list: List is not valid!!\n");
		exit(1);
	}

	if (isEmpty_sorted_list(l)) return;

	// Using Quicksort method
	quicksort_sorted_list(l, l->header, l->tail);
}

void quicksort_sorted_list(sorted_list l, struct node_sorted_list *first, struct node_sorted_list *last) {
	void *pivot;	// Pivot element will be the last
	struct node_sorted_list *p, *current, *prev_current, *next_current, *next_last;

	// Base case: empty list or one element
	if (first == last) return;

	// Get the pivot element
	pivot = last->info;

	// Iterate list from first to last-1
	p = first;
	while (p != last) {
		// Is the current value less than pivot value?
		if ((*l->f_compare)(p->info, pivot) != -1) {
			// No. We have to move current value to the right of the pivot (after last position)
			// Save important nodes
			current = p;
			prev_current = p->prev;
			next_current = p->next;
			// Have to get next node in the list before doing any move
			p = p ->next;
			// Move current node after last node
			// First step is remove current node from list
			if (prev_current == NULL) {
				// Moving first element of the list
				l->header = next_current;
			}
			else {
				prev_current->next = next_current;
			}
			next_current->prev = prev_current;
			// Second step is insert current node after last
			next_last = last->next;
			last->next = current;
			current->next = next_last;
			if (next_last == NULL) {
				// Inserting at the end of the list
				l->tail = current;
			}
			else {
				next_last->prev = current;
			}
		}
		else {
			// Next node
			p = p->next;
		}
	}

	// Recursive call with elements on the left of pivot (left of last node)
	if (last->prev != NULL) {
		// There are elements before last node
		quicksort_sorted_list(l, l->header, last->prev);
	}
	else {
		// No elements before last node
		quicksort_sorted_list(l, NULL, NULL);
	}

	// Recursive call with elements on the right of pivot (right of last node)
	if (last->next != NULL) {
		// There are elements after last node
		quicksort_sorted_list(l, last->next, l->tail);
	}
	else {
		// No elements before last node
		quicksort_sorted_list(l, NULL, NULL);
	}
}