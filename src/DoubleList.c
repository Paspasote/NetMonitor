#include <stdio.h>
#include <stdlib.h>
#include <DoubleList.h>

void init_double_list(double_list *l)
{
	if (*l != NULL) 
	{
		fprintf(stderr,"init_double_list: List must be NULL!!\n");
		exit(1);
	}
	*l = (struct info_double_list *) malloc(sizeof(struct info_double_list));
	if (*l == NULL)
	{
		fprintf(stderr,"init_double_list: Could not allocate memory!!\n");
		exit(1);		
	}
	(*l)->header = NULL;
	(*l)->tail = NULL;
	(*l)->n_elements = 0;
}

int isEmpty_double_list(double_list l)
{
	if (l == NULL) 
	{
		fprintf(stderr,"isEmpty_double_list: List is not valid!!\n");
		exit(1);
	}

	return l->n_elements == 0;
}

unsigned size_double_list(double_list l)
{
	if (l == NULL) 
	{
		fprintf(stderr,"size_double_list: List is not valid!!\n");
		exit(1);
	}

	return l->n_elements;
}

void * front_double_list(double_list l)
{
	if (l == NULL) 
	{
		fprintf(stderr,"front_doble_list: List is not valid!!\n");
		exit(1);
	}

	if (l->n_elements == 0) 
	{
		fprintf(stderr,"front_doble_list: List is empty!!\n");
		exit(1);
	}

	return l->header->info;
}

void * tail_double_list(double_list l)
{
	if (l == NULL) 
	{
		fprintf(stderr,"tail_double_list: List is not valid!!\n");
		exit(1);
	}

	if (l->n_elements == 0) 
	{
		fprintf(stderr,"tail_double_list: List is empty!!\n");
		exit(1);
	}

	return l->tail->info;

}

struct node_double_list * find_double_list(double_list l, void *val, int (*compare)(void *, void*) ) {
	struct node_double_list *p;

	if (l == NULL) 
	{
		fprintf(stderr,"find_double_list: List is not valid!!\n");
		exit(1);
	}

	// Find the position of the element
	p = l->header;
	while (p != NULL && (*compare)(val, p->info) == 0)
	{
		p = p->next;
	}

	return p;
}

void clear_all_double_list(double_list l, int free_info, void (*f)(void *, void *), void *param)
{
	struct node_double_list *p;

	if (l == NULL) 
	{
		fprintf(stderr,"clear_all_double_list: List is not valid!!\n");
		exit(1);
	}

	while (l->header != NULL)
	{
		p = l->header;
		l->header=p->next;
		if (f != NULL) 
		{
			(*f)(p->info, param);
		}
		if (free_info) {
			free(p->info);
		}
		free(p);
	}
	l->tail = NULL;
	l->n_elements = 0;
}

void insert_front_double_list(double_list l, void *data)
{
	struct node_double_list *p = NULL;

	if (l == NULL) 
	{
		fprintf(stderr,"insert_front_double_list: List is not valid!!\n");
		exit(1);
	}

	p = (struct node_double_list *) malloc(sizeof(struct node_double_list));
	if (p == NULL)
	{
		fprintf(stderr,"insert_front_double_list: Could not allocate memory!!\n");
		exit(1);		
	}
	p->info = data;
	p->next = l->header;
	p->prev = NULL;

	if (l->header == NULL)
	{
		l->tail = p;
	}
	else
	{
		l->header->prev = p;
	}

	l->header = p;
	l->n_elements++;
}

void insert_tail_double_list(double_list l, void *data)
{
	struct node_double_list *p = NULL;

	if (l == NULL) 
	{
		fprintf(stderr,"insert_tail_double_list: List is not valid!!\n");
		exit(1);
	}

	p = (struct node_double_list *) malloc(sizeof(struct node_double_list));
	if (p == NULL)
	{
		fprintf(stderr,"insert_tail_double_list: Could not allocate memory!!\n");
		exit(1);		
	}
	p->info = data;
	p->prev = l->tail;
	p->next = NULL;

	if (l->tail == NULL)
	{
		l->header = p;		
	}
	else
	{
		l->tail->next = p;		
	}

	l->tail = p;
	l->n_elements++;
}

void remove_front_double_list(double_list l, int free_info)
{
	struct node_double_list *p;

	if (l == NULL) 
	{
		fprintf(stderr,"remove_front_double_list: List is not valid!!\n");
		exit(1);
	}

	if (l->n_elements == 0) 
	{
		fprintf(stderr,"remove_front_double_list: List is empty!!\n");
		exit(1);
	}

	p = l->header;
	l->header = p->next;
	if (l->header == NULL)
	{
		l->tail = NULL;
	}
	else 
	{
		l->header->prev = NULL;		
	}
	if (free_info)
	{
		free(p->info);
	}
	free(p);
	l->n_elements--;
}

void remove_tail_double_list(double_list l, int free_info) 
{
	struct node_double_list *p;

	if (l == NULL) 
	{
		fprintf(stderr,"remove_tail_double_list: List is not valid!!\n");
		exit(1);
	}

	if (l->n_elements == 0) 
	{
		fprintf(stderr,"remove_tail_double_list: List is empty!!\n");
		exit(1);
	}

	p = l->tail;
	l->tail = p->prev;
	if (l->tail == NULL)
	{
		l->header = NULL;
	}
	else
	{
		l->tail->next = NULL;
	}
	if (free_info)
	{
		free(p->info);
	}
	free(p);
	l->n_elements--;

}

void remove_double_list(double_list l, void *val, int free_info, int (*compare)(void *, void*))
{
	struct node_double_list *p, *current, *prev_current;

	if (l == NULL) 
	{
		fprintf(stderr,"remove_double_list: List is not valid!!\n");
		exit(1);
	}

	if (l->n_elements == 0) 
	{
		fprintf(stderr,"remove_double_list: List is empty!!\n");
		exit(1);
	}

	// Iterate all elements and remove those equal to val
	p = l->header;
	while (p != NULL)
	{
		current = p;
		p = p->next;
		if ((*compare)(val, current->info))
		{
			// We have to remove current node
			prev_current = current->prev;
			if (current->next == NULL) {
				// Removing last node, we need to update tail
				l->tail = prev_current;
			}
			if (prev_current != NULL)
			{
				prev_current->next = current->next;
				if (free_info)
				{
					free(current->info);
				}
				free(current);
			}
			else
			{
				// Removing first node, we need to update head
				l->header = current->next;
				if (free_info)
				{
					free(current->info);
				}
				free(current);
			}
			l->n_elements--;
		}
	}
}

void removeNode_double_list(double_list l, struct node_double_list *node, int free_info) 
{
	struct node_double_list *prev_node, *next_node;

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

void for_each_double_list(double_list l, void (*f)(void *, void *), void *param) {
	struct node_double_list *p;

	if (l == NULL) 
	{
		fprintf(stderr,"for_each_double_list: List is not valid!!\n");
		exit(1);
	}

	// Iterate the list and call f with every element
	p = l->header;
	while (p != NULL) {
		(*f)(p->info, param);
		p = p ->next;
	}
}

void for_each_reverse_double_list(double_list l, void (*f)(void *, void *), void *param) {
	struct node_double_list *p;

	if (l == NULL) 
	{
		fprintf(stderr,"for_each_reverse_double_list: List is not valid!!\n");
		exit(1);
	}

	// Iterate the list and call f with every element
	p = l->tail;
	while (p != NULL) {
		(*f)(p->info, param);
		p = p ->prev;
	}
}