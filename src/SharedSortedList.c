#include <stdio.h>
#include <stdlib.h>

#include <SharedSortedList.h>

// Prototypes
int requestRemoveNode_shared_sorted_list(shared_sorted_list l, struct node_shared_sorted_list *node);
/* NEEDS: A list already initialized
          A node of the list
   MODIFIES: Allow to remove the node. (It does not remove the node yet)
   RETURN: 1 (true) if no one else has requested to remove the node, 0 (false) in another case
   NOTE1: This operation is called automatically by the operations remove_shared_sorted_list and removeNode_shared_sorted_list 
   NOTE1: This operation is blocking, it first mark the node for removing and then wait for permission to remove
   NOTE2: After this operation mark the node for removing, only pointers and threads already using the node will be able to perform 
          operations with this node. Once all of them leave the node, it will be removed		  
*/
void quicksort_shared_sorted_list(shared_sorted_list l, struct node_shared_sorted_list *first, struct node_shared_sorted_list *last);

void init_shared_sorted_list(shared_sorted_list *l, int (*compare)(void *, void*) )
{
	if (*l != NULL) 
	{
		fprintf(stderr,"init_shared_sorted_list: List must be NULL!!\n");
		exit(1);
	}
	*l =(struct info_shared_sorted_list *) malloc(sizeof(struct info_shared_sorted_list));
	if (*l == NULL)
	{
		fprintf(stderr,"init_shared_sorted_list: Could not allocate memory!!\n");
		exit(1);		
	}

    if (sem_init(&((*l)->mutex_list), 0, 1))
    {		
        perror("init_shared_sorted_list: Couldn't create mutex_list semaphore for the list!!!!");
        exit(1);
    }
	(*l)->header = NULL;
	(*l)->tail = NULL;
	(*l)->n_elements = 0;
	(*l)->f_compare = compare;
}

void requestReadNode_shared_sorted_list(struct node_shared_sorted_list *node)
{
	// One reader more using the node
	if (sem_wait(&(node->readers_sem)))
	{
		perror("requestReadNode_shared_sorted_list: sem_wait with readers_sem node");
		exit(1);		
	}
	if (sem_wait(&(node->mutex_sem)))
	{
		perror("requestReadNode_shared_sorted_list: sem_wait with mutex_sem node");
		exit(1);		
	}
	node->nreaders++;
	// First reader ask for permission
	// Also no more readers pass if there is a write request (more priority for writers)
//	if (node->nreaders == 1 || node->write_requests) {
	if (node->nreaders == 1) {
		if (sem_post(&(node->mutex_sem)))
		{
			perror("requestReadNode_shared_sorted_list: sem_post with mutex_sem node");
			exit(1);		
		}

		if (sem_wait(&(node->writers_sem)))
		{
			perror("requestReadNode_shared_sorted_list: sem_wait with writers_sem node");
			exit(1);		
		}
	}
	else {
		if (sem_post(&(node->mutex_sem)))
		{
			perror("requestReadNode_shared_sorted_list: sem_post with mutex_sem node");
			exit(1);		
		}
	}
	if (sem_post(&(node->readers_sem)))
	{
		perror("requestReadNode_shared_sorted_list: sem_post with readers_sem node");
		exit(1);		
	}

}

void leaveReadNode_shared_sorted_list(struct node_shared_sorted_list *node) {
	// One reader less using node
	if (sem_wait(&(node->mutex_sem)))
	{
		perror("leaveReadNode_shared_sorted_list: sem_wait with mutex_sem node");
		exit(1);		
	}
	node->nreaders--;
	// Am i the last reader?
	if (!node->nreaders) {
		// Free node for writers (or readers)
		if (sem_post(&(node->writers_sem)))
		{
			perror("leaveReadNode_shared_sorted_list: sem_post with writers_sem node");
			exit(1);		
		}
	}
	if (sem_post(&(node->mutex_sem)))
	{
		perror("leaveReadNode_shared_sorted_list: sem_post with mutex_sem node");
		exit(1);		
	}

}

void requestWriteNode_shared_sorted_list(struct node_shared_sorted_list *node) {
	// One writer more requesting write access to the node
	if (sem_wait(&(node->mutex_sem)))
	{
		perror("requestWriteNode_shared_sorted_list: sem_wait with mutex_sem node");
		exit(1);		
	}
	node->write_requests++;
	if (sem_post(&(node->mutex_sem)))
	{
		perror("requestWriteNode_shared_sorted_list: sem_post with mutex_sem node");
		exit(1);		
	}

	// Request write access
	if (sem_wait(&(node->writers_sem)))
	{
		perror("requestWriteNode_shared_sorted_list: sem_wait with writers_sem node");
		exit(1);		
	}

	// Access allowed
	if (sem_wait(&(node->mutex_sem)))
	{
		perror("requestWriteNode_shared_sorted_list: sem_wait with mutex_sem node");
		exit(1);		
	}
	node->write_requests--;
	if (sem_post(&(node->mutex_sem)))
	{
		perror("requestWriteNode_shared_sorted_list: sem_post with mutex_sem node");
		exit(1);		
	}
}

void leaveWriteNode_shared_sorted_list(struct node_shared_sorted_list *node) {
	// Free node for writers (or readers)
	if (sem_post(&(node->writers_sem)))
	{
		perror("leaveWriteNode_shared_sorted_list: sem_post with writers_sem node");
		exit(1);		
	}
}

int requestRemoveNode_shared_sorted_list(shared_sorted_list l, struct node_shared_sorted_list *node) {
	int ret;

	if (sem_wait(&(l->mutex_list)))
	{
		perror("requestRemoveNode_shared_sorted_list: sem_wait with mutex_list");
		exit(1);
	}

	// Is there another remove request?
	if (node->remove_request) {
		// Yes. Can't remove node
		if (sem_post(&(l->mutex_list)))
		{
			perror("requestRemoveNode_shared_sorted_list: sem_post with mutex_list");
			exit(1);		
		}
		ret=0;
	}
	else {
		// No. We are going to remove node
		node->remove_request = 1;
		if (sem_post(&(l->mutex_list)))
		{
			perror("requestRemoveNode_shared_sorted_list: sem_post with mutex_list");
			exit(1);		
		}
		// Request write access
		if (sem_wait(&(node->writers_sem)))
		{
			perror("requestRemoveNode_shared_sorted_list: sem_wait with writers_sem node");
			exit(1);		
		}
		if (sem_wait(&(l->mutex_list))) 
		{
			perror("requestRemoveNode_shared_sorted_list: sem_wait with mutex_list");
			exit(1);
		}
		// Am I the only one in this node?
		while (node->nprocs > 1) {
			if (sem_post(&(l->mutex_list)))
			{
				perror("requestRemoveNode_shared_sorted_list: sem_post with mutex_list");
				exit(1);		
			}
			// No. Request write access again
			// Before we have to free node for writers (or readers)
			if (sem_post(&(node->writers_sem)))
			{
				perror("requestRemoveNode_shared_sorted_list: sem_post with writers_sem node");
				exit(1);		
			}
			if (sem_wait(&(node->writers_sem)))
			{
				perror("requestRemoveNode_shared_sorted_list: sem_wait with writers_sem node");
				exit(1);		
			}
			if (sem_wait(&(l->mutex_list))) 
			{
				perror("requestRemoveNode_shared_sorted_list: sem_wait with mutex_list");
				exit(1);
			}
		}
		if (sem_post(&(l->mutex_list)))
		{
			perror("requestRemoveNode_shared_sorted_list: sem_post with mutex_list");
			exit(1);		
		}

		ret=1;
	}

	return ret;

}

void leaveNode_shared_sorted_list(shared_sorted_list l, struct node_shared_sorted_list *node) {
		// One proc less using the node
	if (sem_wait(&(l->mutex_list))) 
	{
		perror("leaveNode_shared_sorted_list: sem_wait with mutex_list");
		exit(1);
	}
	if (node->nprocs == 0) {
		fprintf(stderr,"leaveNode_shared_sorted_listleaveNode_shared_sorted_list: number of procs with access to node is under zero!!\n");
		exit(1);
	}
	node->nprocs--;
	if (sem_post(&(l->mutex_list)))
	{
		perror("leaveNode_shared_sorted_list: sem_post with mutex_list");
		exit(1);
	}

}

int isEmpty_shared_sorted_list(shared_sorted_list l)
{
	int ret;

	if (l == NULL) 
	{
		fprintf(stderr,"isEmpty_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	if (sem_wait(&(l->mutex_list))) 
	{
		perror("isEmpty_shared_sorted_list: sem_wait with mutex_list");
		exit(1);
	}
	ret = l->n_elements == 0;
	if (sem_post(&(l->mutex_list)))
	{
		perror("isEmpty_shared_sorted_list: sem_post with mutex_list");
		exit(1);
	}
	return ret;
}

unsigned size_shared_sorted_list(shared_sorted_list l)
{
	int ret;

	if (l == NULL) 
	{
		fprintf(stderr,"size_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	if (sem_wait(&(l->mutex_list))) 
	{
		perror("size_shared_sorted_list: sem_wait with mutex_list");
		exit(1);
	}
	ret = l->n_elements;
	if (sem_post(&(l->mutex_list)))
	{
		perror("size_shared_sorted_list: sem_post with mutex_list");
		exit(1);
	}
	return ret;
}

struct node_shared_sorted_list * firstNode_shared_sorted_list(shared_sorted_list l) {
	struct node_shared_sorted_list *first_node;

	if (sem_wait(&(l->mutex_list))) 
	{
		perror("firstNode_shared_sorted_list: sem_wait with mutex_list");
		exit(1);
	}

	// Get first node
	first_node = l->header;

	// Is list empty?
	if (first_node == NULL) {
		// Yes, return NULL
		if (sem_post(&(l->mutex_list)))
		{
			perror("firstNode_shared_sorted_list: sem_post with mutex_list");
			exit(1);		
		}
		return NULL;
	}

	// Advance until first node without remove request
	while (first_node->remove_request) {
		first_node = first_node->next;
		if (first_node == NULL) {
			if (sem_post(&(l->mutex_list)))
			{
				perror("firstNode_shared_sorted_list: sem_post with mutex_list");
				exit(1);		
			}
			return NULL;
		}
	}
	// One proc more using node
	first_node->nprocs++;

	if (sem_post(&(l->mutex_list)))
	{
		perror("firstNode_shared_sorted_list: sem_post with mutex_list");
		exit(1);		
	}

	// Return next node
	return first_node;

}

struct node_shared_sorted_list * nextNode_shared_sorted_list(shared_sorted_list l, struct node_shared_sorted_list *node, int leave_current) {
	struct node_shared_sorted_list *next_node;

	if (sem_wait(&(l->mutex_list))) 
	{
		perror("nextNode_shared_sorted_list: sem_wait with mutex_list");
		exit(1);
	}

	// Abandon current node?
	if (leave_current) {
		// Yes
		node->nprocs--;
	}

	// Get next node
	next_node = node->next;

	// Exist ?
	if (next_node == NULL) {
		if (sem_post(&(l->mutex_list)))
		{
			perror("nextNode_shared_sorted_list: sem_post with mutex_list");
			exit(1);		
		}
		return NULL;
	}

	// Advance until first node without remove request
	while (next_node->remove_request) {
		next_node = next_node->next;
		if (next_node == NULL) {
			if (sem_post(&(l->mutex_list)))
			{
				perror("nextNode_shared_sorted_list: sem_post with mutex_list");
				exit(1);		
			}
			return NULL;
		}
	}

	// One proc more using node
	next_node->nprocs++;

	if (sem_post(&(l->mutex_list)))
	{
		perror("nextNode_shared_sorted_list: sem_post with mutex_list");
		exit(1);		
	}

	// Return next node
	return next_node;

}

struct node_shared_sorted_list * find_shared_sorted_list(shared_sorted_list l, void *val, int (*compare)(void *, void*) ) {
	int (*f)(void *, void*);
	struct node_shared_sorted_list *node;
	int fin = 0;

	if (l == NULL) 
	{
		fprintf(stderr,"find_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	if (compare == NULL) {
		if (sem_wait(&(l->mutex_list))) 
		{
			perror("find_shared_sorted_list: sem_wait with mutex_list");
			exit(1);
		}
		f = l->f_compare;
		if (sem_post(&(l->mutex_list)))
		{
			perror("find_shared_sorted_list: sem_post with mutex_list");
			exit(1);
		}
	}
	else {
		f = compare;
	}

	// Iterate the list to search the element with val info
	node = firstNode_shared_sorted_list(l);
	while (node != NULL && !fin) {
		// Request read access to node
		requestReadNode_shared_sorted_list(node);

		// Compares val with info node
		fin = (*f)(val, node->info) != 1;

		if (!fin) {
			// No more read access needed for node
			leaveReadNode_shared_sorted_list(node);

			// Next node
			node = nextNode_shared_sorted_list(l, node, 1);
		}
	}
	if (node != NULL) {
		// Value found in the list?
		if ((*f)(val, node->info) != 0) {
			// Not found.
			// No more read access needed for current node
			leaveReadNode_shared_sorted_list(node);
		
			// Leaving current node
			leaveNode_shared_sorted_list(l, node);

			node = NULL;
		}
		else {
			// Found it.
			// No more read access needed for current node
			leaveReadNode_shared_sorted_list(node);
		}
	}
	return node;
}

struct node_shared_sorted_list * exclusiveFind_shared_sorted_list(shared_sorted_list l, void *val, int (*compare)(void *, void*) ) {
	int (*f)(void *, void*);
	struct node_shared_sorted_list *node;

	if (l == NULL) 
	{
		fprintf(stderr,"exclusiveFind_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	if (sem_wait(&(l->mutex_list))) 
	{
		perror("exclusiveFind_shared_sorted_list: sem_wait with mutex_list");
		exit(1);
	}

	if (compare == NULL) {
		f = l->f_compare;
	}
	else {
		f = compare;
	}

	// Iterate the list to search the element with value >= val
	node = l->header;
	while (node != NULL && node->remove_request == 0 && (*f)(val, node->info) == 1) {
			// Next node
			node = node->next;
	}
	if (node != NULL) {
		// Value found in the list?
		if ((*f)(val, node->info) != 0) {
			// Not found.
			node = NULL;
		}
		else {
			node->nprocs++;
		}
	}

	if (sem_post(&(l->mutex_list)))
	{
		perror("exclusiveFind_shared_sorted_list: sem_post with mutex_list");
		exit(1);
	}

	return node;
}


void clear_all_shared_sorted_list(shared_sorted_list l, int free_info, void (*f)(void *, void *), void *param)
{
	struct node_shared_sorted_list *node, *current_node;

	if (l == NULL) 
	{
		fprintf(stderr,"clear_all_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	node = firstNode_shared_sorted_list(l);
	while (node != NULL) {
		// Node to remove to current_node
		current_node = node;

		// Next node
		node = nextNode_shared_sorted_list(l, node, 0);

		if (f != NULL) {
			// Request write access
			requestWriteNode_shared_sorted_list(current_node);
			(*f)(current_node->info, param);
			// Leave write access
			leaveWriteNode_shared_sorted_list(current_node);
		}

		// Remove current node
		removeNode_shared_sorted_list(l, current_node, free_info);
	}
}

void insert_shared_sorted_list(shared_sorted_list l,  void * val)
{
	int (*f)(void *, void*);
	struct node_shared_sorted_list *new_node = NULL, *node, *prev_node;
	int fin = 0;

	// Is list initialized?
	if (l == NULL) 
	{
		fprintf(stderr,"insert_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	// Create the new node
	new_node = (struct node_shared_sorted_list *) malloc(sizeof(struct node_shared_sorted_list));
	if (new_node == NULL)
	{
		fprintf(stderr,"insert_shared_sorted_list: Could not allocate memory!!\n");
		exit(1);		
	}
	new_node->remove_request = 0;
	new_node->write_requests = 0;
	new_node->nreaders = 0;
	new_node->nprocs = 0;	
	if (sem_init(&(new_node->writers_sem), 0, 1))
	{		
		perror("insert_shared_sorted_list: Couldn't create writers_sem semaphore for the node!!!!");
		exit(1);
	}
	if (sem_init(&(new_node->readers_sem), 0, 1))
	{		
		perror("insert_shared_sorted_list: Couldn't create readers_sem semaphore for the node!!!!");
		exit(1);
	}
	if (sem_init(&(new_node->mutex_sem), 0, 1))
	{		
		perror("insert_shared_sorted_list: Couldn't create mutex_sem semaphore for the node!!!!");
		exit(1);
	}
	new_node->info = val;

	if (sem_wait(&(l->mutex_list))) 
	{
		perror("insert_shared_sorted_list: sem_wait with mutex_list");
		exit(1);
	}

	// Empty list?
	if (l->n_elements == 0) {
		// Special case: list is empty
		new_node->prev = NULL;
		new_node->next = NULL;
		l->header = new_node;
		l->tail = new_node;
		l->n_elements++;
		if (sem_post(&(l->mutex_list)))
		{
			perror("insert_shared_sorted_list: sem_post with mutex_list");
			exit(1);
		}
	}
	else {
		// List is not empty
		f = l->f_compare;
		if (sem_post(&(l->mutex_list)))
		{
			perror("insert_shared_sorted_list: sem_post with mutex_list");
			exit(1);
		}

		// Find the position for the new node
		// Iterate the list to search the element equal or greater than val
		node = firstNode_shared_sorted_list(l);
		while (node != NULL && !fin) {
			// Request read access to node
			requestReadNode_shared_sorted_list(node);

			// Compares val with info node
			fin = (*f)(val, node->info) != 1;

			// No more read access needed for node
			leaveReadNode_shared_sorted_list(node);

			if (!fin) {
				// We have to continue searching
				// Next node
				node = nextNode_shared_sorted_list(l, node, 1);
			}
		}

		if (sem_wait(&(l->mutex_list))) 
		{
			perror("insert_shared_sorted_list: sem_wait with mutex_list");
			exit(1);
		}

		if (node != NULL) {
			// Not inserting at the end of the list
			// Get previous node
			prev_node = node->prev;
			node->prev = new_node;

			// Inserting before node
			new_node->next = node;
			new_node->prev = prev_node;

			if (prev_node == NULL) {
				// Inserting at the beginning
				l->header = new_node;
			}
			else {
				// Inserting at the middle
				prev_node->next = new_node;
			}

			// One more element in the list
			l->n_elements++;

			if (sem_post(&(l->mutex_list)))
			{
				perror("insert_shared_sorted_list: sem_post with mutex_list");
				exit(1);
			}

			// Leaving current node
			leaveNode_shared_sorted_list(l, node);
		}
		else {
			// Inserting at the end of the list
			// Get previous node
			prev_node = l->tail;

			// Inserting at the end
			new_node->next = node;
			new_node->prev = prev_node;

			prev_node->next = new_node;
			l->tail = new_node;

			// One more element in the list
			l->n_elements++;

			if (sem_post(&(l->mutex_list)))
			{
				perror("insert_shared_sorted_list: sem_post with mutex_list");
				exit(1);
			}
		}
	}
}

void remove_shared_sorted_list(shared_sorted_list l, void *val, int free_info, int (*compare)(void *, void*))
{
	int (*f)(void *, void*);
	struct node_shared_sorted_list *node, *current;

	if (l == NULL) 
	{
		fprintf(stderr,"remove_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	if (compare == NULL) {
		if (sem_wait(&(l->mutex_list))) 
		{
			perror("remove_shared_sorted_list: sem_wait with mutex_list");
			exit(1);
		}
		f = l->f_compare;
		if (sem_post(&(l->mutex_list)))
		{
			perror("remove_shared_sorted_list: sem_post with mutex_list");
			exit(1);
		}
	}
	else {
		f = compare;
	}

	node = find_shared_sorted_list(l, val, compare);

	// Remove all elements equal to val
	while (node != NULL && !(*f)(val, node->info))
	{
		// Save node to remove
		current = node;

		// Next node
		node = nextNode_shared_sorted_list(l, node, 1);

		// Remove current node
		removeNode_shared_sorted_list(l, current, free_info);
	}
}

void removeNode_shared_sorted_list(shared_sorted_list l, struct node_shared_sorted_list *node, int free_info) 
{
	struct node_shared_sorted_list *prev_node, *next_node;

	if (l == NULL) 
	{
		fprintf(stderr,"remove_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	if (!requestRemoveNode_shared_sorted_list(l, node)) {
		// Someone else is going to remove this node. Returning now
		return;
	}

	// We can now remove the node safely

	if (sem_wait(&(l->mutex_list))) 
	{
		perror("removeNode_shared_sorted_list: sem_wait with mutex_list");
		exit(1);
	}

	// Destroy semaphores of current node
	sem_destroy(&(node->writers_sem));
	sem_destroy(&(node->readers_sem));
	sem_destroy(&(node->mutex_sem));

	// Remove the node from list
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

	if (free_info) {
		free(node->info);
	}
	free(node);
	l->n_elements--;

	if (sem_post(&(l->mutex_list)))
	{
		perror("removeNode_shared_sorted_list: sem_post with mutex_list");
		exit(1);
	}

}

void updateNode_shared_sorted_list(shared_sorted_list l, struct node_shared_sorted_list *node) {
	struct node_shared_sorted_list *p, *prev_p, *prev_node, *next_node;

	if (l == NULL) 
	{
		fprintf(stderr,"updateNode_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	if (sem_wait(&(l->mutex_list))) 
	{
		perror("updateNode_shared_sorted_list: sem_wait with mutex_list");
		exit(1);
	}

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
		while (p != NULL && (l->f_compare)(node->info, p->info) == 1)
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

	if (sem_post(&(l->mutex_list)))
	{
		perror("updateNode_shared_sorted_list: sem_post with mutex_list");
		exit(1);
	}

}

void for_each_readonly_shared_sorted_list(shared_sorted_list l, void (*f)(void *, void *), void *param) {
	struct node_shared_sorted_list *node;

	if (l == NULL) 
	{
		fprintf(stderr,"for_each_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	// Iterate the list and call f with every element
	node = firstNode_shared_sorted_list(l);
	while (node != NULL) {
		// Request read access
		requestReadNode_shared_sorted_list(node);
		(*f)(node->info, param);
		// Leave read access
		leaveReadNode_shared_sorted_list(node);
		// Next node
		node = nextNode_shared_sorted_list(l, node, 1);
	}
}

void for_each_shared_sorted_list(shared_sorted_list l, void (*f)(void *, void *), void *param) {
	struct node_shared_sorted_list *node;

	if (l == NULL) 
	{
		fprintf(stderr,"for_each_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	// Iterate the list and call f with every element
	node = firstNode_shared_sorted_list(l);
	while (node != NULL) {
		// Request write access
		requestWriteNode_shared_sorted_list(node);
		(*f)(node->info, param);
		// Leave write access
		leaveWriteNode_shared_sorted_list(node);
		// Next node
		node = nextNode_shared_sorted_list(l, node, 1);
	}
}

void for_eachNode_shared_sorted_list(shared_sorted_list l, void (*f)(struct node_shared_sorted_list *, void *), void *param) {
	struct node_shared_sorted_list *node;

	if (l == NULL) 
	{
		fprintf(stderr,"for_eachNode_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	// Iterate the list and call f with every element
	node = firstNode_shared_sorted_list(l);
	while (node != NULL) {
		(*f)(node, param);
		// Next node
		node = nextNode_shared_sorted_list(l, node, 1);
	}
}

void resort_shared_sorted_list(shared_sorted_list l) {
	if (l == NULL) 
	{
		fprintf(stderr,"resort_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	if (isEmpty_shared_sorted_list(l)) return;

	if (sem_wait(&(l->mutex_list))) 
	{
		perror("resort_shared_sorted_list: sem_wait with mutex_list");
		exit(1);
	}

	// Using Quicksort method
	quicksort_shared_sorted_list(l, l->header, l->tail);

	if (sem_post(&(l->mutex_list)))
	{
		perror("resort_shared_sorted_list: sem_post with mutex_list");
		exit(1);
	}
}

void quicksort_shared_sorted_list(shared_sorted_list l, struct node_shared_sorted_list *first, struct node_shared_sorted_list *last) {
	void *pivot;	// Pivot element will be the last
	struct node_shared_sorted_list *p, *current, *prev_current, *next_current, *next_last;

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
		quicksort_shared_sorted_list(l, l->header, last->prev);
	}
	else {
		// No elements before last node
		quicksort_shared_sorted_list(l, NULL, NULL);
	}

	// Recursive call with elements on the right of pivot (right of last node)
	if (last->next != NULL) {
		// There are elements after last node
		quicksort_shared_sorted_list(l, last->next, l->tail);
	}
	else {
		// No elements before last node
		quicksort_shared_sorted_list(l, NULL, NULL);
	}
}