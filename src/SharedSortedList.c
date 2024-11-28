#include <stdio.h>
#include <stdlib.h>

#include <SharedSortedList.h>

// Prototypes

/* NEEDS: A list already initialized
          A node of the list
   MODIFIES: Remove node from list and destroy it
   NOTE1: This operation is called automatically by the operations leaveNode_shared_sorted_list and exclusiveClear_all_shared_sorted_list
   NOTE2: The caller MUST lock the mutex mutex_remove_insert before call this operation.
*/
void removeNodeAux_shared_sorted_list(shared_sorted_list l, struct node_shared_sorted_list *node);

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

    if (pthread_mutex_init(&((*l)->mutex_list), NULL))
    {		
        perror("init_shared_sorted_list: Couldn't create mutex_list pthread_mutex for the list!!!!");
        exit(1);
    }
    if (pthread_mutex_init(&((*l)->mutex_remove_insert), NULL))
    {		
        perror("init_shared_sorted_list: Couldn't create mutex_remove_insert pthread_mutex for the list!!!!");
        exit(1);
    }
	(*l)->header = NULL;
	(*l)->tail = NULL;
	(*l)->nodes_count = 0;
	(*l)->elements_count = 0;
	(*l)->f_compare = compare;
}

int requestAccessNode_shared_sorted_list(shared_sorted_list l, struct node_shared_sorted_list *node)
{
	if (l == NULL) 
	{
		fprintf(stderr,"requestAccessNode_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	// Is there a remove request?
	if (pthread_mutex_lock(&(node->mutex_sem)))
	{
		perror("requestAccessNode_shared_sorted_list: pthrea7d_mutex_lock with mutex_sem node");
		exit(1);		
	}
	if (node->remove_request)
	{
		if (pthread_mutex_unlock(&(node->mutex_sem)))
		{
			perror("requestAccessNode_shared_sorted_list: pthread_mutex_unlock with mutex_sem node");
			exit(1);		
		}
		return 0;
	}

	// One proc more using the node
	node->nprocs++;
	if (pthread_mutex_unlock(&(node->mutex_sem)))
	{
		perror("requestAccessNode_shared_sorted_list: pthread_mutex_unlock with mutex_sem node");
		exit(1);		
	}
	
	return 1;
}

int requestReadNode_shared_sorted_list(struct node_shared_sorted_list *node)
{
	struct info_queue *aux, *aux2;
#if DEBUG >= 2
	int awaked = 0;
#endif

	// Is there a remove request?
	if (isNodeRemoved_shared_sorted_list(node))
	{
		// Yes. Can't read
		return 0;
	}

	// One more reader wants to read the node
	if (pthread_mutex_lock(&(node->mutex_requests)))
	{
		perror("requestReadNode_shared_sorted_list: pthread_mutex_lock with mutex_requests node");
		exit(1);
	}
#if DEBUG >= 2
	printf("Hilo LECTOR %lu solicita acceso lectura (nodo %p)\n", pthread_self(), node);
#endif
	// Any writer accessing or write requests pending?
	if (node->nwriters > 0 || !isEmpty_double_list(node->requests_queue)) {
#if DEBUG >= 2
		printf("Hilo LECTOR %lu debe esperar (nodo %p)\n", pthread_self(), node);
#endif
		// Must wait. Is requests queue empty?
		aux = NULL;
		if (!isEmpty_double_list(node->requests_queue)) {
			// Get info of thread in the tail
			aux = (struct info_queue *) tail_double_list(node->requests_queue);
#if DEBUG >= 2
			printf("Hilo LECTOR %lu comprobando si el último thread en la cola es un lector (nodo %p)\n", pthread_self(), node);
#endif
			// Is it a READER?
			if (aux->type != READER) {
				// I'm the first reader of a group. Must use another condition var
				aux = NULL;
			}
			else {
#if DEBUG >= 2
				printf("Hilo LECTOR %lu se añade al grupo lector (nodo %p)\n", pthread_self(), node);
#endif
				// Another reather in the group 
				aux->group_count++;
			}
		}
		// Am I the first reader in the group ?
		if (aux == NULL) {
			// Yes
#if DEBUG >= 2
			printf("Hilo LECTOR %lu es el primer lector del grupo. Creando variable cond (nodo %p)\n", pthread_self(), node);
#endif
			aux = (struct info_queue *) malloc(sizeof(struct info_queue));
			if (aux == NULL)
			{
				fprintf(stderr,"requestReadNode_shared_sorted_list: Could not allocate memory!!\n");
				exit(1);		
			}
			aux->type = READER;
			aux->group_count = 1;
			aux->cond_var = (pthread_cond_t *) malloc(sizeof(pthread_cond_t));
			if (aux->cond_var == NULL)
			{
				fprintf(stderr,"requestReadNode_shared_sorted_list: Could not allocate memory!!\n");
				exit(1);		
			}
			if (pthread_cond_init(aux->cond_var, NULL)) {
				perror("requestReadNode_shared_sorted_list: pthread_cond_init with aux->cond_var");
				exit(1);
			}
			// Enqueue myself
#if DEBUG >= 2
			printf("Hilo LECTOR %lu a la cola de peticiones (nodo %p)\n", pthread_self(), node);
#endif
			insert_tail_double_list(node->requests_queue, aux);
		}

		// Must wait in cond var until we have access
		aux2 = (struct info_queue *) front_double_list(node->requests_queue);
		while (node->nwriters > 0 || aux != aux2) {
#if DEBUG >= 2
			if (awaked) {
				printf("¡¡HILO LECTOR %lu SE HA DESPERTADO Y VUELTO A DORMIR!! (nodo: %p  nwriters: %0d  aux: %p   aux2: %p)", pthread_self(), node, node->nwriters, aux, aux2);
			}
			else {
				printf("Hilo LECTOR %lu se duerme (nodo %p)\n", pthread_self(), node);
			}
#endif
			if (pthread_cond_wait(aux->cond_var, &(node->mutex_requests))) {
				perror("requestReadNode_shared_sorted_list: pthread_cond_wait with aux->cond_var");
				exit(1);
			}
#if DEBUG >= 2
			awaked = 1;
			printf("Hilo LECTOR %lu se despierta (nodo %p)\n", pthread_self(), node);
			printf("Hilo LECTOR %lu obtiene frente de la cola (nodo %p)\n", pthread_self(), node);
#endif
			aux2 = (struct info_queue *) front_double_list(node->requests_queue);
		}

		// We have access now!
#if DEBUG >= 2
		printf("Hilo LECTOR %lu obtiene ya el acceso y comprueba si es el último del grupo (nodo %p)\n", pthread_self(), node);
#endif
		// One reader less waiting in group
		aux->group_count--;
		// if there are more readers in my group awake the next of them
		if (aux->group_count > 0) {
			// Another reader of my group
			node->awakening_group = 1;
#if DEBUG >= 2
			printf("Hilo LECTOR %lu comprobó que es otro lector de su grupo y lo despierta (nodo %p)\n", pthread_self(), node);
#endif
			if (pthread_cond_signal(aux->cond_var)) {
				perror("requestReadNode_shared_sorted_list: pthread_cond_signal with aux->cond_var");
				exit(1);
			}
		}
		else {
			// I'm the last reader of my group, we have to destroy cond var and free its memory
			node->awakening_group = 0;
#if DEBUG >= 2
			printf("Hilo LECTOR %lu comprobó que es el último lector (nodo %p)\n", pthread_self(), node);
#endif
			if (pthread_cond_destroy(aux->cond_var)) {
				perror("requestReadNode_shared_sorted_list: pthread_cond_destroy with aux->cond_var");
				exit(1);
			}
			free(aux->cond_var);
			// Dequeue myself and free memory
			remove_front_double_list(node->requests_queue, 1);
#if DEBUG >= 2
			printf("Hilo LECTOR %lu destruyó su variable condición y se desencoló (nodo %p)\n", pthread_self(), node);
#endif
		}
	}

	// Another reader accessing this node
	node->nreaders++;
#if DEBUG >= 2
	printf("Hilo LECTOR %lu regresa de la operación requestRead (nodo %p   readers: %0d)\n", pthread_self(), node, node->nreaders);
#endif
	if (pthread_mutex_unlock(&(node->mutex_requests))) {
		perror("requestReadNode_shared_sorted_list: pthread_mutex_unlock with mutex_requests node");
		exit(1);
	}
	return 1;
}

void leaveReadNode_shared_sorted_list(struct node_shared_sorted_list *node) {
	struct info_queue *aux;

	// One reader less using node
	if (pthread_mutex_lock(&(node->mutex_requests)))
	{
		perror("leaveReadNode_shared_sorted_list: pthread_mutex_lock with mutex_requests node");
		exit(1);
	}
	if (node->nreaders == 0)
	{
		fprintf(stderr,"leaveReadNode_shared_sorted_list: number of readers with access to node is under zero!!\n");
		exit(1);
	}
	node->nreaders--;
#if DEBUG >= 2
	printf("Hilo LECTOR %lu abandona acceso lectura (nodo %p   readers: %0d)\n", pthread_self(), node, node->nreaders);
	if (!node->awakening_group) {
		if (!isEmpty_double_list(node->requests_queue)) {
			printf("Hilo LECTOR %lu es el último que abandona lectura y despierta al siguiente (nodo %p)\n", pthread_self(), node);
		}
		else {
			printf("Hilo LECTOR %lu es el último que abandona lectura pero no hay más peticiones (nodo %p)\n", pthread_self(), node);
		}
	}
#endif
	// Have to awake the next?
	if (!node->awakening_group && !isEmpty_double_list(node->requests_queue)) {
		// Try to awake next thread in the queue
		// Get its info from queue
		aux = (struct info_queue *) front_double_list(node->requests_queue);
		if (pthread_cond_signal(aux->cond_var)) {
			perror("leaveReadNode_shared_sorted_list: pthread_cond_signal with aux->cond_var");
			exit(1);
		}
#if DEBUG >= 2
		if (aux->type == WRITER) {
			printf("Hilo LECTOR %lu despertó al siguiente escritor esperando (nodo %p)\n", pthread_self(), node);
		}
		else {
			printf("Hilo LECTOR %lu DESPERTÓ A UN LECTOR esperando (nodo %p)\n", pthread_self(), node);
		}
#endif
	}
#if DEBUG >= 2
	printf("Hilo LECTOR %lu regresa de la operación leaveRequestRead (nodo %p)\n", pthread_self(), node);
#endif
	if (pthread_mutex_unlock(&(node->mutex_requests))) {
		perror("leaveReadNode_shared_sorted_list: pthread_mutex_unlock with mutex_requests node");
		exit(1);
	}
}

int requestWriteNode_shared_sorted_list(struct node_shared_sorted_list *node) {
	struct info_queue *aux, *aux2;
#if DEBUG >= 2
	int awaked = 0;
#endif

	// Is there a remove request?
	if (isNodeRemoved_shared_sorted_list(node))
	{
		// Yes. Can't write
		return 0;
	}

	// One writer more requesting write access to the node
	if (pthread_mutex_lock(&(node->mutex_requests)))
	{
		perror("requestWriteNode_shared_sorted_list: pthread_mutex_lock with mutex_requests node");
		exit(1);
	}
#if DEBUG >= 2
	printf("Hilo ESCRITOR %lu solicita acceso (nodo %p)\n", pthread_self(), node);
#endif
	// Anyone accessing?
	if (node->nwriters > 0 || node->nreaders > 0 || !isEmpty_double_list(node->requests_queue)) {
#if DEBUG >= 2
		printf("Hilo ESCRITOR %lu debe esperar (nodo %p)\n", pthread_self(), node);
#endif
		// Must wait and insert myself in queue
		aux = (struct info_queue *) malloc(sizeof(struct info_queue));
		if (aux == NULL)
		{
			fprintf(stderr,"requestWriteNode_shared_sorted_list: Could not allocate memory!!\n");
			exit(1);		
		}
		aux->type = WRITER;
		// Must create a new cond var
		aux->cond_var = (pthread_cond_t *) malloc(sizeof(pthread_cond_t));
		if (aux->cond_var == NULL)
		{
			fprintf(stderr,"requestWriteNode_shared_sorted_list: Could not allocate memory!!\n");
			exit(1);		
		}
		if (pthread_cond_init(aux->cond_var, NULL)) {
			perror("requestWriteNode_shared_sorted_list: pthread_cond_init with aux->cond_var");
			exit(1);
		}
		// Enqueue myself
#if DEBUG >= 2
		printf("Hilo ESCRITOR %lu a la cola de peticiones (nodo %p)\n", pthread_self(), node);
#endif
		insert_tail_double_list(node->requests_queue, aux);
		// Must wait in cond var until we have access
		aux2 = (struct info_queue *) front_double_list(node->requests_queue);
		while (node->nwriters > 0 || node->nreaders > 0 || aux != aux2) {
#if DEBUG >= 2
			if (awaked) {
				printf("¡¡HILO ESCRITOR %lu SE HA DESPERTADO Y VUELTO A DORMIR!! (nodo: %p  nwriters: %0d  nreaders: %0d   aux: %p   aux2: %p)", pthread_self(), node, node->nwriters, node->nreaders, aux, aux2);
			}
			else {
				printf("Hilo ESCRITOR %lu se duerme (nodo %p)\n", pthread_self(), node);
			}
#endif
			if (pthread_cond_wait(aux->cond_var, &(node->mutex_requests))) {
				perror("requestWriteNode_shared_sorted_list: pthread_cond_wait with mutex_requests node");
				exit(1);
			}
#if DEBUG >= 2
			awaked = 1;
			printf("Hilo ESCRITOR %lu se despierta (nodo %p)\n", pthread_self(), node);
			printf("Hilo ESCRITOR %lu obtiene frente de la cola (nodo %p)\n", pthread_self(), node);
#endif
			aux2 = (struct info_queue *) front_double_list(node->requests_queue);
		}

		// We have access now!
#if DEBUG >= 2
		printf("Hilo ESCRITOR %lu obtiene ya el acceso (nodo %p)\n", pthread_self(), node);
#endif
		// We have to destroy cond var and free its memory
		if (pthread_cond_destroy(aux->cond_var)) {
			perror("requestWriteNode_shared_sorted_list: pthread_cond_destroy with aux->cond_var");
			exit(1);
		}
		free(aux->cond_var);
		// Remove myself from queue and free memory
		remove_front_double_list(node->requests_queue, 1);
#if DEBUG >= 2
		printf("Hilo ESCRITOR %lu destruyó su variable condición y se desencoló (nodo %p)\n", pthread_self(), node);
#endif
	}

	// Another writer accessing this node
	node->nwriters++;
#if DEBUG >= 2
	printf("Hilo ESCRITOR %lu regresa de la operación requestWrite (nodo %p)\n", pthread_self(), node);
#endif
	if (pthread_mutex_unlock(&(node->mutex_requests))) {
		perror("requestWriteNode_shared_sorted_list: pthread_mutex_unlock with mutex_requests node");
		exit(1);
	}
	return 1;
}

void leaveWriteNode_shared_sorted_list(struct node_shared_sorted_list *node) {
	struct info_queue *aux;

	// One writer less using node
	if (pthread_mutex_lock(&(node->mutex_requests)))
	{
		perror("leaveWriteNode_shared_sorted_list: pthread_mutex_lock with mutex_requests node");
		exit(1);
	}
	if (node->nwriters == 0)
	{
		fprintf(stderr,"leaveWriteNode_shared_sorted_list: number of writers with access to node is under zero!!\n");
		exit(1);
	}
#if DEBUG >= 2
	printf("Hilo ESCRITOR %lu abandona acceso escritura (nodo %p)\n", pthread_self(), node);
#endif
	node->nwriters--;
	// if queue is not empty awake the next thread
	if (!isEmpty_double_list(node->requests_queue)) {
#if DEBUG >= 2
		printf("Hilo ESCRITOR %lu despierta al siguiente hilo esperando (nodo %p)\n", pthread_self(), node);
#endif
		// Get its info from queue
		aux = (struct info_queue *) front_double_list(node->requests_queue);
		// Awake him
		if (pthread_cond_signal(aux->cond_var)) {
			perror("leaveWriteNode_shared_sorted_list: pthread_cond_signal with aux->cond_var");
			exit(1);
		}
#if DEBUG >= 2
		printf("Hilo ESCRITOR %lu despertó al siguiente hilo esperando (nodo %p)\n", pthread_self(), node);
#endif
	}
#if DEBUG >= 2
	printf("Hilo ESCRITOR %lu regresa de la operación leaveRequestWrite (nodo %p)\n", pthread_self(), node);
#endif
	if (pthread_mutex_unlock(&(node->mutex_requests))) {
		perror("leaveWriteNode_shared_sorted_list: pthread_mutex_unlock with mutex_requests node");
		exit(1);
	}
}

void leaveNode_shared_sorted_list(shared_sorted_list l, struct node_shared_sorted_list *node) 
{
	if (l == NULL) 
	{
		fprintf(stderr,"leaveNode_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	// One proc less using the node
	if (pthread_mutex_lock(&(node->mutex_sem)))
	{
		perror("leaveNode_shared_sorted_list: pthread_mutex_lock with mutex_sem node");
		exit(1);		
	}
	if (node->nprocs == 0) {
		fprintf(stderr,"leaveNode_shared_sorted_list: number of procs with access to node is under zero!!\n");
		exit(1);
	}
	node->nprocs--;

	// Is this node marked to be removed and last proc leaves node?
	if (node->nprocs == 0 && node->remove_request)
	{		
		if (pthread_mutex_unlock(&(node->mutex_sem))) {
			perror("leaveNode_shared_sorted_list: pthread_mutex_unlock with mutex_sem node");
			exit(1);
		}
		if (pthread_mutex_lock(&(l->mutex_remove_insert)))
		{
			perror("leaveNode_shared_sorted_list: pthread_mutex_lock with mutex_remove_insert");
			exit(1);		
		}
		// Remove this node
		removeNodeAux_shared_sorted_list(l, node);
		if (pthread_mutex_unlock(&(l->mutex_remove_insert)))
		{
			perror("leaveNode_shared_sorted_list: pthread_mutex_unlock with mutex_remove_insert");
			exit(1);		
		}
	}
	else {
		if (pthread_mutex_unlock(&(node->mutex_sem))) {
			perror("leaveNode_shared_sorted_list: pthread_mutex_unlock with mutex_sem node");
			exit(1);
		}
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

	if (pthread_mutex_lock(&(l->mutex_list)))
	{
		perror("isEmpty_shared_sorted_list: pthread_mutex_lock with mutex_list");
		exit(1);		
	}
	ret = l->elements_count == 0;
	if (pthread_mutex_unlock(&(l->mutex_list))) {
		perror("isEmpty_shared_sorted_list: pthread_mutex_unlock with mutex_list");
		exit(1);
	}
	return ret;
}

unsigned long size_shared_sorted_list(shared_sorted_list l)
{
	unsigned long ret;

	if (l == NULL) 
	{
		fprintf(stderr,"size_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	if (pthread_mutex_lock(&(l->mutex_list)))
	{
		perror("size_shared_sorted_list: pthread_mutex_lock with mutex_list");
		exit(1);		
	}
	ret = l->elements_count;
	if (pthread_mutex_unlock(&(l->mutex_list))) {
		perror("size_shared_sorted_list: pthread_mutex_unlock with mutex_list");
		exit(1);
	}
	return ret;
}

int isNodeRemoved_shared_sorted_list(struct node_shared_sorted_list *node)
{
	int ret;

	// Is there a remove request?
	if (pthread_mutex_lock(&(node->mutex_sem)))
	{
		perror("isNodeRemoved_shared_sorted_list: pthread_mutex_lock with mutex_sem node");
		exit(1);		
	}
	ret = node->remove_request;
	if (pthread_mutex_unlock(&(node->mutex_sem))) {
		perror("isNodeRemoved_shared_sorted_list: pthread_mutex_unlock with mutex_sem node");
		exit(1);
	}
	return ret;
}

struct node_shared_sorted_list * firstNode_shared_sorted_list(shared_sorted_list l) 
{
	struct node_shared_sorted_list *first_node;
	int stop;

	if (l == NULL) 
	{
		fprintf(stderr,"firstNode_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	// We CAN'T do this operation while removing or inserting
	// DO NOT NEED TO LOCK mutex_list because mutex_remove_insert 
	// is more restrictive
	if (pthread_mutex_lock(&(l->mutex_remove_insert)))
	{
		perror("firstNode_shared_sorted_list: pthread_mutex_lock with mutex_remove_insert");
		exit(1);		
	}

	// Get first node
	first_node = l->header;

	// Advance until first node without remove request or end of list
	stop = 0;
	do {
		// Try to find a valid node (node without remove request)
		while (first_node != NULL && first_node->remove_request) {
			first_node = first_node->next;
		}

		// if found a valid node recheck remove request with mutex
		if (first_node != NULL) {
			if (pthread_mutex_lock(&(first_node->mutex_sem)))
			{
				perror("firstNode_shared_sorted_list: pthread_mutex_lock with mutex_sem node");
				exit(1);		
			}
			if (!first_node->remove_request) {
				first_node->nprocs++;
				stop = 1;
			}
			if (pthread_mutex_unlock(&(first_node->mutex_sem)))
			{
				perror("firstNode_shared_sorted_list: pthread_mutex_unlock with mutex_sem node");
				exit(1);		
			}
			if (!stop) {
				first_node = first_node->next;
			}
		}
	} while (!stop && first_node != NULL);

	if (pthread_mutex_unlock(&(l->mutex_remove_insert))) {
		perror("firstNode_shared_sorted_list: pthread_mutex_unlock with mutex_remove_insert");
		exit(1);
	}

	// Return first node
	return first_node;
}

struct node_shared_sorted_list * nextNode_shared_sorted_list(shared_sorted_list l, struct node_shared_sorted_list *node, int leave_current) 
{
	struct node_shared_sorted_list *nextNode;
	int stop;

	if (l == NULL) 
	{
		fprintf(stderr,"nextNode_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	// We CAN'T do this operation while removing or inserting
	// DO NOT NEED TO LOCK node->mutex_sem because mutex_remove_insert 
	// is more restrictive
	if (pthread_mutex_lock(&(l->mutex_remove_insert)))
	{
		perror("nextNode_shared_sorted_list: pthread_mutex_lock with mutex_remove_insert");
		exit(1);		
	}

	// Advance until we find a node without remove request, or end of list
	nextNode = node->next;
	stop = 0;
	do {
		// Try to find a valid node (node without remove request)
		while (nextNode != NULL && nextNode->remove_request) {
			nextNode = nextNode->next;
		}

		// if found a valid node recheck remove request with mutex
		if (nextNode != NULL) {
			if (pthread_mutex_lock(&(nextNode->mutex_sem)))
			{
				perror("nextNode_shared_sorted_list: pthread_mutex_lock with mutex_sem node");
				exit(1);		
			}
			if (!nextNode->remove_request) {
				nextNode->nprocs++;
				stop = 1;
			}
			if (pthread_mutex_unlock(&(nextNode->mutex_sem)))
			{
				perror("nextNode_shared_sorted_list: pthread_mutex_unlock with mutex_sem node");
				exit(1);		
			}
			if (!stop) {
				nextNode = nextNode->next;
			}
		}
	} while (!stop && nextNode != NULL);

	if (pthread_mutex_unlock(&(l->mutex_remove_insert))) {
		perror("nextNode_shared_sorted_list: pthread_mutex_unlock with mutex_remove_insert");
		exit(1);
	}

	if (leave_current) {
		leaveNode_shared_sorted_list(l, node);
	}

	// Return next node
	return nextNode;

}

/* struct node_shared_sorted_list * firstNode_shared_sorted_list(shared_sorted_list l) 
{
	struct node_shared_sorted_list *first_node;
	int stop;

	if (l == NULL) 
	{
		fprintf(stderr,"firstNode_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	// We CAN'T do this operation while removing or inserting
	// DO NOT NEED TO LOCK mutex_list because mutex_remove_insert 
	// is more restrictive
	if (pthread_mutex_lock(&(l->mutex_remove_insert)))
	{
		perror("firstNode_shared_sorted_list: pthread_mutex_lock with mutex_remove_insert");
		exit(1);		
	}

	// Get first node
	first_node = l->header;

	// Advance until first node without remove request or end of list
	stop = 0;
	while (first_node != NULL && !stop) {
		// Try to find a valid node (node without remove request)
		if (pthread_mutex_lock(&(first_node->mutex_sem)))
		{
			perror("firstNode_shared_sorted_list: pthread_mutex_lock with mutex_sem node");
			exit(1);		
		}
		if (!first_node->remove_request) {
			first_node->nprocs++;
			stop = 1;
		}
		if (pthread_mutex_unlock(&(first_node->mutex_sem)))
		{
			perror("firstNode_shared_sorted_list: pthread_mutex_unlock with mutex_sem node");
			exit(1);		
		}
		if (!stop) {
			first_node = first_node->next;
		}
	}

	if (pthread_mutex_unlock(&(l->mutex_remove_insert))) {
		perror("firstNode_shared_sorted_list: pthread_mutex_unlock with mutex_remove_insert");
		exit(1);
	}

	// Return first node
	return first_node;
}

struct node_shared_sorted_list * nextNode_shared_sorted_list(shared_sorted_list l, struct node_shared_sorted_list *node, int leave_current) 
{
	struct node_shared_sorted_list *nextNode;
	int stop;

	if (l == NULL) 
	{
		fprintf(stderr,"nextNode_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	// We CAN'T do this operation while removing or inserting
	// DO NOT NEED TO LOCK node->mutex_sem because mutex_remove_insert 
	// is more restrictive
	if (pthread_mutex_lock(&(l->mutex_remove_insert)))
	{
		perror("nextNode_shared_sorted_list: pthread_mutex_lock with mutex_remove_insert");
		exit(1);		
	}

	// Advance until we find a node without remove request, or end of list
	nextNode = node->next;
	stop = 0;
	while (nextNode != NULL && !stop) {
		// Try to find a valid node (node without remove request)
		if (pthread_mutex_lock(&(nextNode->mutex_sem)))
		{
			perror("nextNode_shared_sorted_list: pthread_mutex_lock with mutex_sem node");
			exit(1);		
		}
		if (!nextNode->remove_request) {
			nextNode->nprocs++;
			stop = 1;
		}
		if (pthread_mutex_unlock(&(nextNode->mutex_sem)))
		{
			perror("nextNode_shared_sorted_list: pthread_mutex_unlock with mutex_sem node");
			exit(1);		
		}
		if (!stop) {
			nextNode = nextNode->next;
		}
	} 

	if (pthread_mutex_unlock(&(l->mutex_remove_insert))) {
		perror("nextNode_shared_sorted_list: pthread_mutex_unlock with mutex_remove_insert");
		exit(1);
	}

	if (leave_current) {
		leaveNode_shared_sorted_list(l, node);
	}

	// Return next node
	return nextNode;

}
 */
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
		if (pthread_mutex_lock(&(l->mutex_list)))
		{
			perror("find_shared_sorted_list: pthread_mutex_lock with mutex_list");
			exit(1);		
		}
		f = l->f_compare;
		if (pthread_mutex_unlock(&(l->mutex_list)))
		{
			perror("find_shared_sorted_list: pthread_mutex_unlock with mutex_list");
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
		if (requestReadNode_shared_sorted_list(node))
		{
			// Compares val with info node
			fin = (*f)(val, node->info) != 1;

			if (!fin) {
				// No more read access needed for node
				leaveReadNode_shared_sorted_list(node);

				// Next node
				node = nextNode_shared_sorted_list(l, node, 1);
			}
		}
		else
		{
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
	int stop;

	if (l == NULL) 
	{
		fprintf(stderr,"exclusiveFind_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	if (pthread_mutex_lock(&(l->mutex_remove_insert))) 
	{
		perror("exclusiveFind_shared_sorted_list: pthread_mutex_lock with mutex_remove_insert");
		exit(1);
	}

	if (compare == NULL) {
		f = l->f_compare;
	}
	else {
		f = compare;
	}

	// Iterate the list to search the element with value >= val
	stop = 0;
	node = l->header;
	do {
		// Try to find a not removed node with value val, or end of list
		while (node != NULL && (node->remove_request == 1 || (*f)(val, node->info) == 1)) {
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
				// Found it
				// Recheck node is not removed with mutex locked
				if (pthread_mutex_lock(&(node->mutex_sem)))
				{
					perror("exclusiveFind_shared_sorted_list: pthread_mutex_lock with mutex_sem node");
					exit(1);		
				}
				if (!node->remove_request) {
					// One proc more using node
					node->nprocs++;
					stop = 1;
				}
				else {
					node = node->next;
				}
				if (pthread_mutex_unlock(&(node->mutex_sem)))
				{
					perror("exclusiveFind_shared_sorted_list: pthread_mutex_unlock with mutex_sem node");
					exit(1);		
				}
			}
		}
	} while (node != NULL && !stop);

	if (pthread_mutex_unlock(&(l->mutex_remove_insert)))
	{
		perror("exclusiveFind_shared_sorted_list: pthread_mutex_unlock with mutex_remove_insert");
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
			if (requestWriteNode_shared_sorted_list(current_node))
			{
				(*f)(current_node->info, param);
				// Leave write access
				leaveWriteNode_shared_sorted_list(current_node);
			}
		}

		// Remove current node
		removeNode_shared_sorted_list(l, current_node, free_info, 1);
	}
}

void exclusiveClear_all_shared_sorted_list(shared_sorted_list l, int free_info, void (*f)(void *, void *), void *param) {
 	struct node_shared_sorted_list *node, *current_node;

	if (l == NULL) 
	{
		fprintf(stderr,"clear_all_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	if (pthread_mutex_lock(&(l->mutex_remove_insert))) 
	{
		perror("clear_all_shared_sorted_list: pthread_mutex_lock with mutex_remove_insert");
		exit(1);
	}

	// Iterate the list 
	node = l->header;
	do {
		// Try to find a not removed node, or end of list
		while (node != NULL && node->remove_request) {
				// Next node
				node = node->next;
		}
		
		if (node != NULL) {
			// Found it
			current_node = node;
			node = node->next;
			// Recheck if node is not removed with mutex locked
			if (pthread_mutex_lock(&(current_node->mutex_sem)))
			{
				perror("clear_all_shared_sorted_list: pthread_mutex_lock with mutex_sem node");
				exit(1);		
			}
			if (!current_node->remove_request) {
				// we have to remove this node
 				(*f)(current_node->info, param);
				current_node->remove_request = 1;
				// Can we remove it and free it now?
				if (!current_node->nprocs) {
					// Yes, we can
					removeNodeAux_shared_sorted_list(l, current_node);
				}
			}
			if (pthread_mutex_unlock(&(current_node->mutex_sem)))
			{
				perror("clear_all_shared_sorted_list: pthread_mutex_unlock with mutex_sem node");
				exit(1);		
			}
		}
	} while (node != NULL);

	if (pthread_mutex_unlock(&(l->mutex_remove_insert)))
	{
		perror("clear_all_shared_sorted_list: pthread_mutex_unlock with mutex_remove_insert");
		exit(1);
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
	new_node->requests_queue = NULL;
	init_double_list(&(new_node->requests_queue));
	new_node->awakening_group = 0;
	new_node->remove_request = 0;
	new_node->nreaders = 0;
	new_node->nwriters = 0;
	new_node->nprocs = 0;
	new_node->free_info = 0;
	if (pthread_mutex_init(&(new_node->mutex_requests), NULL))
	{		
		perror("insert_shared_sorted_list: Couldn't create mutex_requests mutex for the node!!!!");
		exit(1);
	}
	if (pthread_mutex_init(&(new_node->mutex_sem), NULL))
	{		
		perror("insert_shared_sorted_list: Couldn't create mutex_sem mutex for the node!!!!");
		exit(1);
	}
	new_node->info = val;

	if (pthread_mutex_lock(&(l->mutex_remove_insert))) 
	{
		perror("insert_shared_sorted_list: pthread_mutex_lock with mutex_remove_insert");
		exit(1);
	}

	// Empty list?
	if (l->nodes_count == 0) {
		// Special case: list is empty
		new_node->prev = NULL;
		new_node->next = NULL;
		l->header = new_node;
		l->tail = new_node;

		// One more element in the list
		l->nodes_count++;
		if (pthread_mutex_lock(&(l->mutex_list))) 
		{
			perror("insert_shared_sorted_list: pthread_mutex_lock with mutex_list");
			exit(1);
		}
		l->elements_count++;
		if (pthread_mutex_unlock(&(l->mutex_list))) 
		{
			perror("insert_shared_sorted_list: pthread_mutex_unlock with mutex_list");
			exit(1);
		}

		if (pthread_mutex_unlock(&(l->mutex_remove_insert))) 
		{
			perror("insert_shared_sorted_list: pthread_mutex_unlock with mutex_remove_insert");
			exit(1);
		}
	}
	else {
		// List is not empty
		f = l->f_compare;
		if (pthread_mutex_unlock(&(l->mutex_remove_insert))) 
		{
			perror("insert_shared_sorted_list: pthread_mutex_unlock with mutex_remove_insert");
			exit(1);
		}

		// Find the position for the new node
		// Iterate the list to search the element equal or greater than val
		node = firstNode_shared_sorted_list(l);
		while (node != NULL && !fin) {
			// Request read access to node
			if (requestReadNode_shared_sorted_list(node))
			{
				// Compares val with info node
				fin = (*f)(val, node->info) == -1;

				// No more read access needed for node
				leaveReadNode_shared_sorted_list(node);

				if (!fin) {
					// We have to continue searching
					// Next node
					node = nextNode_shared_sorted_list(l, node, 1);
				}
			}
			else
			{
				// Next node
				node = nextNode_shared_sorted_list(l, node, 1);
			}
		}

		if (pthread_mutex_lock(&(l->mutex_remove_insert))) 
		{
			perror("insert_shared_sorted_list: pthread_mutex_lock with mutex_remove_insert");
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
			l->nodes_count++;
			if (pthread_mutex_lock(&(l->mutex_list))) 
			{
				perror("insert_shared_sorted_list: pthread_mutex_lock with mutex_list");
				exit(1);
			}
			l->elements_count++;
			if (pthread_mutex_unlock(&(l->mutex_list))) 
			{
				perror("insert_shared_sorted_list: pthread_mutex_unlock with mutex_list");
				exit(1);
			}

			if (pthread_mutex_unlock(&(l->mutex_remove_insert))) 
			{
				perror("insert_shared_sorted_list: pthread_mutex_unlock with mutex_remove_insert");
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
			if (pthread_mutex_lock(&(l->mutex_list))) 
			{
				perror("insert_shared_sorted_list: pthread_mutex_lock with mutex_list");
				exit(1);
			}
			l->elements_count++;
			if (pthread_mutex_unlock(&(l->mutex_list))) 
			{
				perror("insert_shared_sorted_list: pthread_mutex_unlock with mutex_list");
				exit(1);
			}
			l->nodes_count++;

			if (pthread_mutex_unlock(&(l->mutex_remove_insert))) 
			{
				perror("insert_shared_sorted_list: pthread_mutex_unlock with mutex_remove_insert");
				exit(1);
			}
		}
	}
}

struct node_shared_sorted_list * insert_access_shared_sorted_list(shared_sorted_list l,  void * val)
{
	int (*f)(void *, void*);
	struct node_shared_sorted_list *new_node = NULL, *node, *prev_node;
	int fin = 0;

	// Is list initialized?
	if (l == NULL) 
	{
		fprintf(stderr,"insert_access_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	// Create the new node
	new_node = (struct node_shared_sorted_list *) malloc(sizeof(struct node_shared_sorted_list));
	if (new_node == NULL)
	{
		fprintf(stderr,"insert_access_shared_sorted_list: Could not allocate memory!!\n");
		exit(1);		
	}
	new_node->requests_queue = NULL;
	init_double_list(&(new_node->requests_queue));
	new_node->awakening_group = 0;
	new_node->remove_request = 0;
	new_node->nreaders = 0;
	new_node->nwriters = 0;
	new_node->nprocs = 1;
	new_node->free_info = 0;
	if (pthread_mutex_init(&(new_node->mutex_requests), NULL))
	{		
		perror("insert_access_shared_sorted_list: Couldn't create mutex_requests mutex for the node!!!!");
		exit(1);
	}
	if (pthread_mutex_init(&(new_node->mutex_sem), NULL))
	{		
		perror("insert_access_shared_sorted_list: Couldn't create mutex_sem mutex for the node!!!!");
		exit(1);
	}
	new_node->info = val;

	if (pthread_mutex_lock(&(l->mutex_remove_insert))) 
	{
		perror("insert_access_shared_sorted_list: pthread_mutex_lock with mutex_remove_insert");
		exit(1);
	}

	// Empty list?
	if (l->nodes_count == 0) {
		// Special case: list is empty
		new_node->prev = NULL;
		new_node->next = NULL;
		l->header = new_node;
		l->tail = new_node;

		// One more element in the list
		if (pthread_mutex_lock(&(l->mutex_list))) 
		{
			perror("insert_access_shared_sorted_list: pthread_mutex_lock with mutex_list");
			exit(1);
		}
		l->elements_count++;
		if (pthread_mutex_unlock(&(l->mutex_list))) 
		{
			perror("insert_access_shared_sorted_list: pthread_mutex_unlock with mutex_list");
			exit(1);
		}
		l->nodes_count++;

		if (pthread_mutex_unlock(&(l->mutex_remove_insert))) 
		{
			perror("insert_access_shared_sorted_list: pthread_mutex_unlock with mutex_remove_insert");
			exit(1);
		}
	}
	else {
		// List is not empty
		f = l->f_compare;
		if (pthread_mutex_unlock(&(l->mutex_remove_insert))) 
		{
			perror("insert_access_shared_sorted_list: pthread_mutex_unlock with mutex_remove_insert");
			exit(1);
		}

		// Find the position for the new node
		// Iterate the list to search the element equal or greater than val
		node = firstNode_shared_sorted_list(l);
		while (node != NULL && !fin) {
			// Request read access to node
			if (requestReadNode_shared_sorted_list(node))
			{
				// Compares val with info node
				fin = (*f)(val, node->info) == -1;

				// No more read access needed for node
				leaveReadNode_shared_sorted_list(node);

				if (!fin) {
					// We have to continue searching
					// Next node
					node = nextNode_shared_sorted_list(l, node, 1);
				}
			}
			else
			{
				// Next node
				node = nextNode_shared_sorted_list(l, node, 1);
			}
		}

		if (pthread_mutex_lock(&(l->mutex_remove_insert))) 
		{
			perror("insert_access_shared_sorted_list: pthread_mutex_lock with mutex_remove_insert");
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
			if (pthread_mutex_lock(&(l->mutex_list))) 
			{
				perror("insert_access_shared_sorted_list: pthread_mutex_lock with mutex_list");
				exit(1);
			}
			l->elements_count++;
			if (pthread_mutex_unlock(&(l->mutex_list))) 
			{
				perror("insert_access_shared_sorted_list: pthread_mutex_unlock with mutex_list");
				exit(1);
			}
			l->nodes_count++;

			if (pthread_mutex_unlock(&(l->mutex_remove_insert))) 
			{
				perror("insert_access_shared_sorted_list: pthread_mutex_unlock with mutex_remove_insert");
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
			if (pthread_mutex_lock(&(l->mutex_list))) 
			{
				perror("insert_access_shared_sorted_list: pthread_mutex_lock with mutex_list");
				exit(1);
			}
			l->elements_count++;
			if (pthread_mutex_unlock(&(l->mutex_list))) 
			{
				perror("insert_access_shared_sorted_list: pthread_mutex_unlock with mutex_list");
				exit(1);
			}
			l->nodes_count++;

			if (pthread_mutex_unlock(&(l->mutex_remove_insert))) 
			{
				perror("insert_access_shared_sorted_list: pthread_mutex_unlock with mutex_remove_insert");
				exit(1);
			}
		}
	}
	return new_node;
}

struct node_shared_sorted_list * insert_read_access_shared_sorted_list(shared_sorted_list l,  void * val)
{
	int (*f)(void *, void*);
	struct node_shared_sorted_list *new_node = NULL, *node, *prev_node;
	int fin = 0;

	// Is list initialized?
	if (l == NULL) 
	{
		fprintf(stderr,"insert_read_access_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	// Create the new node
	new_node = (struct node_shared_sorted_list *) malloc(sizeof(struct node_shared_sorted_list));
	if (new_node == NULL)
	{
		fprintf(stderr,"insert_read_access_shared_sorted_list: Could not allocate memory!!\n");
		exit(1);		
	}
	new_node->requests_queue = NULL;
	init_double_list(&(new_node->requests_queue));
	new_node->awakening_group = 0;
	new_node->remove_request = 0;
	new_node->nreaders = 1;
	new_node->nwriters = 0;
	new_node->nprocs = 1;
	new_node->free_info = 0;
	if (pthread_mutex_init(&(new_node->mutex_requests), NULL))
	{		
		perror("insert_read_access_shared_sorted_list: Couldn't create mutex_requests mutex for the node!!!!");
		exit(1);
	}
	if (pthread_mutex_init(&(new_node->mutex_sem), NULL))
	{		
		perror("insert_read_access_shared_sorted_list: Couldn't create mutex_sem mutex for the node!!!!");
		exit(1);
	}
	new_node->info = val;

	if (pthread_mutex_lock(&(l->mutex_remove_insert))) 
	{
		perror("insert_read_access_shared_sorted_list: pthread_mutex_lock with mutex_remove_insert");
		exit(1);
	}

	// Empty list?
	if (l->nodes_count == 0) {
		// Special case: list is empty
		new_node->prev = NULL;
		new_node->next = NULL;
		l->header = new_node;
		l->tail = new_node;

		// One more element in the list
		l->nodes_count++;
		if (pthread_mutex_lock(&(l->mutex_list))) 
		{
			perror("insert_read_access_shared_sorted_list: pthread_mutex_lock with mutex_list");
			exit(1);
		}
		l->elements_count++;
		if (pthread_mutex_unlock(&(l->mutex_list))) 
		{
			perror("insert_read_access_shared_sorted_list: pthread_mutex_unlock with mutex_list");
			exit(1);
		}

		if (pthread_mutex_unlock(&(l->mutex_remove_insert))) 
		{
			perror("insert_read_access_shared_sorted_list: pthread_mutex_unlock with mutex_remove_insert");
			exit(1);
		}
	}
	else {
		// List is not empty
		f = l->f_compare;
		if (pthread_mutex_unlock(&(l->mutex_remove_insert))) 
		{
			perror("insert_read_access_shared_sorted_list: pthread_mutex_unlock with mutex_remove_insert");
			exit(1);
		}

		// Find the position for the new node
		// Iterate the list to search the element equal or greater than val
		node = firstNode_shared_sorted_list(l);
		while (node != NULL && !fin) {
			// Request read access to node
			if (requestReadNode_shared_sorted_list(node))
			{
				// Compares val with info node
				fin = (*f)(val, node->info) == -1;

				// No more read access needed for node
				leaveReadNode_shared_sorted_list(node);

				if (!fin) {
					// We have to continue searching
					// Next node
					node = nextNode_shared_sorted_list(l, node, 1);
				}
			}
			else
			{
				// Next node
				node = nextNode_shared_sorted_list(l, node, 1);
			}
		}

		if (pthread_mutex_lock(&(l->mutex_remove_insert))) 
		{
			perror("insert_read_access_shared_sorted_list: pthread_mutex_lock with mutex_remove_insert");
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
			if (pthread_mutex_lock(&(l->mutex_list))) 
			{
				perror("insert_read_access_shared_sorted_list: pthread_mutex_lock with mutex_list");
				exit(1);
			}
			l->elements_count++;
			if (pthread_mutex_unlock(&(l->mutex_list))) 
			{
				perror("insert_read_access_shared_sorted_list: pthread_mutex_unlock with mutex_list");
				exit(1);
			}
			l->nodes_count++;

			if (pthread_mutex_unlock(&(l->mutex_remove_insert))) 
			{
				perror("insert_read_access_shared_sorted_list: pthread_mutex_unlock with mutex_remove_insert");
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
			if (pthread_mutex_lock(&(l->mutex_list))) 
			{
				perror("insert_read_access_shared_sorted_list: pthread_mutex_lock with mutex_list");
				exit(1);
			}
			l->elements_count++;
			if (pthread_mutex_unlock(&(l->mutex_list))) 
			{
				perror("insert_read_access_shared_sorted_list: pthread_mutex_unlock with mutex_list");
				exit(1);
			}
			l->nodes_count++;

			if (pthread_mutex_unlock(&(l->mutex_remove_insert))) 
			{
				perror("insert_read_access_shared_sorted_list: pthread_mutex_unlock with mutex_remove_insert");
				exit(1);
			}
		}
	}
	return new_node;
}

struct node_shared_sorted_list * insert_write_access_shared_sorted_list(shared_sorted_list l,  void * val)
{
	int (*f)(void *, void*);
	struct node_shared_sorted_list *new_node = NULL, *node, *prev_node;
	int fin = 0;

	// Is list initialized?
	if (l == NULL) 
	{
		fprintf(stderr,"insert_write_access_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	// Create the new node
	new_node = (struct node_shared_sorted_list *) malloc(sizeof(struct node_shared_sorted_list));
	if (new_node == NULL)
	{
		fprintf(stderr,"insert_write_access_shared_sorted_list: Could not allocate memory!!\n");
		exit(1);		
	}
	new_node->requests_queue = NULL;
	init_double_list(&(new_node->requests_queue));
	new_node->awakening_group = 0;
	new_node->remove_request = 0;
	new_node->nreaders = 0;
	new_node->nwriters = 1;
	new_node->nprocs = 1;
	new_node->free_info = 0;
	if (pthread_mutex_init(&(new_node->mutex_requests), NULL))
	{		
		perror("insert_write_access_shared_sorted_list: Couldn't create mutex_requests mutex for the node!!!!");
		exit(1);
	}
	if (pthread_mutex_init(&(new_node->mutex_sem), NULL))
	{		
		perror("insert_write_access_shared_sorted_list: Couldn't create mutex_sem mutex for the node!!!!");
		exit(1);
	}
	new_node->info = val;

	if (pthread_mutex_lock(&(l->mutex_remove_insert))) 
	{
		perror("insert_write_access_shared_sorted_list: pthread_mutex_lock with mutex_remove_insert");
		exit(1);
	}

	// Empty list?
	if (l->nodes_count == 0) {
		// Special case: list is empty
		new_node->prev = NULL;
		new_node->next = NULL;
		l->header = new_node;
		l->tail = new_node;

		// One more element in the list
		l->nodes_count++;
		if (pthread_mutex_lock(&(l->mutex_list))) 
		{
			perror("insert_write_access_shared_sorted_list: pthread_mutex_lock with mutex_list");
			exit(1);
		}
		l->elements_count++;
		if (pthread_mutex_unlock(&(l->mutex_list))) 
		{
			perror("insert_write_access_shared_sorted_list: pthread_mutex_unlock with mutex_list");
			exit(1);
		}

		if (pthread_mutex_unlock(&(l->mutex_remove_insert))) 
		{
			perror("insert_write_access_shared_sorted_list: pthread_mutex_unlock with mutex_remove_insert");
			exit(1);
		}
	}
	else {
		// List is not empty
		f = l->f_compare;
		if (pthread_mutex_unlock(&(l->mutex_remove_insert))) 
		{
			perror("insert_write_access_shared_sorted_list: pthread_mutex_unlock with mutex_remove_insert");
			exit(1);
		}

		// Find the position for the new node
		// Iterate the list to search the element equal or greater than val
		node = firstNode_shared_sorted_list(l);
		while (node != NULL && !fin) {
			// Request read access to node
			if (requestReadNode_shared_sorted_list(node))
			{
				// Compares val with info node
				fin = (*f)(val, node->info) == -1;

				// No more read access needed for node
				leaveReadNode_shared_sorted_list(node);

				if (!fin) {
					// We have to continue searching
					// Next node
					node = nextNode_shared_sorted_list(l, node, 1);
				}
			}
			else
			{
				// Next node
				node = nextNode_shared_sorted_list(l, node, 1);
			}
		}

		if (pthread_mutex_lock(&(l->mutex_remove_insert))) 
		{
			perror("insert_write_access_shared_sorted_list: pthread_mutex_lock with mutex_remove_insert");
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
			if (pthread_mutex_lock(&(l->mutex_list))) 
			{
				perror("insert_write_access_shared_sorted_list: pthread_mutex_lock with mutex_list");
				exit(1);
			}
			l->elements_count++;
			if (pthread_mutex_unlock(&(l->mutex_list))) 
			{
				perror("insert_write_access_shared_sorted_list: pthread_mutex_unlock with mutex_list");
				exit(1);
			}
			l->nodes_count++;

			if (pthread_mutex_unlock(&(l->mutex_remove_insert))) 
			{
				perror("insert_write_access_shared_sorted_list: pthread_mutex_unlock with mutex_remove_insert");
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
			if (pthread_mutex_lock(&(l->mutex_list))) 
			{
				perror("insert_write_access_shared_sorted_list: pthread_mutex_lock with mutex_list");
				exit(1);
			}
			l->elements_count++;
			if (pthread_mutex_unlock(&(l->mutex_list))) 
			{
				perror("insert_write_access_shared_sorted_list: pthread_mutex_unlock with mutex_list");
				exit(1);
			}
			l->nodes_count++;

			if (pthread_mutex_unlock(&(l->mutex_remove_insert))) 
			{
				perror("insert_write_access_shared_sorted_list: pthread_mutex_unlock with mutex_remove_insert");
				exit(1);
			}
		}
	}
	return new_node;
}

int remove_shared_sorted_list(shared_sorted_list l, void *val, int free_info, int (*compare)(void *, void*))
{
	int (*f)(void *, void*);
	struct node_shared_sorted_list *node, *current;
	int count, result;

	if (l == NULL) 
	{
		fprintf(stderr,"remove_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	if (compare == NULL) {
		if (pthread_mutex_lock(&(l->mutex_list)))
		{
			perror("remove_shared_sorted_list: pthread_mutex_lock with mutex_list");
			exit(1);		
		}
		f = l->f_compare;
		if (pthread_mutex_unlock(&(l->mutex_list)))
		{
			perror("remove_shared_sorted_list: pthread_mutex_unlock with mutex_list");
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
		node = nextNode_shared_sorted_list(l, node, 0);

		// Remove current node
		if (removeNode_shared_sorted_list(l, current, free_info, 1))
		{
			count++;
		}
	}
	return count;
}

int removeNode_shared_sorted_list(shared_sorted_list l, struct node_shared_sorted_list *node, int free_info, int leave_current) 
{
	int ret;

	if (l == NULL) 
	{
		fprintf(stderr,"removeNode_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	// Is there another remove request?
	if (pthread_mutex_lock(&(node->mutex_sem)))
	{
		perror("removeNode_shared_sorted_list: pthread_mutex_lock with mutex_sem node");
		exit(1);
	}
	if (node->remove_request)
	{
		// Yes. Can't remove node
		ret = 0;
	}
	else {
		// No. We can remove the node
		node->remove_request = 1;
		node->free_info = free_info;
		if (pthread_mutex_lock(&(l->mutex_list)))
		{
			perror("removeNode_shared_sorted_list: pthread_mutex_lock with mutex_list");
			exit(1);
		}
		l->elements_count--;
		if (pthread_mutex_unlock(&(l->mutex_list)))
		{
			perror("removeNode_shared_sorted_list: pthread_mutex_unlock with mutex_list");
			exit(1);
		}
		ret = 1;
	}
	if (pthread_mutex_unlock(&(node->mutex_sem))) {
		perror("removeNode_shared_sorted_list: pthread_mutex_unlock with mutex_sem node");
		exit(1);
	}
	// Leave current node
	if (leave_current) {
		leaveNode_shared_sorted_list(l, node);
	}
	return ret;
}

void removeNodeAux_shared_sorted_list(shared_sorted_list l, struct node_shared_sorted_list *node)
{
	struct node_shared_sorted_list *prev_node, *next_node;

	if (l == NULL) 
	{
		fprintf(stderr,"removeNodeAux_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	// Destroy mutex of current node
	pthread_mutex_destroy(&(node->mutex_requests));
	pthread_mutex_destroy(&(node->mutex_sem));

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

	if (node->free_info) {
		free(node->info);
	}
	free(node);
	l->nodes_count--;
}

int updateNode_shared_sorted_list(shared_sorted_list l, struct node_shared_sorted_list *node, void *new_val, int free_old_info) {
	int ret;

	if (l == NULL) 
	{
		fprintf(stderr,"updateNode_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	// Try to remove old value
	ret = removeNode_shared_sorted_list(l, node, free_old_info, 0);
	if (ret)
	{
		// Insert new one
		insert_shared_sorted_list(l, new_val);
	}
	return ret;
}

void for_each_readonly_shared_sorted_list(shared_sorted_list l, void (*f)(void *, void *), void *param) {
	struct node_shared_sorted_list *node;

	if (l == NULL) 
	{
		fprintf(stderr,"for_each_readonly_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

	// Iterate the list and call f with every element
	node = firstNode_shared_sorted_list(l);
	while (node != NULL) {
		// Request read access
		if (requestReadNode_shared_sorted_list(node))
		{
			(*f)(node->info, param);
			// Leave read access
			leaveReadNode_shared_sorted_list(node);
		}
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
		if (requestWriteNode_shared_sorted_list(node))
		{
			(*f)(node->info, param);
			// Leave write access
			leaveWriteNode_shared_sorted_list(node);
		}
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

	if (pthread_mutex_lock(&(l->mutex_remove_insert)))
	{
		perror("resort_shared_sorted_list: pthread_mutex_lock with mutex_remove_insert");
		exit(1);		
	}

	// Using Quicksort method
	quicksort_shared_sorted_list(l, l->header, l->tail);

	if (pthread_mutex_unlock(&(l->mutex_remove_insert)))
	{
		perror("resort_shared_sorted_list: pthread_mutex_unlock with mutex_remove_insert");
		exit(1);		
	}
}

void quicksort_shared_sorted_list(shared_sorted_list l, struct node_shared_sorted_list *first, struct node_shared_sorted_list *last) {
	void *pivot;	// Pivot element will be the last
	struct node_shared_sorted_list *p, *current, *prev_current, *next_current, *next_last;

	if (l == NULL) 
	{
		fprintf(stderr,"quicksort_shared_sorted_list: List is not valid!!\n");
		exit(1);
	}

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

#if DEBUG >= 1
	void checkNProcs_shared_sorted_list(shared_sorted_list l,  void (*f)(void *)) {
		int cont=0;
		struct node_shared_sorted_list *node;

		node = l->header;

		while (node != NULL) {
			if (node->nprocs) {
				(*f)(node->info);
				printf(":%0d ;", node->nprocs);
			}
			node = node->next;
			cont++;
		}
		printf("\n");
		printf("Hay un total de %0d nodos y nodes_count vale: %0ld\n", cont, l->nodes_count);
	}
#endif
