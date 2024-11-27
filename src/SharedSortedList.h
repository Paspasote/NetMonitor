#ifndef __SHARED_SORTED_LIST_H
#define __SHARED_SORTED_LIST_H

#include <pthread.h>
#include <DoubleList.h>

#define DEBUG 2

typedef enum {
   READER      = 0,
   WRITER      = 1
} access_t;
struct info_queue  {
   access_t type;
   pthread_cond_t *cond_var;
   int group_count;
};
struct node_shared_sorted_list 
{
   double_list requests_queue;
	pthread_mutex_t mutex_requests;
   pthread_mutex_t mutex_sem;
   unsigned awakening_group;
	unsigned remove_request;
	unsigned nreaders;
   unsigned nwriters;
	unsigned nprocs;
   int free_info;

	void * info;
	struct node_shared_sorted_list *next;
	struct node_shared_sorted_list *prev;
};

typedef struct info_shared_sorted_list {
	pthread_mutex_t mutex_list;
   pthread_mutex_t mutex_remove_insert;
	struct node_shared_sorted_list *header;
	struct node_shared_sorted_list *tail;
	unsigned long elements_count;
   unsigned long nodes_count;
	int (*f_compare)(void *, void *);
} *shared_sorted_list;

// Function prototypes

/* NEEDS: A pointer to shared_sorted_list var with NULL value
          The function to compare two elements of the list (for sorting)
		  This function must return -1 if first value is less than second one,
		  0 if both values are equal and 1 in another case.
   MODIFY: l with an empty list
   ERROR: If l is not NULL
*/
void init_shared_sorted_list(shared_sorted_list *l, int (*compare)(void *, void*) );

/* NEEDS: A list already initialized
          A node of the list
   MODIFIES: Allow access to node (just access to it, not for read/write).
   RETURN: 1 if access is allowed, 0 in another case (node is marked for removing)
   NOTE1: It is not needed to call this operation unless we point directly the node without calling
         other request operations.
   NOTE2: If thread doesn't have a previous access to this node (by mean of other operations) then 
          this operation DOES NOT GUARANTEE the node has not been previously deleted and freed. So 
          call to this operation can result in a segmentation fault.
*/
int requestAccessNode_shared_sorted_list(shared_sorted_list l, struct node_shared_sorted_list *node);

/* NEEDS: A node of the list
   MODIFIES: Allow access to node for reading (only). Access can be concurrent with others (readers)
   RETURN: 1 if read access is allowed, 0 in another case (node is marked for removing)
   NOTE1: This operation is a blocking one (only return if access is allowed or node is marked for removing)
   NOTE2: DO NOT read node info of the list without requesting this access!!!!
*/
int requestReadNode_shared_sorted_list(struct node_shared_sorted_list *node);

/* NEEDS: A node of the list with read access granted
   MODIFIES: Remove read access to node
   NOTE: Once a thread doesn't need to read the node, MUST call this function so that others (writers) can access the node
   ERROR: If leave read access without a previous request read access
*/
void leaveReadNode_shared_sorted_list(struct node_shared_sorted_list *node);

/* NEEDS: A node of the list
   MODIFIES: Allow access to node for reading/writing (only). Access CAN NOT be concurrent with others (readers or writers)
   RETURN: 1 if write access is allowed, 0 in another case (node is marked for removing)
   NOTE1: This operation is a blocking one (only return if access is allowed or node is marked for removing)
   NOTE2: DO NOT modify a node of the list without requesting this access!!!!
*/
int requestWriteNode_shared_sorted_list(struct node_shared_sorted_list *node);

/* NEEDS: A node of the list with write access granted
   MODIFIES: Remove write access to node
   NOTE: Once a thread doesn't need to write the node, MUST call this function so that others can access the node
*/
void leaveWriteNode_shared_sorted_list(struct node_shared_sorted_list *node);

/* NEEDS: A list already initialized
          A node of the list
   MODIFIES: Decrement by one the number of pointers using this node
   NOTE1: Once a thread doesn't need access to this node (neither read or write or remove), MUST call this function
          so that update the number of pointers using this node
   NOTE2: A node WONT be removed if this number is more than one (The node is not only accessed by the thread that is going
          to remove it )
   NOTE3: If node is marked to be removed and last proc leaves it then it will be removed automatically.
   ERROR: If leave node without a previous access to it
*/
void leaveNode_shared_sorted_list(shared_sorted_list l, struct node_shared_sorted_list *node);

/* NEEDS: A list already initialized
   RETURNS: 1 if list is empty or 0 in another case
   ERROR: If list is not initialized
*/
int isEmpty_shared_sorted_list(shared_sorted_list l);

/* NEEDS: A list already initialized
   RETURNS: The number of elements in the list
   ERROR: If list is not initialized
*/
unsigned long size_shared_sorted_list(shared_sorted_list l);

/*  NEEDS: A node list.
    RETURNS: 1 if node is marked to be removed, 0 in another case
*/
int isNodeRemoved_shared_sorted_list(struct node_shared_sorted_list *node);

/* NEEDS: A list already initialized
   MODIFIES: Increment by one the number of pointers using this node
   RETURNS: The first node of the list (not marked for removing) or NULL if the list is empty            
*/
struct node_shared_sorted_list * firstNode_shared_sorted_list(shared_sorted_list l);

/* NEEDS: A list already initialized
		  A node of the list
          An integer to indicate if thread leaves the current node: 1 leave, 0 don't leave
   MODIFIES: Increment by one the number of pointers using the next node (the returned one)
             if leave_current is one, decrement the number of pointers of current node
   RETURNS: The next node of the list (not marked for removing) or NULL if we have reached the end of the list
*/
struct node_shared_sorted_list * nextNode_shared_sorted_list(shared_sorted_list l, struct node_shared_sorted_list *node, int leave_current);

/* NEEDS: A list already initialized
          A value
		  A compare function or NULL (the compare function of the list will be used in this case)
   MODIFIES: Increment by one the number of pointers of the node with the value (if any)
   RETURNS: The node of the list (not marked for removing) with the value or NULL if there are none
   NOTE: This search DOES NOT GUARANTEE  val is/isn't in the list because others threads can move, delete, insert, nodes while
           searching the val
   ERROR: If list is not initialized
*/
struct node_shared_sorted_list * find_shared_sorted_list(shared_sorted_list l, void *val, int (*compare)(void *, void*) );

/* NEEDS: A list already initialized
          A value
		  A compare function or NULL (the compare function of the list will be used in this case)
   MODIFIES: Increment by one the number of pointers of the node with the value (if any)
   RETURNS: The node of the list  (not marked for removing)  with the value or NULL if there are none
   NOTE1: This search DOES NOT GUARANTEE val is/isn't in the list because any writer can change values to the list while searching
          But moving, inserting, or deleting nodes are not allowed while in search
   ERROR: If list is not initialized
*/
struct node_shared_sorted_list * exclusiveFind_shared_sorted_list(shared_sorted_list l, void *val, int (*compare)(void *, void*) );

/* NEEDS: A list already initialized
          A boolean (int)
          A function (or NULL)
          An extra param for the function (or NULL)
   MODIFIES: Remove all elements of the list (elements will be removed when no one else is accessing).
             The function f is called (if not NULL) before remove every element and after requesting write access. This functions is called with the following
             arguments: element of the list, param
             if free_info is 1 then the free operation will be applied to every element.
   NOTE: This operation could be a bit slow because it has to wait for all nodes to be free and for write access
   ERROR: If list is not initialized
*/
void clear_all_shared_sorted_list(shared_sorted_list l, int free_info, void (*f)(void *, void *), void *param);

/* NEEDS: A list already initialized
          A boolean (int)
          A function (or NULL)
          An extra param for the function (or NULL)
   MODIFIES: Remove all elements of the list (elements will be removed when no one else is accessing).
             The function f is called (if not NULL) before remove every element. This functions is called with the following
             arguments: element of the list, param
             if free_info is 1 then the free operation will be applied to every element.
   NOTE: This operation is faster than previous operation because moving, inserting, or deleting nodes are not allowed until this operation finish. f is called WITHOUT ANY PREVIOUS ACCESS REQUESTED
   ERROR: If list is not initialized
*/
void exclusiveClear_all_shared_sorted_list(shared_sorted_list l, int free_info, void (*f)(void *, void *), void *param);

/* NEEDS: A list already initialized
          A val
   MODIFIES: Insert a new node in the list with the val value
   NOTE: The caller has NOT access to node granted
   ERROR: If list is not initialized or can not allocate memory for new element
*/
void insert_shared_sorted_list(shared_sorted_list l,  void *val);

/* NEEDS: A list already initialized
          A val
   MODIFIES: Insert a new node in the list with the val value
   RETURNS: The node inserted or NULL if any node was inserted
   NOTE: The caller has access to node granted and must leave node when it is no longer necessary
   ERROR: If list is not initialized or can not allocate memory for new element
*/
struct node_shared_sorted_list * insert_access_shared_sorted_list(shared_sorted_list l,  void *val);

/* NEEDS: A list already initialized
          A val
   MODIFIES: Insert a new node in the list with the val value
   RETURNS: The node inserted or NULL if any node was inserted
   NOTE: The caller has READ access to node granted and must leave read access and leave node when it is no longer necessary
   ERROR: If list is not initialized or can not allocate memory for new element
*/
struct node_shared_sorted_list * insert_read_access_shared_sorted_list(shared_sorted_list l,  void *val);

/* NEEDS: A list already initialized
          A val
   MODIFIES: Insert a new node in the list with the val value
   RETURNS: The node inserted or NULL if any node was inserted
   NOTE: The caller has WRITE access to node granted and must leave write access and leave node when it is no longer necessary
   ERROR: If list is not initialized or can not allocate memory for new element
*/
struct node_shared_sorted_list * insert_write_access_shared_sorted_list(shared_sorted_list l,  void *val);

/* NEEDS: A list already initialized
          A value
          A boolean (int)
		    A compare function or NULL (the compare function of the list will be used in this case)
   MODIFIES: Remove the node with the value (if any). 
             If free_info is 1 the free operation over info node will be called after remove
   RETURN: Number of items removed (either now or later)
   NOTE1: This operation is NOT BLOCKING.
   NOTE2: The elements (nodes) will be removed when no one (apart from the calling process) is accessing to it. IT IS NOT NEEDED to call any request operation
   ERROR: If list is not initialized
*/
int remove_shared_sorted_list(shared_sorted_list l, void *val, int free_info, int (*compare)(void *, void*));

/* NEEDS: A list already initialized
          A node of the list
          A boolean (int)
          An integer to indicate if thread leave current node: 1 leave, 0 don't leave
   MODIFIES: Remove the node. If free_info is 1 the free operation over info node will be called after remove
   RETURN: 1 if node has been removed, 0 if someone else requested to remove this node
   NOTE1: The process calling this operation MUST HAVE ACCESS TO THIS NODE (and not leave that access before the remove)
   NOTE2: This operation is NOT BLOCKING.
   NOTE3: The node will be removed when no one is accessing to it. IT IS NOT NEEDED to call any request operation
   ERROR: If list is not initialized
*/
int removeNode_shared_sorted_list(shared_sorted_list l, struct node_shared_sorted_list *node, int free_info, int leave_current);

/* NEEDS: A list already initialized
          A node of the list
   MODIFIES: Relocate node in its right position
   NOTE1: THREADS MUST CALL THIS OPERATION AFTER CHANGE THE NODE'S VALUE IF THIS CHANGE AFFECTS ORDERING.
   NOTE2: WRITE ACCESS TO NODE IS NEEDED
   NOTE3: TO RELOCATE NODE IT WILL BE MARK FOR REMOVING AND INSERTED AGAIN. NODE WILL BE REMOVED WHEN LAST THREAD LEAVES NODE, UNTIL THEN
           OLD AND NEW NODE WILL HAVE THE SAME NEW VALUE. SO THREADS CAN MOVE TO PREV/NEXT NODE SAFETY (FROM ORIGINAL NODE POSITION)
   ERROR: If list is not initialized
*/
void updateNode_shared_sorted_list(shared_sorted_list l, struct node_shared_sorted_list *node);

/* NEEDS: A list already initialized
          A function
          An extra param for the function (or NULL)
   MODIFIES: Calls the function with every element of the list (and extra param)
   NOTE: IT IS NOT NEEDED to call any request operation. Read access will be requested automatically with every node
   ERROR: If list is not initialized
*/
void for_each_readonly_shared_sorted_list(shared_sorted_list l, void (*f)(void *, void *), void *param);

/* NEEDS: A list already initialized
          A function
          An extra param for the function (or NULL)
   MODIFIES: Calls the function with every element of the list and param as second argument
   NOTE: IT IS NOT NEEDED to call any request operation. Write access will be requested automatically with every node
   ERROR: If list is not initialized
*/
void for_each_shared_sorted_list(shared_sorted_list l, void (*f)(void *, void *), void *param);

/* NEEDS: A list already initialized
          A function
          An extra param for the function (or NULL)
   MODIFIES: Calls the function with every node of the list and param as second argument
   NOTE: IT IS NEEDED to call any request operation. No access is granted to node
   ERROR: If list is not initialized
*/
void for_eachNode_shared_sorted_list(shared_sorted_list l, void (*f)(struct node_shared_sorted_list *, void *), void *param);

/* NEEDS A list already initialized
   MODIFIES: Resort the list with "Quick sort method"
   NOTE: While doing this operation move, insert or remove in the list is NOT allowed
   ERROR: If list is not initialized
*/
void resort_shared_sorted_list(shared_sorted_list l);

#if DEBUG == 2
void checkNProcs_shared_sorted_list(shared_sorted_list l,  void (*f)(void *));
#endif

#endif
