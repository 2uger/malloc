/*
 * Malloc implementation with simple list of blocks
 * with metadata information.
 */

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

// Closest and biggest for align 32 bits(4 bytes)
#define ALIGN4(x) (((((x)-1)>>2)<<2)+4)
#define MAX_MEMORY_ALLOCATION 4096
#define HEAP_SIZE 2000
#define VALIDATION_FLAG 'h'


/*
 * HeapBlock + size(MetaData) = pointer to the heap field
 */
typedef struct MetaData HeapBlock;

struct MetaData {
    char validation_flag;
    size_t size;
    uint8_t is_free;
    HeapBlock *next;
    HeapBlock *prev;
} __attribute__((packed));

static size_t META_DATA_SIZE = sizeof(HeapBlock);


/************* Malloc help functions ***************/

static HeapBlock* find_heap_block(size_t size);

static void split_heap_block(HeapBlock *block, size_t size);

static HeapBlock* extend_heap(HeapBlock *last_bloc, size_t size);

static int validate_heap_pointer(void *ptr);

static HeapBlock* unite_with_next_heap_block(HeapBlock *block);

void* ssbrk(size_t);

void* bbrk(void*);

void* malloc(size_t);

void free(void *ptr);


char heap[HEAP_SIZE];
static void *current_heap_location = heap;
HeapBlock *baseHeap = NULL;

int
main()
{
    size_t n_1 = 12;
    printf("Start address of heap: %p\n", ssbrk(0));
    void *p_1 = malloc(n_1);
    printf("Malloc memory start at: %p, should be at: %p\n", p_1, heap + META_DATA_SIZE);

    size_t n_2 = 24;
    void *p_2 = malloc(n_2);
    printf("Malloc memory start at: %p, should be at: %p\n", p_2, p_1 + n_1 + META_DATA_SIZE);

    free(p_2);
    printf("Current heap pointer after calling free for previous pointer:%p\n", current_heap_location - n_1);

    free(p_1);
    printf("Current heap pointer after calling free for previous pointer:%p\n", current_heap_location);

    return 0;
} 

/*
 * emulate sbrk system call
 */
void *
ssbrk(size_t increment)
{
    if (increment == 0)
        return current_heap_location;
    else if ((char*)current_heap_location + increment > &heap[HEAP_SIZE])
        return -1;
    
    current_heap_location += increment;

    return current_heap_location;
}

void *
bbrk(void *addr)
{
    if (addr > &heap[HEAP_SIZE] || addr < heap)
        return -1;

    current_heap_location = addr;

    return current_heap_location;
}

void *
malloc(size_t size) 
{
    if (size > MAX_MEMORY_ALLOCATION) 
        return NULL;

    size_t align_size = ALIGN4(size);
    
    HeapBlock *last_block = baseHeap;
    HeapBlock *new_block;

    if (baseHeap != NULL) {
        new_block = find_heap_block(align_size);

        if (new_block) {
            if (new_block->size >= align_size + META_DATA_SIZE + 4)
                split_heap_block(new_block, align_size);

            new_block->is_free = 0;
        } 
        else if (new_block == NULL) {
            new_block = extend_heap(last_block, align_size);
        } 
    } 
    else if (baseHeap == NULL) {
        new_block = extend_heap(NULL, align_size);
        if (new_block == NULL) 
            return NULL;
        new_block->is_free = 0;
        baseHeap = new_block; 
    } 

    return (char*)new_block + META_DATA_SIZE;
}

HeapBlock *
find_heap_block(size_t size)
{
    HeapBlock *new_block = baseHeap;
    while (new_block && !(new_block->is_free && new_block->size <= size)) {
        new_block = new_block->next;
    }

    return new_block;
} 

HeapBlock *
extend_heap(HeapBlock *last_block, size_t size)
{
    HeapBlock *new_block = ssbrk(0);

    if (ssbrk(META_DATA_SIZE + size) == (void*)-1)
        return NULL;

    new_block->validation_flag = VALIDATION_FLAG;
    new_block->size = size;
    new_block->is_free = 1;
    new_block->next = NULL;
    new_block->prev = last_block;

    if (last_block) 
        last_block->next = new_block;

    return new_block; 
}

void
split_heap_block(HeapBlock *block, size_t size)
{
    HeapBlock *new_block;

    new_block = (HeapBlock*)((char*)block + META_DATA_SIZE + size);

    new_block->size = block->size - size - META_DATA_SIZE;
    new_block->is_free = 1;
    new_block->next = block->next;
    new_block->prev = block;

    block->size = size;
    block->next = new_block;
}

void
free(void *ptr)
{
    if (ptr == NULL) 
        return;

    if (!validate_heap_pointer(ptr))
        return;

    HeapBlock *block;

    block = (HeapBlock*)((char*)ptr - META_DATA_SIZE);
    block->is_free = 1;

    // check for previous free block
    if (block->prev && block->prev->is_free)
        block = unite_with_next_heap_block(block->prev);
    // check for next free block
    if (block->next && block->next->is_free) {
        block = unite_with_next_heap_block(block); 
    // check if current block is last one
    } else if (block->next == NULL) {
        if (block->prev)
            block->prev->next = NULL;
        else
            baseHeap = NULL;
        bbrk(block);
    }
}

int
validate_heap_pointer(void *ptr)
{
    HeapBlock *block = (HeapBlock*)((char*)ptr - META_DATA_SIZE);
    
    return block->validation_flag == VALIDATION_FLAG;
}

/*
 * Unite heap block with next one
 */
HeapBlock *
unite_with_next_heap_block(HeapBlock *block)
{
    block->size = block->size + META_DATA_SIZE + block->next->size;
    block->next = block->next->next;
    
    if (block->next) 
        block->next->prev = block;

    return block;
}
