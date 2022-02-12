/*
* Malloc implementation with simple list of blocks
* with metadata information.
* Using system calls brk() and sbrk() is ineficcient 
* for size bigger than page(4096), so max size is 4096
* First fit algo while search place and resize(unite) 
* blocks when free
*/

/*
* TODO:
*   - count memory bytes
*   - check blocks when unite them
*/

#include <stdio.h>
#include <malloc.h>
#include <unistd.h>

// Closest and biggest for align 32 bits(4 bytes)
#define ALIGN4(x) (((((x)-1)>>2)<<2)+4)

#define MAX_MEMORY_ALLOCATION 4096

static size_t META_DATA_SIZE = 24;

/*
* HeapBlock + size(MetaData) = pointer to the heap field
*/
typedef struct MetaData HeapBlock;

struct MetaData {
    size_t size;
    int is_free;
    HeapBlock *next;
    HeapBlock *prev;
};

/************* Global scope ***************/

// To count allocated memory
static size_t memoryUsage;
// Point to the heap base
static HeapBlock *baseHeap = NULL;

/************* Malloc help funcs ***************/

static HeapBlock *find_heap_block(HeapBlock *last_block, size_t size);

static void split_heap_block(HeapBlock *block, size_t size);

static HeapBlock *extend_heap(HeapBlock *last_bloc, size_t size);

/************* Free help funcs ***************/

static int validate_heap_pointer(void *ptr);

static HeapBlock *unite_heap_block(HeapBlock *block);

int main() {
    void *p = sbrk(0);
    printf("ALigned size is %zu\n", ALIGN4(9));
    printf("Start of testing malloc break is in %p\n", sbrk(0));
    void *pt1 = malloc(2);
    printf("Adress of base heap is %p\n", baseHeap);
    malloc(6);
    printf("Adress of break is %p\n", sbrk(0));
    malloc(6);
    printf("Adress of break is %p\n", sbrk(0));
    malloc(6);
    printf("Adress of break is %p\n", sbrk(0));
    malloc(6);
    printf("Adress of break is %p\n", sbrk(0));
    malloc(6);
    printf("Adress of break is %p\n", sbrk(0));
    //printf("Adress of pt1(8) is %p\n", pt1);
    //void *pt2 = malloc(8);
    //printf("Adress of pt2(8) is %p\n", pt2);
    //void *pt4 = malloc(8);
    //printf("Adress of sbrk is %p\n", sbrk(0));
    //printf("Adress of pt4(8) is %p\n", pt4);
    //free(pt4);
    //printf("Adress of sbrk is %p\n", sbrk(0));
    return 0;
} 

void *malloc(size_t size) {
    if (size > MAX_MEMORY_ALLOCATION) 
        return NULL;

    size_t align_size = ALIGN4(size);
    
    HeapBlock *last_block = baseHeap;
    HeapBlock *new_block;

    if (baseHeap != NULL) {
        new_block = find_heap_block(last_block, align_size);

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
        new_block -> is_free = 0;
        if (new_block == NULL) 
            return NULL;
        baseHeap = new_block; 
    } 

    return new_block + META_DATA_SIZE;
}

HeapBlock *find_heap_block(HeapBlock *last_block, size_t size) {
    HeapBlock *new_block = baseHeap;
    while(new_block && !(new_block->is_free && new_block->size <= size)) {
        last_block = new_block;
        new_block = new_block->next;
    }

    return new_block;
} 

HeapBlock *extend_heap(HeapBlock *last_block, size_t size) {
    HeapBlock *new_block = sbrk(0);

    sbrk(32);

    new_block->size = size;
    new_block->is_free = 1;
    new_block->next = NULL;
    new_block->prev = last_block;

    if (last_block) 
        last_block->next = new_block;

    return new_block; 
}

void split_heap_block(HeapBlock *block, size_t size) {
    HeapBlock *new_block;

    new_block = block + META_DATA_SIZE + size;
    new_block->size = block->size - size - META_DATA_SIZE;
    new_block->is_free = 1;
    new_block->next = block->next;
    new_block->prev = block;

    block->size = size;
    block->next = new_block;
}

void free(void *ptr) {
    if (ptr == NULL) 
        return;

    if (!validate_heap_pointer(ptr))
        return;

    HeapBlock *block;

    block = ptr - META_DATA_SIZE;
    block->is_free = 1;
    if (block->prev && block->prev->is_free)
        block = unite_heap_block(block->prev);

/*********CHECK if ITS TRUE**************/
    if (block->next && block->next->is_free) {
        block = unite_heap_block(block); 
    } 
    else {
        // Last block => delete it and release memory(brk)
        if (block->prev) 
            block->prev->next = NULL;
        else 
            baseHeap = NULL;
        brk(block);
    }
}

int validate_heap_pointer(void *ptr){
    return 11;
}
/*
* Unite heap block with next one
*/
HeapBlock *unite_heap_block(HeapBlock *block) {
    block->size = block->size + META_DATA_SIZE + block->next->size;
    block->next = block->next->next;
    
    if (block->next) 
        block->next->prev = block;

    return block;
}
