/*
*my-malloc.c
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define HEAP_INCREASE 4096

struct mem_info{
    struct mem_info* next;
    int size;
    int isfree;
};

void* malloc(size_t num_bytes);
void free(void* ptr);
void* calloc(size_t num_elements, size_t size);
void* realloc(void* ptr, size_t size);
int malloc_usable_size(void* ptr);

void* heap_start = NULL;
int space_left = 0;

void* malloc(size_t num_bytes){

    //makes sure the number of bytes being allocated is a multiple of 16
    //allowing for 16 byte allignment
    if (num_bytes % 16 != 0){
        num_bytes += (16 - (num_bytes % 16));
    }

    //check to see if the amount being asked to allocate is
    //more than the standard amount to push the heap
    if ((num_bytes + sizeof(struct mem_info)) > HEAP_INCREASE){
        if(heap_start == NULL){
            if ((heap_start = sbrk(num_bytes + sizeof(struct mem_info))) == (void*) -1){
                return NULL;
            }
        }
        else{
            if ((sbrk(num_bytes + sizeof(struct mem_info))) == (void*) -1){
                return NULL;
            }
        }
        space_left += (num_bytes + sizeof(struct mem_info));
    }

    //if its the first call to malloc
    if (heap_start == NULL){
        if ((heap_start = sbrk(HEAP_INCREASE)) == (void*) -1){
            return NULL;
        }
        space_left += HEAP_INCREASE;

        struct mem_info* allocation = (struct mem_info*) heap_start;
        allocation->next = NULL;
        allocation->size = num_bytes;
        allocation->isfree = 0;
        space_left -= (num_bytes + sizeof(struct mem_info));
        return (void*)((char*) heap_start + sizeof(struct mem_info));
    }

    struct mem_info* current_allocation = (struct mem_info*) heap_start;
    //follow the linked list until next allocation is null or an allocation is free and has space
    while (current_allocation->next != NULL || ((current_allocation->isfree == 1) && (current_allocation->size >= num_bytes))){
        //If the chunk has been freed and has enough space for the new allocation
        if ((current_allocation->isfree == 1) && (current_allocation->size >= num_bytes)){
            int sizedif = current_allocation->size - num_bytes;
            if (sizedif > sizeof(struct mem_info)){
                struct mem_info* new_free_allocation = (struct mem_info*) ((char*) current_allocation + sizeof(struct mem_info) + num_bytes);
                new_free_allocation->next = current_allocation->next;
                new_free_allocation->size = sizedif - sizeof(struct mem_info);
                new_free_allocation->isfree = 1;
                
                current_allocation->next = new_free_allocation;
                current_allocation->size = num_bytes;
            }
            else{
                current_allocation->size = num_bytes + sizedif;
            }
            current_allocation->isfree = 0;
            return ((char*) current_allocation + sizeof(struct mem_info));
        }
        current_allocation = current_allocation->next;
    }
    if (space_left < (num_bytes + sizeof(struct mem_info))){
        if ((sbrk(HEAP_INCREASE)) == (void*) -1){
            return NULL;
        }
        space_left += HEAP_INCREASE;
    }
    struct mem_info* new_allocation = (struct mem_info*) ((char*)current_allocation + current_allocation->size + sizeof(struct mem_info));
    new_allocation->next = NULL;
    new_allocation->size = num_bytes;
    new_allocation->isfree = 0;
    current_allocation->next = new_allocation;
    space_left -= (num_bytes + sizeof(struct mem_info));
    return (current_allocation->next + 1);
    
}

void free(void* ptr){
    if(ptr != NULL) {
        struct mem_info* current_struct = ((struct mem_info*) ptr - 1);
        current_struct->isfree = 1;
    }
}

void* calloc(size_t num_elements, size_t size){
    if (num_elements == 0 || size == 0){
        return NULL;
    }

    int product = num_elements * size;

    if (product / num_elements != size){
        return NULL;
    }

    void* ptr;
    if ((ptr = malloc(product)) == NULL){
        return NULL;
    }
    memset(ptr, 0, product);

    return ptr;
}

void* realloc(void* ptr, size_t bytes){
    if (bytes % 16 != 0){
        bytes += (16 - (bytes % 16));
    }

    if (ptr == NULL){
        return malloc(bytes);
    }

    if (bytes == 0){
        free(ptr);
        return NULL;
    }

    struct mem_info* current_struct = ((struct mem_info*) ptr - 1);

    //if the sizes are equal, we do nothing
    if (current_struct->size == bytes){
        return ptr;
    }

    //case where the new size is greater, so we have to malloc a new space and make the old one free
    if(current_struct->size < bytes){
        void* new_ptr;
        if ((new_ptr = malloc(bytes)) == NULL){
            return NULL;
        }
        memcpy(new_ptr, ptr, current_struct->size);
        free(ptr);
        return new_ptr;
    }

    //case where the new size is only 16 bytes smaller and 
    //couldn't fit a new allocaition in the new space so we do nothing
    if (current_struct->size - bytes <= sizeof(struct mem_info)){
        return ptr;
    }

    //case where the new allocation is small enough to fit a new free allocation above, 
    //so we shrink the allocation and add a new free allocation above
    else{
        struct mem_info* new_free_ptr = (struct mem_info*) ((char*) current_struct + bytes + sizeof(struct mem_info));
        new_free_ptr->next = current_struct->next;
        new_free_ptr->size = current_struct->size - bytes - sizeof(struct mem_info);
        new_free_ptr->isfree = 1;

        current_struct->next = new_free_ptr;
        current_struct->size = bytes;
        return (current_struct + 1);
    }
}

int malloc_usable_size(void* ptr){
    if (ptr == NULL){
        return 0;
    }

    struct mem_info* current_struct = ((struct mem_info*) ptr - 1);
    return current_struct->size;
}


