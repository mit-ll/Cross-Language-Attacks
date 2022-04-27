#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

// Simple function that acts user input
extern int64_t get_attack();

// Simple initialization function
void init() {
    // Turns off heap checks for double frees 
    // Set to lowest level which just prints out the error and continues
    // Not strictly necessary, but helps with presentation
    // I.e., prints when we achieved a double free
    mallopt(M_CHECK_ACTION, 1);
}

// Given the array to modify, this function set a field in the array  
// Can cause an OOB vulnerability
void user_given_array(int64_t array_ptr_addr) {
    // These values could be set by a corruptible source, e.g., user input
    // Thus, the index points to Data.cb and value is the address of attack() 
    // This is an OOB as it indexes past the allocated array of size 3)
    int64_t array_index = 3;
    int64_t array_value = get_attack(); 

    int64_t* a = (void *)array_ptr_addr;
    printf("addr of a[array_index] in user_given_array: %ld\n", (int64_t)&(a[array_index]));

    a[array_index] = array_value;
    printf("Done with user_given_array.\n");
}

// This function prints the address of a given array 
// Can cause UaF and DF vulnerabilities
void print_array_addr(int64_t array_ptr_addr) {
    int64_t* a = (void *)array_ptr_addr;
    printf("addr of a in print_array_addr: %ld\n", (int64_t)a);

    // This is an unnecessary free call, as Go allocated the array 
    // (and subsequently Go will free this array later) 
    //free(a);

    // C now thinks it can use a for something else 
    // (e.g., set it to a user defined address)
    // Go may not realize this functionality occurs
    // These values could be set by a corruptible source, e.g., user input
    int64_t array_value = get_attack(); 
    *a = array_value;

    printf("Done with print_array_addr.\n");
}


// This function allocates its own array and populates based on user input
void user_set_array() {

    // Initialize array
    int64_t a[1] = { 0 };

    // These values could be set by a corruptible source, e.g., user input
    // Thus, the index points to Data.cb and value is the address of attack() 
    // This is an OOB as it indexes past the allocated array of size 3)
    // Note: the value of array_index only works 50% of the time
    // It depends on what memory address the stack gets 
    // (i.e., stack location is not deterministic in Go) 
    // Thus, we corrupt two likely canidates  

    int64_t array_index = (((int64_t)get_attack() + 824628677912) - (int64_t)&a)/8; 
    int64_t array_index2 = (((int64_t)get_attack() + 824628698392) - (int64_t)&a)/8; 

    int64_t array_value = get_attack(); 

    printf("addr of &a: %ld\n", (int64_t)&a);
    printf("array_value: %ld\n", array_value);
    printf("addr of a[array_index] in user_given_array: %ld\n", (int64_t)&(a[array_index]));
    printf("addr of a[array_index2] in user_given_array: %ld\n", (int64_t)&(a[array_index2]));

    a[array_index] = array_value;
    a[array_index2] = array_value;
    printf("Done with user_set_array.\n");
}

// Go calls this function to get the right address of a call back function
// If Go doesn't properly sanitize data from this function, 
// it could return corrupted data
int64_t get_cb_from_c() {
    // These values could be set by a corruptible source, e.g., user input
    int64_t call_back_addr = get_attack(); 

    return call_back_addr;
}

// Given the array to modify, this function set a field in the array  
// Can cause an OOB vulnerability
void user_given_slice(int64_t slice_ptr_addr) {
    // These values could be set by a corruptible source, e.g., user input
    // Thus, the index points to the slice fat pointer and value too large 
    // This is an OOB as it indexes past the allocated array of size 3)
    int64_t array_index = 1;
    int64_t array_value = 10000000; 

    int64_t* a = (void *)slice_ptr_addr;
    printf("addr of a[array_index] in user_given_slice: %ld\n", (int64_t)&(a[array_index]));

    a[array_index] = array_value;
    printf("Done with user_given_slice.\n");
}
