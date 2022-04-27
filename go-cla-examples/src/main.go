package main

/*
#include "./init/init.h"
#include <stdint.h>       // for C.int64_t
#include <stdlib.h>       // for free()
#cgo LDFLAGS: -L./init/ -linit
*/
import "C"

import (
	"fmt"
	"unsafe"
)

var fa_attack = attack

const MAX_LENGTH = 3

//export get_attack
func get_attack() C.int64_t {

	// Get a pointer to the address of the function pointer
	p := unsafe.Pointer(&fa_attack)

	// Pull out the address of a function pointer from the pointer to the address of the function pointer
	p_addr := C.int64_t(uintptr(p))

	return p_addr
}

type Data struct {
	vals  [MAX_LENGTH]int64
	cb    *func(*int64)
	slice []int64
	cb2   *func(*int64)
}

// A simple benign function that doubles a value
//go:noinline
func doubler(x *int64) {
	fmt.Println("Not attacked! Adding two to the input...")
	*x = *x + 2
}

// A simple benign function that increments a value
//go:noinline
func incrementer(x *int64) {
	fmt.Println("Not attacked! Adding one to the input...")
	*x = *x + 1
}

// Attack aims to call this
// Could be replaced with actual gadgets that together execute a weird machine
//go:noinline
func attack() {
	fmt.Println("We were attacked!")
}

// Main function
//go:noinline
func analyze_data(cb_fptr *func(*int64)) {

	// Initialize program
	C.init()

	// Set up some function pointers
	fa1 := incrementer
	fp1 := (*func(*int64))(&fa1)
	fa2 := doubler
	fp2 := (*func(*int64))(&fa2)

	// Initialize some data
	data := Data{
		vals:  [3]int64{1, 2, 3},
		cb:    fp1,
		slice: []int64{4, 5},
		cb2:   fp2,
	}
	fmt.Println("Start data: vals[0]=", data.vals[0], "cb=", data.cb, "slice[0]=", data.slice[0], "cb2=", data.cb2)

	// Get and print the addresses of the Data struct
	data_vals_addr := C.int64_t(uintptr(unsafe.Pointer(&data.vals)))
	data_cb_addr := C.int64_t(uintptr(unsafe.Pointer(&data.cb)))
	data_slice_addr := C.int64_t(uintptr(unsafe.Pointer(&data.slice)))
	data_cb2_addr := C.int64_t(uintptr(unsafe.Pointer(&data.cb2)))

	fmt.Println("data_vals_addr", data_vals_addr)
	fmt.Println("data_cb_addr", data_cb_addr)
	fmt.Println("data_slice_addr", data_slice_addr)
	fmt.Println("data_cb2_addr", data_cb2_addr)

	// Get and print the address of the function argument to this function
	cb_fptr_addr := C.int64_t(uintptr(unsafe.Pointer(&cb_fptr)))
	fmt.Println("cb_fptr_addr", cb_fptr_addr)

	// Get and print the address of heap data that a new stores
	doubler_fp := new(func(*int64))
	doubler_fp = fp2
	doubler_fp_addr := C.int64_t(uintptr(unsafe.Pointer(&doubler_fp)))
	fmt.Println("doubler_fp_addr", doubler_fp_addr)

	// Get and print the address of heap data that a new stores
	doubler2_fp := new(func(*int64))
	doubler2_fp = fp2
	doubler2_fp_addr := C.int64_t(uintptr(unsafe.Pointer(&doubler2_fp)))
	fmt.Println("doubler2_fp_addr", doubler2_fp_addr)

	// Get a callback function pointer from C
	incrementer_fp_addr := C.get_cb_from_c()
	// Derive a function pointer from the address of a pointer to a function pointer
	incrementer_fp := (*func(*int64))(unsafe.Pointer(uintptr(incrementer_fp_addr)))

	// Section 4 Attacks
	/* Go Static Bounds Check Bypass Attack */
	fmt.Println("Launching Go Bounds Check Bypass Attack...")
	C.user_given_array(data_vals_addr)

	fmt.Println("Calling data.cb...")
	(*data.cb)(&data.vals[0])
	fmt.Println("Updated data: vals[0]=", data.vals[0])

	/* Go Garbage Collection Bypass Attack */
	fmt.Println("Launching Go Garbage Collection Bypass Attack...")
	C.print_array_addr(doubler_fp_addr)

	fmt.Println("Calling doubler_fp...")
	(*doubler_fp)(&data.vals[0])
	fmt.Println("Updated data: vals[0]=", data.vals[0])

	/* C/C++ Hardening Bypass Attack */
	fmt.Println("Launching C/C++ Hardening Bypass Attack...")
	C.user_set_array()

	fmt.Println("Calling cb_fptr...")
	(*cb_fptr)(&data.vals[0])
	fmt.Println("Updated data: vals[0]=", data.vals[0])

	// Section 5 Attacks
	/* Corrupting Go Dynamic Bounds */
	fmt.Println("Launching Go Dynaic Bounds Check Bypass Attack...")
	C.user_given_slice(data_slice_addr)

	// Now we can access past the length of data.slice in *Safe Go*
	// Length of slice is only 2 (and capacity is 2)
	// E.g., data.slice[22] actually points to doubler2_fp on the heap
	// So setting data.slice[22] actually corrupts the value a pointer holds
	// Moreover, slice_index and slice_val could come from a corruptible source, e.g., user input
	data_slice0_addr := C.int64_t(uintptr(unsafe.Pointer(&data.slice[0])))
	slice_index := (doubler2_fp_addr - data_slice0_addr) / 8

	if slice_index > 0 {
		data_slice_I_addr := C.int64_t(uintptr(unsafe.Pointer(&data.slice[slice_index])))

		fmt.Println("addr of data.slice[0]:", data_slice0_addr)
		fmt.Println("addr of data.slice[slice_index]:", data_slice_I_addr)

		slice_val := int64(get_attack())

		/* This OOB is done in Safe Go! */
		data.slice[slice_index] = slice_val

	} else {
		// ASLR placed doubler2_fp "below" data.slice in the heap
		// But, we can't access a slice with a negative value
		fmt.Println("ASLR protected us! Better luck next time attacker...")
	}

	fmt.Println("Calling doubler2_fp...")
	(*doubler2_fp)(&data.vals[0])
	fmt.Println("Updated data: vals[0]=", data.vals[0])

	/* Corrupting Intended Interactions */
	fmt.Println("Launching Intended Interactions Attack...")

	fmt.Println("Calling incrementer_fp...")
	(*incrementer_fp)(&data.vals[0])
	fmt.Println("Updated data: vals[0]=", data.vals[0])

	/* Corrupting with Double Frees */
	// Unsure exactly when, but Go will try to free doubler_fp
	// but it was already freed in print_array_addr
	// This will cause an abort, but could be used to execute a weird machine
}

func main() {
	// Set up a function pointer
	fa0 := incrementer
	fp0 := (*func(*int64))(&fa0)

	// Call the main function
	analyze_data(fp0)

	fmt.Println("Finished main.")
}
