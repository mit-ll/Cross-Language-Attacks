/* External unsafe functions */

extern "C" { fn init(); }
extern "C" { fn user_set_array(); }
extern "C" { fn user_given_array(array_ptr_addr: i64); }
extern "C" { fn user_given_vec(vec_ptr_addr: i64); }
extern "C" { fn print_array_addr(array_ptr_addr: i64); }
extern "C" { fn get_cb_from_c() -> i64; }

// A simple function that acts as user input
#[no_mangle]
extern "C" fn get_attack() -> i64 {
    return attack as i64;
}

pub const MAX_LENGTH: usize = 3;

// A simple struct that we frequently manipulate
pub struct Data {
    vals: [i64;MAX_LENGTH],
    cb: fn(&mut i64),
    vecs: std::vec::Vec<i64>,
    cb2: fn(&mut i64)
}

// A simple benign function that doubles a value
#[no_mangle]
#[inline(never)]
pub fn doubler(x: &mut i64) {
    println!("Not attacked! Adding two to input...");
    *x += 2;
}

// A simple benign function that increments a value
#[no_mangle]
#[inline(never)]
pub fn incrementer(x: &mut i64) {
    println!("Not attacked! Adding one to input...");
    *x += 1;
}

// Attack aims to call this
// Could be replaced with actual gadgets that together execute a weird machine
#[no_mangle]
#[inline(never)]
pub fn attack() {
    println!("We were attacked!");
}

// Main function
#[no_mangle]
#[inline(never)]
fn analyze_data(cb_fptr: fn(&mut i64)) {

    // Initialize program
    unsafe{init()};
    
    // Set up some function pointers
    let fp1 = incrementer;
    let fp2 = doubler;

    // Initialize some data 
    let mut data = Data {
        vals: [1,2,3],
        cb: fp1,
        vecs: vec![4,5],
        cb2: fp2
    };
    println!("Start data: vals[0]={}, cb={}, vecs[0]={}, cb2={}", 
             data.vals[0], 
             data.cb as *const fn(&mut i64) as i64, 
             data.vecs[0], 
             data.cb2 as *const fn(&mut i64) as i64);

    // Get and print the addresses of the Data Struct
    let data_vals_addr = &data.vals as *const i64 as i64;
    let data_cb_addr = &data.cb as *const fn(&mut i64) as i64;
    let data_vecs_addr = &data.vecs as *const std::vec::Vec<i64> as i64;
    let data_cb2_addr = &data.cb2 as *const fn(&mut i64) as i64;

    println!("data_vals_addr: {}", data_vals_addr);
    println!("data_cb_addr: {}", data_cb_addr);
    println!("data_vecs_addr: {}", data_vecs_addr);
    println!("data_cb2_addr: {}", data_cb2_addr);

    // Get and print the address of the function argument to this function 
    let cb_fptr_addr = &cb_fptr as *const fn(&mut i64) as i64;
    println!("cb_fptr_addr: {}", cb_fptr_addr);

    // Get and print the address of heap data that a Box stores
    let doubler_fp: Box<fn(&mut i64)> = Box::new(doubler);
    let doubler_fp_addr = &(*doubler_fp) as *const fn(&mut i64) as i64;
    println!("doubler_fp_addr: {}", doubler_fp_addr);

    // Get and print the address of heap data that a Box stores
    let doubler2_fp: Box<fn(&mut i64)> = Box::new(doubler);
    let doubler2_fp_addr = &(*doubler2_fp) as *const fn(&mut i64) as i64;
    println!("doubler2_fp_addr: {}", doubler2_fp_addr);

    // Get a callback function pointer from C
    // Uses unsafe because it needs to parse data from C 
    // since this is used as an intended interaction
    let incrementer_fp = unsafe { 
        let c_addr: i64 = get_cb_from_c();
        let ptr = c_addr as *const fn(&mut i64);
        let fp: fn(&mut i64) = std::mem::transmute::<*const fn(&mut i64), fn(&mut i64)>(ptr);
        fp
    }; 

    // Section 4 Attacks
    /* Rust Bounds Check Bypass Attack */
    println!("Launching Rust Bounds Check Bypass Attack...");
    unsafe{ user_given_array(data_vals_addr) }

    println!("Calling data.cb...");
    (data.cb)(&mut data.vals[0]);
    println!("Updated data: vals[0]={}", data.vals[0]);

    /* Rust Lifetime Bypass Attack */
    println!("Launching Rust Lifetimes Bypass Attack...");
    unsafe{ print_array_addr(doubler_fp_addr) }

    println!("Calling doubler_fp...");
    doubler_fp(&mut data.vals[0]);
    println!("Updated data: vals[0]={}", data.vals[0]);

    /* C/C++ Hardening Bypass Attack */
    println!("Launching C/C++ Hardening Bypass Attack...");
    unsafe{ user_set_array() }

    println!("Calling cb_fptr...");
    cb_fptr(&mut data.vals[0]);
    println!("Updated data: vals[0]={}", data.vals[0]);

    // Section 5 Attacks
    /* Corrupting Rust Dynamic Bounds */
    println!("Launching Dynamic Rust Bounds Check Bypass Attack...");
    unsafe{ user_given_vec(data_vecs_addr) }

    // Now we can access past the length of data.vecs in *Safe Rust*
    // Length of vec is only 2 (and capacity is 2)
    // E.g., data.vec[22] actually points to doubler2_fp on the heap 
    // So setting data.vec[22] actually corrupts the value a pointer holds
    // Moreover, vec_index and vec_val could come from a corruptible source, e.g., user input

    let data_vecs0_addr = &data.vecs[0] as *const i64 as i64;
    let vec_index = ((doubler2_fp_addr - data_vecs0_addr)/8) as usize; 
    let vec_val = get_attack();
    
    println!("addr of data.vecs[0]: {}", &data.vecs[0] as *const i64 as i64);
    println!("addr of data.vecs[vec_index]: {}", &data.vecs[vec_index] as *const i64 as i64);

    /* This OOB is done in Safe Rust! */
    data.vecs[vec_index] = vec_val;

    println!("Calling doubler2_fp...");
    doubler2_fp(&mut data.vals[0]);
    println!("Updated data: vals[0]={}", data.vals[0]);

    /* Corrupting Intended Interactions */
    println!("Launching Intended Interactions Attack...");
    println!("Calling incrementer_fp...");
    incrementer_fp(&mut data.vals[0]);
    println!("Updated data: vals[0]={}", data.vals[0]);

    /* Corrupting with Serialization Errors */
    // TODO

    /* Corrupting vTable dynamic dispatch */
    // TODO

    /* Corrupting with Double Frees */
    // Rust will now free doubler_fp as it goes out of scope here, 
    // but it was already freed in print_array_addr
    // This will cause an abort, but could be used to execute a weird machine
}
 
fn main() {
    // Setup a function pointer
    let fp0 = doubler;

    // Call the main function 
    analyze_data(fp0);

    println!("Finished main.");
}
