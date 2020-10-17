use optee_utee::Time;
use optee_utee::{
    trace_println,
};

pub fn print_time() {
    let mut time = Time::new();
    time.ree_time();
    trace_println!("[+] Get REE time {}.", time);
}