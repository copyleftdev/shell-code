extern crate libc;

use std::ptr;

unsafe fn inject_shellcode(shellcode: &[u8]) {
    let shellcode_ptr = libc::mmap(ptr::null_mut(), shellcode.len(), libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0);
    ptr::copy_nonoverlapping(shellcode.as_ptr(), shellcode_ptr as *mut u8, shellcode.len());
    let shellcode_fn: extern "C" fn() = std::mem::transmute(shellcode_ptr);
    shellcode_fn();
}

fn main() {
    let shellcode: &[u8] = &[0x90, 0x90, 0x90]; // NOP sled as example
    unsafe {
        inject_shellcode(shellcode);
    }
}
