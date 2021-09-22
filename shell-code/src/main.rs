#![no_std]
#![no_main]
#![feature(asm)]

#[panic_handler]
fn panic(_:&core::panic::PanicInfo) -> ! {
    loop {}
}

const SYS_WRITE: u64 = 1;
const SYS_EXIT: u64 = 60;
const STDOUT: u64 = 1;

static MESSAGE: &str = "hello world\n";

unsafe fn syscall1(syscall: u64, arg1: u64) -> u64 {
    let ret: u64;
    asm!(
        "syscall",
        in("rax") syscall,
        in("rdi") arg1,
        out("rcx") _,
        out("r11") _,
        lateout("rax") ret,
        options(nostack),
    );
    ret
}

unsafe fn syscall3(syscall: u64, arg1: u64, arg3: u64) -> u64 {
    let ret: u64;
    asm!(
        "syscall",
        in("rax") syscall,
        in("rdi") arg1,
        in("rdx") arg3,
        out("rcx") _,
        out("r11") _,
        lateout("rax") ret,
        options(nostack),
    );
    ret
}


#[no_mangle]
fn main() {
    unsafe {
        let msg = "hello, world\n";
        asm!(
            "xor {} {}",
            "push {}",
            inout("rbx") _
        );
        syscall3(
            SYS_WRITE,
            STDOUT,
            msg.len() as u64,
        );

        syscall1(SYS_EXIT, 0)
    };
}