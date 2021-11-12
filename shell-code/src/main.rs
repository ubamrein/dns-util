#![no_std]
#![no_main]
#![feature(asm)]

#[panic_handler]
fn panic(_:&core::panic::PanicInfo) -> ! {
    loop {}
}

const SYS_WRITE: u64 = 0x2000004;
const SYS_EXIT: u64 = 0x2000001;
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
        "lea rsi, [rsp]",
        "mov rdi, 1",
        "mov rdx, 14",
        "syscall",
        in("rax") syscall,
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

        asm!(
            "xor rbx, rbx",
            "push rbx",
            "mov rax, 0x0a21646c72",
            "push rax",
            "mov rax, 0x6f77206f6c6c6548",
            "push rax",
            options(nostack),
        );
        syscall3(
            SYS_WRITE,
            STDOUT,
            14,
        );
        asm!(
            "pop rax",
            "pop rax",
            "pop rax",
            options(nostack),
        );
    };
}