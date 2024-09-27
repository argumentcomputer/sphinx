#[cfg(target_os = "zkvm")]
use core::arch::asm;

#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_sha512_extend(w: *mut u64, i: u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::SHA512_EXTEND,
            in("a0") w,
            in("a1") i
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
