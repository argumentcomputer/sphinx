#[cfg(target_os = "zkvm")]
use core::arch::asm;

#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_sha512_compress(w: *mut u64, state: *mut u64) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::SHA512_COMPRESS,
            in("a0") w,
            in("a1") state,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
