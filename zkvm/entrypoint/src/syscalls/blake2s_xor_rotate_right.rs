#[cfg(target_os = "zkvm")]
use core::arch::asm;

#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_blake2s_xor_rotate_right(left: *mut u32, right: *const u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
        "ecall",
        in("t0") crate::syscalls::BLAKE_2S_XOR_ROTATE_RIGHT,
        in("a0") left,
        in("a1") right
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
