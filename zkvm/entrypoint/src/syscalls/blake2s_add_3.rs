#[cfg(target_os = "zkvm")]
use core::arch::asm;

#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_blake2s_add_3(left: *mut u32, right: *const u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
        "ecall",
        in("t0") crate::syscalls::BLAKE_2S_ADD_3,
        in("a0") left,
        in("a1") right
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
