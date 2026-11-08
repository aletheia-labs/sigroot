#![cfg_attr(target_os = "none", no_std, no_main)]

use sigroot_core as _;
use sigroot_eth as _;
use sigroot_hd as _;

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
	#[allow(clippy::empty_loop)]
	loop {}
}

#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
extern "C" fn _start() -> ! {
	#[allow(clippy::empty_loop)]
	loop {}
}

#[cfg(not(target_os = "none"))]
fn main() {}
