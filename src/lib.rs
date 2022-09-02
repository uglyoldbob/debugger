#[no_mangle]
pub extern "C" fn do_stuff() {}

#[no_mangle]
extern "system" fn DllMain(_: *const u8, _: u32, _: *const u8) -> u32 {
    println!("I am groot from hook.dll");
    42
}
