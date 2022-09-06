#[cfg(target_os = "windows")]
pub mod debug_windows;

#[cfg(target_os = "windows")]
pub use debug_windows::*;

pub trait Debugger {
    type Registers;
    type ThreadId;

    fn get_registers(&mut self, id: Self::ThreadId) -> Option<&Self::Registers>;
    fn set_registers(&mut self, id: Self::ThreadId, r: &Self::Registers);
    fn get_main_thread(&mut self) -> Self::ThreadId;
    fn get_extra_threads(&mut self) -> Vec<Self::ThreadId>;
    fn get_all_threads(&mut self) -> Vec<Self::ThreadId> {
        let mut vd = Vec::<Self::ThreadId>::new();
        vd.push(self.get_main_thread());
        let mut others = self.get_extra_threads();
        vd.append(&mut others);
        vd
    }
}
