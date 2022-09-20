#[cfg(target_os = "windows")]
pub mod debug_windows;

#[cfg(target_os = "windows")]
pub use debug_windows::*;

#[derive(Copy, Clone)]
pub enum Exception {
    Unknown,
    Code(i32),
}

#[derive(Copy, Clone)]
pub enum ReasonToPause {
    ProcessStart,
    ProcessEnd,
    ThreadStart,
    ThreadEnd,
    LibraryLoad,
    LibraryUnload,
    Exception,
    Unknown,
}

#[derive(Copy, Clone)]
pub enum DebuggerState {
    Paused(ReasonToPause),
    Running,
}

pub struct MemoryRange {
    pub begin: usize,
    pub length: usize,
    pub flags: u8,
}

impl MemoryRange {
    pub fn contains(&self, adr: usize) -> bool {
        adr >= self.begin && adr < (self.begin + self.length)
    }
    pub fn contiguous(&self, adr: usize, flags: u8) -> bool {
        self.flags == flags && adr == (self.begin + self.length)
    }
    pub fn add_page(&mut self, adr: usize, flags: u8, size: usize) {
        if self.contiguous(adr, flags) {
            self.length += size;
        }
    }
}

pub trait Debugger {
    type Registers;
    type ThreadId;

    /// This resumes all threads that are not configured for suspension.
    fn resume_all_threads(&mut self);
    fn process_debugger(&mut self);
    fn get_registers(&mut self, id: Self::ThreadId) -> Option<&Self::Registers>;
    fn set_registers(&mut self, id: Self::ThreadId, r: &Self::Registers);
    fn get_main_thread(&mut self) -> Option<Self::ThreadId>;
    fn get_extra_threads(&mut self) -> Vec<Self::ThreadId>;
    fn get_all_threads(&mut self) -> Vec<Self::ThreadId> {
        let mut vd = Vec::<Self::ThreadId>::new();
        if let Some(t) = self.get_main_thread() {
            vd.push(t);
        }
        let mut others = self.get_extra_threads();
        vd.append(&mut others);
        vd
    }
    fn get_state(&mut self) -> DebuggerState;
    fn get_exception(&mut self) -> Exception;
    fn get_thread_focus(&mut self) -> Option<Self::ThreadId>;

    fn get_memory_ranges(&mut self) -> Option<&Vec<MemoryRange>>;
}
