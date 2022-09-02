#[cfg(target_os = "windows")]
pub mod debug_windows;
#[cfg(target_os = "windows")]
pub use debug_windows::*;

pub enum MessageToDebugger {
    Pause,
}

pub enum MessageFromDebugger {
    Paused,
}

pub struct DebuggerChannels {
    pub rcvr: std::sync::mpsc::Receiver<MessageFromDebugger>,
    pub sndr: std::sync::mpsc::Sender<MessageToDebugger>,
}
