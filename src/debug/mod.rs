#[cfg(target_os = "windows")]
pub mod debug_windows;
#[cfg(target_os = "windows")]
pub use debug_windows::*;
use static_assertions::const_assert;

const_assert!(std::mem::size_of::<MessageToDebugger>() < 10);
const_assert!(std::mem::size_of::<MessageFromDebugger>() < 10);

pub enum MessageToDebugger {
    Pause,
}

pub enum MessageFromDebugger {
    ProcessStarted,
    Paused,
}

pub struct DebuggerChannels {
    pub rcvr: std::sync::mpsc::Receiver<MessageFromDebugger>,
    pub sndr: std::sync::mpsc::Sender<MessageToDebugger>,
}
