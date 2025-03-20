//! This is a general purpose debugger written in rust.

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

use egui_multiwin_dynamic::multi_window::{MultiWindow, NewWindowRequest};

/// Macro generated code
pub mod egui_multiwin_dynamic {
    egui_multiwin::tracked_window!(
        crate::AppCommon,
        egui_multiwin::NoEvent,
        crate::screens::MyWindows
    );
    egui_multiwin::multi_window!(
        crate::AppCommon,
        egui_multiwin::NoEvent,
        crate::screens::MyWindows
    );
}

mod debug;
mod screens;

use screens::root::{self};

/// Defines the system type when debugging a windows program
pub struct Windows {}

/// Defines the local system type for the debugger
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
type LocalMachine = Windows;

/// The common elements for the debugger, shared among gui windows.
pub struct AppCommon {
    clicks: u32,
    debugger: Option<Box<debug::DebuggedMachine>>,
}

impl AppCommon {
    /// Process events
    fn process_event(&mut self, _event: egui_multiwin::NoEvent) -> Vec<NewWindowRequest> {
        Vec::new()
    }
}

fn main() {
    let event_loop = egui_multiwin::winit::event_loop::EventLoopBuilder::with_user_event().build().unwrap();
    let mut multi_window = MultiWindow::new();
    let root_window = root::RootWindow::new();

    let mut ac = AppCommon {
        clicks: 0,
        debugger: None,
    };

    let _e = multi_window.add(root_window, &mut ac, &event_loop);
    multi_window.run(event_loop, ac);
}
