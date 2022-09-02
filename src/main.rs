use egui_multiwin::multi_window::MultiWindow;

mod debug;
mod screens;

use screens::root::{self};

pub struct AppCommon {
    clicks: u32,
}

fn main() {
    let event_loop = glutin::event_loop::EventLoopBuilder::with_user_event().build();
    let mut multi_window = MultiWindow::new();
    let root_window = root::RootWindow::new();

    let ac = AppCommon { clicks: 0 };

    let _e = multi_window.add(root_window, &event_loop);
    multi_window.run(event_loop, ac);
}
