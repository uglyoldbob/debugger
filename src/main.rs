pub mod multi_window;
pub mod tracked_window;
pub mod windows;

#[macro_use]
extern crate enum_dispatch;

use multi_window::MultiWindow;

use windows::{
    popup_window,
    root::{self},
};

fn main() {
    let event_loop = glutin::event_loop::EventLoopBuilder::with_user_event().build();
    let mut multi_window = MultiWindow::new();
    let root_window = root::RootWindow::new();
    let root_window2 = popup_window::PopupWindow::new("initial popup".to_string());

    let _e = multi_window.add(root_window, &event_loop);
    let _e = multi_window.add(root_window2, &event_loop);
    MultiWindow::run(multi_window, event_loop);
}
