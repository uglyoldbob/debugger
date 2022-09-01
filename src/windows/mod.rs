use crate::tracked_window::{TrackedWindow, TrackedWindowControl, TrackedWindowResponse};
use egui_glow::EguiGlow;
use glutin::PossiblyCurrent;

pub mod popup_window;
pub mod root;

#[enum_dispatch(TrackedWindow)]
pub enum MyWindows {
    Root(root::RootWindow),
    Popup(popup_window::PopupWindow),
}
