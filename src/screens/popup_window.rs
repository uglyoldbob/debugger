use crate::egui_multiwin_dynamic::{
    multi_window::NewWindowRequest,
    tracked_window::{RedrawResponse, TrackedWindow},
};
use egui_multiwin::egui_glow::EguiGlow;

use crate::AppCommon;

pub struct PopupWindow {
    pub input: String,
}

impl PopupWindow {
    pub fn new(label: String) -> NewWindowRequest {
        NewWindowRequest::new(PopupWindow {
            input: label.clone(),
        }.into(), egui_multiwin::winit::window::WindowBuilder::new()
        .with_resizable(false)
        .with_inner_size(egui_multiwin::winit::dpi::LogicalSize {
            width: 400.0,
            height: 200.0,
        })
        .with_title(label), egui_multiwin::tracked_window::TrackedWindowOptions {
            vsync: false,
            shader: None,
        }, egui_multiwin::multi_window::new_id())
    }
}

impl TrackedWindow for PopupWindow {
    fn redraw( &mut self,
        c: &mut AppCommon,
        egui: &mut EguiGlow,
        window: &egui_multiwin::winit::window::Window,
        _clipboard: &mut egui_multiwin::arboard::Clipboard,
    ) -> RedrawResponse {
        let mut quit = false;

        egui_multiwin::egui::CentralPanel::default().show(&egui.egui_ctx, |ui| {
            if ui.button("Increment").clicked() {
                c.clicks += 1;
            }
            let response = ui.add(egui_multiwin::egui::TextEdit::singleline(&mut self.input));
            if response.changed() {
                // …
            }
            if response.lost_focus() && ui.input(|i| i.key_pressed(egui_multiwin::egui::Key::Enter)) {
                // …
            }
            if ui.button("Quit").clicked() {
                quit = true;
            }
        });
        RedrawResponse {
            quit: quit,
            new_windows: Vec::new(),
        }
    }
}
