use crate::{
    multi_window::NewWindowRequest,
    tracked_window::{TrackedWindow, TrackedWindowResponse},
};
use egui_glow::EguiGlow;
use glutin::PossiblyCurrent;

pub struct PopupWindow {
    pub input: String,
}

impl PopupWindow {
    pub fn new(label: String) -> NewWindowRequest {
        NewWindowRequest {
            window_state: PopupWindow {
                input: label.clone(),
            }
            .into(),
            builder: glutin::window::WindowBuilder::new()
                .with_resizable(false)
                .with_inner_size(glutin::dpi::LogicalSize {
                    width: 400.0,
                    height: 200.0,
                })
                .with_title(label),
        }
    }
}

impl TrackedWindow for PopupWindow {
    fn redraw(
        &mut self,
        egui: &mut EguiGlow,
        _gl_window: &mut glutin::WindowedContext<PossiblyCurrent>,
    ) -> TrackedWindowResponse {
        let mut quit = false;

        egui::CentralPanel::default().show(&egui.egui_ctx, |ui| {
            if ui.button("Increment").clicked() {
                //TODO
            }
            let response = ui.add(egui::TextEdit::singleline(&mut self.input));
            if response.changed() {
                // …
            }
            if response.lost_focus() && ui.input().key_pressed(egui::Key::Enter) {
                // …
            }
            if ui.button("Quit").clicked() {
                quit = true;
            }
        });
        TrackedWindowResponse {
            quit: quit,
            new_windows: Vec::new(),
        }
    }
}
