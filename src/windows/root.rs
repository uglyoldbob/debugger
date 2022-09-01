use crate::tracked_window::TrackedWindowResponse;
use crate::{
    multi_window::NewWindowRequest, tracked_window::TrackedWindow,
    windows::popup_window::PopupWindow,
};
use egui_glow::EguiGlow;
use glutin::PossiblyCurrent;

pub struct RootWindow {
    pub button_press_count: u32,
    pub num_popups_created: u32,
    root: bool,
}

impl RootWindow {
    pub fn new() -> NewWindowRequest {
        NewWindowRequest {
            window_state: RootWindow {
                button_press_count: 0,
                num_popups_created: 0,
                root: true,
            }
            .into(),
            builder: glutin::window::WindowBuilder::new()
                .with_resizable(true)
                .with_inner_size(glutin::dpi::LogicalSize {
                    width: 800.0,
                    height: 600.0,
                })
                .with_title("egui-multiwin root window"),
        }
    }
}

impl TrackedWindow for RootWindow {
    fn is_root(&self) -> bool {
        self.root
    }

    fn redraw(
        &mut self,
        egui: &mut EguiGlow,
        _gl_window: &mut glutin::WindowedContext<PossiblyCurrent>,
    ) -> TrackedWindowResponse {
        let mut quit = false;

        let mut windows_to_create = Vec::new();

        egui::SidePanel::left("my_side_panel").show(&egui.egui_ctx, |ui| {
            ui.heading("Hello World!");
            if ui.button("New popup").clicked() {
                windows_to_create.push(PopupWindow::new(format!(
                    "popup window #{}",
                    self.num_popups_created
                )));
                self.num_popups_created += 1;
            }
            if ui.button("Quit").clicked() {
                quit = true;
            }
        });
        egui::CentralPanel::default().show(&egui.egui_ctx, |ui| {
            ui.heading(format!("number {}", self.button_press_count));

            /*
            for window in other_windows {
                match window {
                    MyWindows::Popup(popup_window) => {
                        ui.add(egui::TextEdit::singleline(&mut popup_window.input));
                    }
                    _ => (),
                }
            }*/
        });
        TrackedWindowResponse {
            quit: quit,
            new_windows: windows_to_create,
        }
    }
}
