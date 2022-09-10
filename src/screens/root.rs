use std::marker::PhantomData;

use egui_glow::EguiGlow;
use egui_multiwin::{
    multi_window::NewWindowRequest,
    tracked_window::{RedrawResponse, TrackedWindow},
};

use crate::{debug::ReasonToPause, AppCommon};

use super::popup_window::PopupWindow;

pub struct RootWindow<T> {
    pub button_press_count: u32,
    pub num_popups_created: u32,
    _d: PhantomData<T>,
}

impl RootWindow<crate::Windows> {
    pub fn new() -> NewWindowRequest<AppCommon> {
        NewWindowRequest {
            window_state: Box::new(RootWindow::<crate::Windows> {
                button_press_count: 0,
                num_popups_created: 0,
                _d: PhantomData,
            }),
            builder: glutin::window::WindowBuilder::new()
                .with_resizable(true)
                .with_inner_size(glutin::dpi::LogicalSize {
                    width: 800.0,
                    height: 600.0,
                })
                .with_title("UglyOldBob Debugger"),
        }
    }
}

impl TrackedWindow for RootWindow<crate::Windows> {
    type Data = AppCommon;

    fn is_root(&self) -> bool {
        true
    }

    fn set_root(&mut self, _root: bool) {}

    fn redraw(&mut self, c: &mut AppCommon, egui: &mut EguiGlow) -> RedrawResponse<Self::Data> {
        let mut quit = false;

        let mut windows_to_create = vec![];

        egui.egui_ctx.request_repaint();
        egui::TopBottomPanel::top("menubar").show(&egui.egui_ctx, |ui| {
            if ui.button("📂").clicked() {
                let file = rfd::FileDialog::new()
                    .add_filter("executables", &["exe"])
                    .pick_file();
                if let Some(file) = file {
                    println!("You picked {:?}", file.display());
                    c.debugger = Some(crate::debug::DebuggerWindows::start_process(file));
                }
            }
        });

        if let Some(d) = &mut c.debugger {
            (*d).process_debugger();
            egui::TopBottomPanel::top("Command bar").show(&egui.egui_ctx, |ui| {
                let r = ui.button("▶");
                if r.clicked() {
                    (*d).resume_all_threads();
                }
            });

            egui::SidePanel::left("side panel 1").show(&egui.egui_ctx, |ui| {
                egui::TopBottomPanel::top("threads panel")
                    .resizable(true)
                    .show_inside(ui, |ui| {
                        ui.heading("Threads");
                        egui::ScrollArea::vertical()
                            .auto_shrink([false; 2])
                            .show(ui, |ui| {
                                for (i, id) in (*d).get_all_threads().iter().enumerate() {
                                    ui.horizontal(|ui| {
                                        ui.label(format!("Thread #{} 0x{:x}", i + 1, id));
                                        if ui.button("→").clicked() {
                                            println!("Single thread run selected");
                                        }
                                        if ui.button("▶").clicked() {
                                            println!("Single thread resume selected");
                                        }
                                        if ui.button("⏸").clicked() {
                                            println!("Single thread pause selected");
                                        }
                                    });
                                }
                            });
                    });
                egui::TopBottomPanel::bottom("bottom remainder panel")
                    .resizable(true)
                    .show_inside(ui, |ui| {
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
            });
            egui::SidePanel::right("right panel")
                .resizable(true)
                .show(&egui.egui_ctx, |ui| {
                    egui::TopBottomPanel::top("register panel")
                        .resizable(true)
                        .show_inside(ui, |ui| {
                            ui.heading("Registers");
                            egui::ScrollArea::vertical()
                                .auto_shrink([false; 2])
                                .show(ui, |ui| {
                                    ui.label("EAX: 0x1234");
                                    ui.label("EBX: 0x4321");
                                });
                        });
                });
            egui::CentralPanel::default().show(&egui.egui_ctx, |ui| match (*d).get_state() {
                crate::debug::DebuggerState::Paused(reason) => {
                    ui.label("Program is paused");
                    let desc = match reason {
                        ReasonToPause::ProcessStart => "Process start".to_string(),
                        ReasonToPause::ProcessEnd => "Process end".to_string(),
                        ReasonToPause::ThreadStart => "Thread start".to_string(),
                        ReasonToPause::ThreadEnd => "Thread end".to_string(),
                        ReasonToPause::LibraryLoad => "Library load".to_string(),
                        ReasonToPause::LibraryUnload => "Library unload".to_string(),
                        ReasonToPause::Exception => match (*d).get_exception() {
                            crate::debug::Exception::Code(c) => {
                                format!("Exception code {:x}", c)
                            }
                            crate::debug::Exception::Unknown => "Unknown exception".to_string(),
                        },
                        ReasonToPause::Unknown => "Unknown".to_string(),
                    };
                    ui.label(desc);
                }
                crate::debug::DebuggerState::Running => {
                    ui.label("Program is running");
                }
            });
        } else {
            egui::CentralPanel::default().show(&egui.egui_ctx, |ui| {});
        }

        RedrawResponse {
            quit: quit,
            new_windows: windows_to_create,
        }
    }
}
