use std::marker::PhantomData;

use egui_glow::EguiGlow;
use egui_multiwin::{
    multi_window::NewWindowRequest,
    tracked_window::{RedrawResponse, TrackedWindow},
};

use crate::{
    debug::{ReasonToPause, X86Registers},
    AppCommon,
};

use super::popup_window::PopupWindow;

pub struct RootWindow<T> {
    pub button_press_count: u32,
    pub num_popups_created: u32,
    thread_selection: Option<u32>,
    /// Defines which region of memory is selected for examination
    memory_selection: Option<usize>,
    _d: PhantomData<T>,
}

impl RootWindow<crate::Windows> {
    pub fn new() -> NewWindowRequest<AppCommon> {
        NewWindowRequest {
            window_state: Box::new(RootWindow::<crate::Windows> {
                button_press_count: 0,
                num_popups_created: 0,
                thread_selection: None,
                memory_selection: None,
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
            ui.menu_button("File", |ui| {
                if ui.button("Open executable").clicked() {
                    let file = rfd::FileDialog::new()
                        .add_filter("executables", &["exe"])
                        .pick_file();
                    if let Some(file) = file {
                        println!("You picked {:?}", file.display());
                        c.debugger = Some(crate::debug::DebuggerWindows::start_process(file));
                    }
                    ui.close_menu();
                }
            });
        });

        if let Some(d) = &mut c.debugger {
            (*d).process_debugger();
            if let Some(f) = (*d).get_thread_focus() {
                self.thread_selection = Some(f);
            }
            egui::TopBottomPanel::top("Command bar").show(&egui.egui_ctx, |ui| {
                let r = ui.button("???");
                if r.clicked() {
                    (*d).resume_all_threads();
                }
                ui.horizontal(|ui| match (*d).get_state() {
                    crate::debug::DebuggerState::Paused(reason) => {
                        ui.label("Program is paused, ");
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
                                        if ui
                                            .selectable_label(
                                                self.thread_selection == Some(*id),
                                                format!("Thread #{} 0x{:x}", i + 1, id),
                                            )
                                            .clicked()
                                        {
                                            self.thread_selection = Some(*id);
                                        }
                                    });
                                }
                            });
                    });
                if let Some(ranges) = (*d).get_memory_ranges() {
                    egui::TopBottomPanel::top("memory range panel")
                        .resizable(true)
                        .show_inside(ui, |ui| {
                            ui.heading("Memory Ranges");
                            egui::ScrollArea::vertical()
                                .auto_shrink([false; 2])
                                .show(ui, |ui| {
                                    for (i, r) in ranges.iter().enumerate() {
                                        if ui
                                            .selectable_label(
                                                self.memory_selection == Some(i),
                                                format!(
                                                    "0x{:x}, 0x{:x} {:x}",
                                                    r.begin, r.length, r.flags
                                                ),
                                            )
                                            .clicked()
                                        {
                                            self.memory_selection = Some(i);
                                        }
                                    }
                                });
                        });
                }
            });
            egui::SidePanel::right("right panel")
                .resizable(true)
                .show(&egui.egui_ctx, |ui| {
                    egui::TopBottomPanel::top("register panel")
                        .resizable(true)
                        .show_inside(ui, |ui| {
                            ui.heading("Registers");
                            if let Some(threadid) = &self.thread_selection {
                                let regs = (*d).get_registers(*threadid);
                                if let Some(r) = regs {
                                    egui::ScrollArea::vertical().auto_shrink([false; 2]).show(
                                        ui,
                                        |ui| match r {
                                            X86Registers::Bits32(r) => {
                                                ui.label(format!("EIP: 0x{:x}", r.eip));
                                                ui.label(format!("EAX: 0x{:x}", r.eax));
                                                ui.label(format!("EBX: 0x{:x}", r.ebx));
                                                ui.label(format!("ECX: 0x{:x}", r.ecx));
                                                ui.label(format!("EDX: 0x{:x}", r.edx));
                                                ui.label(format!("ESI: 0x{:x}", r.esi));
                                                ui.label(format!("EDI: 0x{:x}", r.edi));
                                                ui.label(format!("EBP: 0x{:x}", r.ebp));
                                                ui.label(format!("ESP: 0x{:x}", r.esp));
                                                ui.label(format!("CS: 0x{:x}", r.cs));
                                                ui.label(format!("DS: 0x{:x}", r.ds));
                                                ui.label(format!("ES: 0x{:x}", r.es));
                                                ui.label(format!("FS: 0x{:x}", r.fs));
                                                ui.label(format!("GS: 0x{:x}", r.gs));
                                                ui.label(format!("SS: 0x{:x}", r.ss));
                                                ui.label(format!("DR0: 0x{:x}", r.dr0));
                                                ui.label(format!("DR1: 0x{:x}", r.dr1));
                                                ui.label(format!("DR2: 0x{:x}", r.dr2));
                                                ui.label(format!("DR3: 0x{:x}", r.dr3));
                                                ui.label(format!("DR6: 0x{:x}", r.dr6));
                                                ui.label(format!("DR7: 0x{:x}", r.dr7));
                                                ui.label(format!("EFLAGS: 0x{:x}", r.eflags));
                                            }
                                            X86Registers::Bits64(r) => {
                                                ui.label(format!("RIP: 0x{:x}", r.rip));
                                                ui.label(format!("RAX: 0x{:x}", r.rax));
                                                ui.label(format!("RBX: 0x{:x}", r.rbx));
                                                ui.label(format!("RCX: 0x{:x}", r.rcx));
                                                ui.label(format!("RDX: 0x{:x}", r.rdx));
                                                ui.label(format!("RSI: 0x{:x}", r.rsi));
                                                ui.label(format!("RDI: 0x{:x}", r.rdi));
                                                ui.label(format!("RBP: 0x{:x}", r.rbp));
                                                ui.label(format!("RSP: 0x{:x}", r.rsp));
                                                ui.label(format!("CS: 0x{:x}", r.cs));
                                                ui.label(format!("DS: 0x{:x}", r.ds));
                                                ui.label(format!("ES: 0x{:x}", r.es));
                                                ui.label(format!("FS: 0x{:x}", r.fs));
                                                ui.label(format!("GS: 0x{:x}", r.gs));
                                                ui.label(format!("SS: 0x{:x}", r.ss));
                                                ui.label(format!("DR0: 0x{:x}", r.dr0));
                                                ui.label(format!("DR1: 0x{:x}", r.dr1));
                                                ui.label(format!("DR2: 0x{:x}", r.dr2));
                                                ui.label(format!("DR3: 0x{:x}", r.dr3));
                                                ui.label(format!("DR6: 0x{:x}", r.dr6));
                                                ui.label(format!("DR7: 0x{:x}", r.dr7));
                                                ui.label(format!("EFLAGS: 0x{:x}", r.eflags));
                                            }
                                        },
                                    );
                                }
                            }
                        });
                });
            egui::CentralPanel::default().show(&egui.egui_ctx, |ui| {
                if let Some(threadid) = &self.thread_selection {
                    let regs = (*d).get_registers(*threadid);
                    if let Some(r) = regs {
                        ui.label("placeholder for disassembly");
                    }
                }
                if let Some(mi) = self.memory_selection {
                    egui::TopBottomPanel::bottom("memory view")
                        .resizable(true)
                        .show_inside(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label("Memory ");
                                if ui.button("X").clicked() {
                                    self.memory_selection = None;
                                }
                            });
                        });
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
