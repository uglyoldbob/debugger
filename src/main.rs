//! This is a general purpose debugger written in rust.

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

mod debug;

use debug::{ReasonToPause, X86Registers};

/// Defines the system type when debugging a windows program
pub struct Windows {}

/// Defines the local system type for the debugger
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
type LocalMachine = Windows;

/// The common elements for the debugger, shared among gui windows.
pub struct AppCommon {
    clicks: u32,
    debugger: Option<Box<debug::DebuggedMachine>>,
    thread_selection: Option<u32>,
    memory_selection: Option<usize>,
}

impl AppCommon {
    /// Construct a new main app instance
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            clicks: 0,
            debugger: None,
            thread_selection: None,
            memory_selection: None,
        }
    }
}

impl eframe::App for AppCommon {
    fn update(&mut self, ctx: &eframe::egui::Context, frame: &mut eframe::Frame) {
        ctx.request_repaint();
        eframe::egui::TopBottomPanel::top("menubar").show(ctx, |ui| {
            ui.menu_button("File", |ui| {
                if ui.button("Open executable").clicked() {
                    let file = rfd::FileDialog::new()
                        .add_filter("executables", &["exe"])
                        .pick_file();
                    if let Some(file) = file {
                        println!("You picked {:?}", file.display());
                        self.debugger = Some(crate::debug::DebuggerWindows::start_process(file));
                    }
                    ui.close_menu();
                }
            });
        });

        let Self {
            clicks,
            debugger,
            thread_selection,
            memory_selection,
        } = self;

        if let Some(d) = debugger {
            (*d).process_debugger();
            if let Some(f) = (*d).get_thread_focus() {
                *thread_selection = Some(f);
            }
            eframe::egui::TopBottomPanel::top("Command bar").show(ctx, |ui| {
                let r = ui.button("▶");
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

            eframe::egui::SidePanel::left("side panel 1").show(ctx, |ui| {
                eframe::egui::TopBottomPanel::top("threads panel")
                    .resizable(true)
                    .show_inside(ui, |ui| {
                        ui.heading("Threads");
                        eframe::egui::ScrollArea::vertical()
                            .auto_shrink([false; 2])
                            .show(ui, |ui| {
                                for (i, id) in (*d).get_all_threads().iter().enumerate() {
                                    ui.horizontal(|ui| {
                                        if ui
                                            .selectable_label(
                                                *thread_selection == Some(*id),
                                                format!("Thread #{} 0x{:x}", i + 1, id),
                                            )
                                            .clicked()
                                        {
                                            *thread_selection = Some(*id);
                                        }
                                    });
                                }
                            });
                    });
                if let Some(ranges) = (*d).get_memory_ranges() {
                    eframe::egui::TopBottomPanel::top("memory range panel")
                        .resizable(true)
                        .show_inside(ui, |ui| {
                            ui.heading("Memory Ranges");
                            eframe::egui::ScrollArea::vertical()
                                .auto_shrink([false; 2])
                                .show(ui, |ui| {
                                    for (i, r) in ranges.iter().enumerate() {
                                        if ui
                                            .selectable_label(
                                                *memory_selection == Some(i),
                                                format!(
                                                    "0x{:x}, 0x{:x} {:x}",
                                                    r.begin, r.length, r.flags
                                                ),
                                            )
                                            .clicked()
                                        {
                                            *memory_selection = Some(i);
                                        }
                                    }
                                });
                        });
                }
            });
            eframe::egui::SidePanel::right("right panel")
                .resizable(true)
                .show(ctx, |ui| {
                    eframe::egui::TopBottomPanel::top("register panel")
                        .resizable(true)
                        .show_inside(ui, |ui| {
                            ui.heading("Registers");
                            if let Some(threadid) = &thread_selection {
                                let regs = (*d).get_registers(*threadid);
                                if let Some(r) = regs {
                                    eframe::egui::ScrollArea::vertical().auto_shrink([false; 2]).show(
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
                eframe::egui::CentralPanel::default().show(ctx, |ui| {
                if let Some(threadid) = &thread_selection {
                    let regs = (*d).get_registers(*threadid);
                    if let Some(r) = regs {
                        ui.label("placeholder for disassembly");
                    }
                }
                if let Some(mi) = memory_selection {
                    eframe::egui::TopBottomPanel::bottom("memory view")
                        .resizable(true)
                        .show_inside(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label("Memory ");
                                if ui.button("X").clicked() {
                                    *memory_selection = None;
                                }
                            });
                        });
                }
            });
        } else {
            eframe::egui::CentralPanel::default().show(ctx, |ui| {});
        }
    }
}

fn main() {
    let options = eframe::NativeOptions::default();
    eframe::run_native("UglyOldBob Debugger", options, Box::new(|cc| Ok(Box::new(AppCommon::new(cc)))));
}
