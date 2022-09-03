use std::{ffi::c_void, ffi::CString, mem, path::PathBuf};

use windows::{
    core::{PCSTR, PSTR},
    Win32::{
        Foundation::{BOOL, HANDLE},
        Security::SECURITY_ATTRIBUTES,
        System::{
            Diagnostics::Debug::{self, DEBUG_EVENT},
            Threading::{
                PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOA,
            },
        },
    },
};

use super::{DebuggerChannels, MessageFromDebugger, MessageToDebugger};

pub struct Debugger {
    info: PROCESS_INFORMATION,
    is64: Option<bool>,
    recvr: std::sync::mpsc::Receiver<MessageToDebugger>,
    sndr: std::sync::mpsc::Sender<MessageFromDebugger>,
}

struct WorkingSetEntry {
    address: usize,
    shareable: bool,
    sharecount: u8,
    flags: u8,
}

impl WorkingSetEntry {
    fn is_readable(&self) -> bool {
        (self.flags & 1) != 0
    }

    fn is_executable(&self) -> bool {
        (self.flags & 2) != 0
    }

    fn is_writable(&self) -> bool {
        (self.flags & 4) != 0
    }

    fn is_non_cacheable(&self) -> bool {
        (self.flags & 8) != 0
    }

    fn is_guard_page(&self) -> bool {
        (self.flags & 16) != 0
    }
}

impl Debugger {
    fn new(
        recvr: std::sync::mpsc::Receiver<MessageToDebugger>,
        sndr: std::sync::mpsc::Sender<MessageFromDebugger>,
    ) -> Self {
        Self {
            info: PROCESS_INFORMATION::default(),
            is64: None,
            recvr: recvr,
            sndr: sndr,
        }
    }

    fn is_64_bit_process(&mut self) -> Option<bool> {
        let mut process: windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE =
            windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE::default();
        let mut native: windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE =
            windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE::default();
        let res = unsafe {
            windows::Win32::System::Threading::IsWow64Process2(
                self.info.hProcess,
                &mut process as *mut windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE,
                &mut native as *mut windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE,
            )
        };
        if res.as_bool() {
            match process {
                windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_UNKNOWN => {
                    match native {
                        windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_UNKNOWN => {
                            None
                        }
                        windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_I386
                        | windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_ARM => {
                            Some(false)
                        }
                        windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_IA64
                        | windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_AMD64
                        | windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_ARM64 => {
                            Some(true)
                        }
                        _ => None,
                    }
                }
                windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_I386
                | windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_ARM => Some(false),
                windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_IA64
                | windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_AMD64
                | windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_ARM64 => Some(true),
                _ => None,
            }
        } else {
            let err = unsafe { windows::Win32::Foundation::GetLastError() };
            None
        }
    }

    fn query_working_set(&mut self) -> Result<Vec<WorkingSetEntry>, u32> {
        let mut pv: Vec<usize> = Vec::with_capacity(8);
        for _ in 0..8 {
            pv.push(0);
        }
        let a = pv.as_mut_ptr() as *mut c_void;
        let res = unsafe {
            windows::Win32::System::ProcessStatus::K32QueryWorkingSet(self.info.hProcess, a, 8)
        };
        let pv = if res.as_bool() {
            println!("Success queryworkingset");
            Ok(pv)
        } else {
            let err = unsafe { windows::Win32::Foundation::GetLastError() };
            if err == windows::Win32::Foundation::ERROR_BAD_LENGTH {
                let len = pv[0] + 1;
                pv.resize(len, 0);
                let a = pv.as_mut_ptr() as *mut c_void;
                let res = unsafe {
                    windows::Win32::System::ProcessStatus::K32QueryWorkingSet(
                        self.info.hProcess,
                        a,
                        (mem::size_of::<usize>() * len) as u32,
                    )
                };
                if res.as_bool() {
                    println!("Success queryworkingset {:?}", pv);
                    Ok(pv)
                } else {
                    Err(err.0)
                }
            } else {
                println!("The error for queryworkingset is {:?} {:?}", err, pv);
                Err(err.0)
            }
        };
        pv.map(|e| {
            e.iter()
                .map(|v| WorkingSetEntry {
                    address: *v & !0xFFF,
                    shareable: (*v & 0x100) != 0,
                    sharecount: ((*v >> 5) & 7) as u8,
                    flags: (*v & 0x1f) as u8,
                })
                .collect()
        })
    }

    fn debug_loop(&mut self) {
        let mut lpdebugevent = DEBUG_EVENT::default();
        let mut should_exit = false;
        loop {
            let r = unsafe {
                windows::Win32::System::Diagnostics::Debug::WaitForDebugEvent(
                    &mut lpdebugevent,
                    0xFFFFFFFF,
                )
            };
            if r.as_bool() {
                let mut cont_code = windows::Win32::Foundation::DBG_CONTINUE.0 as u32;
                match lpdebugevent.dwDebugEventCode {
                    Debug::CREATE_PROCESS_DEBUG_EVENT => {
                        println!("Process created");
                        self.is64 = self.is_64_bit_process();
                        if let Some(is64) = self.is64 {
                            if is64 {
                                println!("Remote process is 64 bit");
                            } else {
                                println!("Remote process is 32 bit");
                            }
                        }
                        let v = self.query_working_set();
                        if let Ok(r) = v {
                            for e in r {
                                println!("Address 0x{:x} is 0x{:x}", e.address, e.flags);
                            }
                        }
                    }
                    Debug::LOAD_DLL_DEBUG_EVENT => {
                        let event = unsafe { lpdebugevent.u.LoadDll };
                        println!("DLL Load event {:x?}", event.lpBaseOfDll);
                    }
                    Debug::UNLOAD_DLL_DEBUG_EVENT => {
                        println!("DLL Unload event");
                    }
                    Debug::CREATE_THREAD_DEBUG_EVENT => {
                        println!("Thread creation event");
                    }
                    Debug::EXIT_THREAD_DEBUG_EVENT => {
                        println!("Thread exit event");
                    }
                    Debug::EXCEPTION_DEBUG_EVENT => {
                        println!("Exception in debugging");
                    }
                    Debug::EXIT_PROCESS_DEBUG_EVENT => {
                        if lpdebugevent.dwProcessId == self.info.dwProcessId {
                            should_exit = true;
                            println!("Process exit event for main process");
                        } else {
                            println!("Other process exit event");
                        }
                    }
                    _ => {
                        println!("Received a debug event {:?}", lpdebugevent.dwDebugEventCode);
                    }
                }
                if !should_exit {
                    unsafe {
                        windows::Win32::System::Diagnostics::Debug::ContinueDebugEvent(
                            lpdebugevent.dwProcessId,
                            lpdebugevent.dwThreadId,
                            cont_code,
                        );
                    }
                } else {
                    break;
                }
            } else {
                let err = unsafe { windows::Win32::Foundation::GetLastError() };
                println!("The error for waitfordebugevent is {:?}", err);
                return;
            }
        }
        println!("Done debugging process");
    }

    fn thread_start_process(&mut self, p: PathBuf) {
        let mut p2 = p.clone();
        p2.pop();
        let s = p.into_os_string().into_string().unwrap();
        let s2 = p2.into_os_string().into_string().unwrap();
        let path = CString::new(s.clone()).unwrap();
        let mut cmd = CString::new(s.clone()).unwrap();
        let curdir = CString::new(s2.clone()).unwrap();
        let env = CString::new(s.clone()).unwrap();
        let mut pattr: SECURITY_ATTRIBUTES = SECURITY_ATTRIBUTES {
            nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: 0 as *mut c_void,
            bInheritHandle: BOOL(0),
        };
        let mut tattr: SECURITY_ATTRIBUTES = SECURITY_ATTRIBUTES {
            nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: 0 as *mut c_void,
            bInheritHandle: BOOL(0),
        };
        let envflags = 0 as *mut c_void;

        let inp: HANDLE = HANDLE(0); //TODO create a handle for this CreateNamedPipeA
        let outp: HANDLE = HANDLE(0); //TODO create a handle for this CreateNamedPipeA
        let errp: HANDLE = HANDLE(0); //TODO create a handle for this CreateNamedPipeA

        let start: STARTUPINFOA = STARTUPINFOA {
            cb: mem::size_of::<STARTUPINFOA>() as u32,
            lpReserved: PSTR(0 as *mut u8),
            lpDesktop: PSTR(0 as *mut u8),
            lpTitle: PSTR(0 as *mut u8),
            dwX: 0,
            dwY: 0,
            dwXSize: 0,
            dwYSize: 0,
            dwXCountChars: 0,
            dwYCountChars: 0,
            dwFillAttribute: 0,
            dwFlags: STARTF_USESTDHANDLES,
            wShowWindow: 0,
            cbReserved2: 0,
            lpReserved2: (0 as *mut u8),
            hStdInput: inp,
            hStdOutput: outp,
            hStdError: errp,
        };
        let response = unsafe {
            windows::Win32::System::Threading::CreateProcessA(
                PCSTR(path.as_ptr() as *const u8),
                PSTR(0 as *mut u8),
                &mut pattr,
                &mut tattr,
                BOOL(0),
                PROCESS_CREATION_FLAGS(1),
                envflags,
                PCSTR(curdir.as_ptr() as *const u8),
                &start,
                &mut self.info,
            )
        };
        println!("Response of createprocess is {}", response.as_bool());
        if !response.as_bool() {
            let err = unsafe { windows::Win32::Foundation::GetLastError() };
            println!("The error is {:?}", err);
            return;
        }

        self.debug_loop();
    }

    pub fn start_process(p: PathBuf) -> DebuggerChannels {
        let (to_debugger, from_app) = std::sync::mpsc::channel();
        let (to_app, from_debugger) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
            let mut d = Debugger::new(from_app, to_app);
            d.thread_start_process(p);
        });
        DebuggerChannels {
            sndr: to_debugger,
            rcvr: from_debugger,
        }
    }
}
