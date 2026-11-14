//! The only `unsafe` in the app: Mach calls used by Attach by PID.
//! Everything here is a thin, checked wrapper; the snapshot logic itself is
//! safe code in `attach.rs`.

use crate::attach::RemoteReader;
use mach2::kern_return::KERN_SUCCESS;
use mach2::port::{mach_port_t, MACH_PORT_NULL};

/// `proc_pidpath`: executable path of `pid`, if the kernel will tell us.
pub fn pid_path(pid: i32) -> Option<String> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: `buf` is a valid writable buffer of exactly the length passed;
    // proc_pidpath writes at most that many bytes and returns the count.
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    String::from_utf8(buf).ok()
}

/// A task port for another process; released on drop.
pub struct Task(mach_port_t);

impl Task {
    /// Open the task of `pid` and return it with the remote address of its
    /// `dyld_all_image_infos`.
    pub fn open(pid: i32) -> Result<(Task, u64), String> {
        let mut port: mach_port_t = MACH_PORT_NULL;
        // SAFETY: `port` is a valid out-pointer for the duration of the call;
        // mach_task_self() only reads a process-global port name.
        let kr =
            unsafe { mach2::traps::task_for_pid(mach2::traps::mach_task_self(), pid, &mut port) };
        if kr != KERN_SUCCESS || port == MACH_PORT_NULL {
            return Err(format!(
                "task_for_pid failed (kr={kr}). This mode requires root/codesign entitlements."
            ));
        }
        let task = Task(port);

        let mut info = mach2::task_info::task_dyld_info {
            all_image_info_addr: 0,
            all_image_info_size: 0,
            all_image_info_format: 0,
        };
        let mut count = mach2::task_info::TASK_DYLD_INFO_COUNT;
        // SAFETY: `info` is a properly sized and aligned task_dyld_info and
        // `count` holds its size in natural_t units, as TASK_DYLD_INFO
        // requires; the kernel writes at most `count` units.
        let kr = unsafe {
            mach2::task::task_info(
                task.0,
                mach2::task_info::TASK_DYLD_INFO,
                (&mut info as *mut mach2::task_info::task_dyld_info).cast(),
                &mut count,
            )
        };
        if kr != KERN_SUCCESS || info.all_image_info_addr == 0 {
            return Err(format!("task_info(TASK_DYLD_INFO) failed (kr={kr})"));
        }
        Ok((task, info.all_image_info_addr))
    }
}

impl RemoteReader for Task {
    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<(), String> {
        let mut out: u64 = 0;
        // SAFETY: the destination is `buf`, valid for `buf.len()` writable
        // bytes in this process; the kernel copies at most that many bytes
        // and reports the count in `out`. The remote address is only read by
        // the kernel, which fails with an error code if it is unmapped.
        let kr = unsafe {
            mach2::vm::mach_vm_read_overwrite(
                self.0,
                addr,
                buf.len() as u64,
                buf.as_mut_ptr() as u64,
                &mut out,
            )
        };
        if kr != KERN_SUCCESS || out != buf.len() as u64 {
            return Err(format!(
                "mach_vm_read_overwrite failed at 0x{addr:x} (kr={kr}, size={}, out={out})",
                buf.len()
            ));
        }
        Ok(())
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a send right obtained from task_for_pid and
        // owned exclusively by this value; releasing it once is correct.
        unsafe {
            mach2::mach_port::mach_port_deallocate(mach2::traps::mach_task_self(), self.0);
        }
    }
}
