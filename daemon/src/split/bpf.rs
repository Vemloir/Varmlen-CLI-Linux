use std::fs::File;
use std::os::fd::AsRawFd;

use super::SplitError;

pub const BYPASS_MARK: u32 = 0x2025;

const BPF_PROG_LOAD: libc::c_int = 5;
const BPF_PROG_ATTACH: libc::c_int = 8;
const BPF_PROG_DETACH: libc::c_int = 9;
const BPF_PROG_TYPE_CGROUP_SOCK: u32 = 9;
const BPF_CGROUP_INET_SOCK_CREATE: u32 = 2;

fn instruction(code: u8, dst: u8, src: u8, offset: i16, immediate: i32) -> [u8; 8] {
    let mut bytes = [0_u8; 8];
    bytes[0] = code;
    bytes[1] = (src << 4) | (dst & 0x0f);
    bytes[2..4].copy_from_slice(&offset.to_ne_bytes());
    bytes[4..8].copy_from_slice(&immediate.to_ne_bytes());
    bytes
}

pub fn socket_mark_program() -> Vec<u8> {
    let mut program = Vec::with_capacity(32);
    program.extend_from_slice(&instruction(0xb4, 2, 0, 0, BYPASS_MARK as i32));
    program.extend_from_slice(&instruction(0x63, 1, 2, 16, 0));
    program.extend_from_slice(&instruction(0xb4, 0, 0, 0, 1));
    program.extend_from_slice(&instruction(0x95, 0, 0, 0, 0));
    program
}

fn put_u32(buffer: &mut [u8], offset: usize, value: u32) {
    buffer[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}

fn put_u64(buffer: &mut [u8], offset: usize, value: u64) {
    buffer[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
}

fn bpf_call(command: libc::c_int, attributes: &mut [u8]) -> Result<i64, SplitError> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            command,
            attributes.as_mut_ptr(),
            attributes.len(),
        )
    };
    if result < 0 {
        Err(SplitError::BpfUnavailable)
    } else {
        Ok(result)
    }
}

pub fn detach_socket_mark(cgroup: &File) -> Result<(), SplitError> {
    let mut attributes = vec![0_u8; 16];
    put_u32(&mut attributes, 0, cgroup.as_raw_fd() as u32);
    put_u32(&mut attributes, 8, BPF_CGROUP_INET_SOCK_CREATE);
    bpf_call(BPF_PROG_DETACH, &mut attributes).map(|_| ())
}

pub fn attach_socket_mark(cgroup: &File) -> Result<(), SplitError> {
    let program = socket_mark_program();
    let license = b"Dual MIT/GPL\0";
    let mut load_attributes = vec![0_u8; 128];
    put_u32(&mut load_attributes, 0, BPF_PROG_TYPE_CGROUP_SOCK);
    put_u32(&mut load_attributes, 4, (program.len() / 8) as u32);
    put_u64(&mut load_attributes, 8, program.as_ptr() as u64);
    put_u64(&mut load_attributes, 16, license.as_ptr() as u64);
    put_u32(&mut load_attributes, 68, BPF_CGROUP_INET_SOCK_CREATE);
    let program_fd = bpf_call(BPF_PROG_LOAD, &mut load_attributes)? as libc::c_int;

    let _ = detach_socket_mark(cgroup);
    let mut attach_attributes = vec![0_u8; 16];
    put_u32(&mut attach_attributes, 0, cgroup.as_raw_fd() as u32);
    put_u32(&mut attach_attributes, 4, program_fd as u32);
    put_u32(&mut attach_attributes, 8, BPF_CGROUP_INET_SOCK_CREATE);
    let result = bpf_call(BPF_PROG_ATTACH, &mut attach_attributes).map(|_| ());
    unsafe {
        libc::close(program_fd);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{socket_mark_program, BYPASS_MARK};

    #[test]
    fn socket_program_sets_mark_and_returns_allow() {
        let program = socket_mark_program();
        assert_eq!(program.len(), 32);
        assert_eq!(
            i32::from_ne_bytes(program[4..8].try_into().unwrap()),
            BYPASS_MARK as i32
        );
        assert_eq!(program[8], 0x63);
        assert_eq!(i16::from_ne_bytes(program[10..12].try_into().unwrap()), 16);
        assert_eq!(i32::from_ne_bytes(program[20..24].try_into().unwrap()), 1);
        assert_eq!(program[24], 0x95);
    }
}
