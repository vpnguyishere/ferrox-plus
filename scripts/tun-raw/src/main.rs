//! Raw TUN device benchmark: opens two interfaces exactly as `ferrox-app`'s
//! device layer does and forwards packets between them. The plain mode is the
//! shipping read/write path; the offload and multi-queue modes measure the
//! headroom those options buy. It is benchmark tooling, not the shipping
//! engine, and runs on Linux only.
//!
//! Usage:
//!   ferrox-tun-raw --iface1 tun11 --iface2 tun22 [--gso] [--queues N]

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::io::FromRawFd;
use std::thread;

const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const IFF_MULTI_QUEUE: libc::c_short = 0x0100;
const IFF_VNET_HDR: libc::c_short = 0x4000;

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const TUNSETOFFLOAD: libc::c_ulong = 0x4004_54d0;

const TUN_F_CSUM: libc::c_int = 0x01;
const TUN_F_TSO4: libc::c_int = 0x02;
const TUN_F_TSO6: libc::c_int = 0x04;

const VIRTIO_NET_HDR_LEN: usize = 10;
const MAX_FRAME: usize = 65_535 + VIRTIO_NET_HDR_LEN;

#[repr(C)]
struct IfReq {
    ifr_name: [u8; 16],
    ifr_flags: libc::c_short,
    _pad: [u8; 22],
}

fn open_tun(name: &str, offload: bool, multi_queue: bool) -> io::Result<File> {
    let path = CString::new("/dev/net/tun").expect("the device path has no NUL");
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut req = IfReq {
        ifr_name: [0; 16],
        ifr_flags: IFF_TUN
            | IFF_NO_PI
            | if offload { IFF_VNET_HDR } else { 0 }
            | if multi_queue { IFF_MULTI_QUEUE } else { 0 },
        _pad: [0; 22],
    };
    let bytes = name.as_bytes();
    let len = bytes.len().min(15);
    req.ifr_name[..len].copy_from_slice(&bytes[..len]);

    let flags = req.ifr_flags;
    let rc = unsafe { libc::ioctl(fd, TUNSETIFF, &raw mut req) };
    if rc < 0 {
        let error = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(io::Error::new(
            error.kind(),
            format!("TUNSETIFF {name} flags {flags:#x}: {error}"),
        ));
    }

    if offload {
        let offloads: libc::c_int = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
        let rc = unsafe { libc::ioctl(fd, TUNSETOFFLOAD, &raw const offloads) };
        if rc < 0 {
            let error = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(io::Error::new(
                error.kind(),
                format!("TUNSETOFFLOAD {name}: {error}"),
            ));
        }
    }

    Ok(unsafe { File::from_raw_fd(fd) })
}

fn forward(mut source: File, mut sink: File) {
    let mut frame = vec![0u8; MAX_FRAME];
    loop {
        match source.read(&mut frame) {
            Ok(0) => {
                eprintln!("ferrox-tun-raw: read returned zero");
                return;
            }
            Ok(n) => {
                if let Err(error) = sink.write_all(&frame[..n]) {
                    eprintln!("ferrox-tun-raw: write failed: {error}");
                    return;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                eprintln!("ferrox-tun-raw: read failed: {error}");
                return;
            }
        }
    }
}

fn main() -> io::Result<()> {
    let mut iface1 = None;
    let mut iface2 = None;
    let mut offload = false;
    let mut queues = 1usize;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--iface1" => iface1 = args.next(),
            "--iface2" => iface2 = args.next(),
            "--gso" => offload = true,
            "--queues" => {
                queues = args
                    .next()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(1);
            }
            other => {
                eprintln!("ferrox-tun-raw: unknown argument {other}");
                std::process::exit(2);
            }
        }
    }
    let iface1 = iface1.expect("--iface1 is required");
    let iface2 = iface2.expect("--iface2 is required");
    let queues = queues.max(1);

    let mut left = Vec::with_capacity(queues);
    let mut right = Vec::with_capacity(queues);
    for _ in 0..queues {
        left.push(open_tun(&iface1, offload, queues > 1)?);
        right.push(open_tun(&iface2, offload, queues > 1)?);
    }

    eprintln!(
        "ferrox-tun-raw: {iface1} <-> {iface2} queues={queues} offload={offload}"
    );
    let mut handles = Vec::with_capacity(queues * 2);
    for (l, r) in left.into_iter().zip(right) {
        let l2 = l.try_clone()?;
        let r2 = r.try_clone()?;
        handles.push(thread::spawn(move || forward(l, r2)));
        handles.push(thread::spawn(move || forward(r, l2)));
    }
    for handle in handles {
        let _ = handle.join();
    }
    Ok(())
}
