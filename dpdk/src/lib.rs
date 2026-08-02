//! Minimal safe ownership wrapper around the DPDK C API.

use std::{ffi::CString, io, ptr::NonNull};

#[allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]
mod ffi {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub struct Environment {
    pool: NonNull<ffi::rte_mempool>,
}

impl Environment {
    pub fn init(arguments: &[String]) -> io::Result<(Self, usize)> {
        let cstrings: Vec<_> = arguments
            .iter()
            .map(|arg| CString::new(arg.as_str()))
            .collect::<Result<_, _>>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "argument contains NUL"))?;
        let mut pointers: Vec<_> = cstrings.iter().map(|arg| arg.as_ptr().cast_mut()).collect();
        // SAFETY: pointers remain valid for the call and argc matches the array length.
        let consumed = unsafe { ffi::dpdk_eal_init(pointers.len() as i32, pointers.as_mut_ptr()) };
        if consumed < 0 {
            return Err(io::Error::other("DPDK EAL initialization failed"));
        }
        let name = CString::new(format!("etherip_{}", std::process::id())).unwrap();
        // SAFETY: EAL is initialized and name is a live NUL-terminated string.
        let pool = unsafe { ffi::dpdk_pool_create(name.as_ptr(), 8191) };
        Ok((
            Self {
                pool: NonNull::new(pool)
                    .ok_or_else(|| io::Error::other("mbuf pool creation failed"))?,
            },
            consumed as usize,
        ))
    }

    pub fn port_count(&self) -> u16 {
        // SAFETY: EAL remains initialized for Environment's lifetime.
        unsafe { ffi::dpdk_port_count() as u16 }
    }

    pub fn open(&self, id: u16) -> io::Result<Port> {
        if id >= self.port_count() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DPDK port does not exist",
            ));
        }
        // SAFETY: pool is live and id was checked against available ports.
        check(unsafe { ffi::dpdk_port_open(id, self.pool.as_ptr()) })?;
        Ok(Port {
            id,
            pool: self.pool,
        })
    }
}

pub struct Port {
    id: u16,
    pool: NonNull<ffi::rte_mempool>,
}

impl Port {
    pub fn mac(&self) -> io::Result<[u8; 6]> {
        let mut mac = [0; 6];
        // SAFETY: mac points to six writable bytes and the port is open.
        check(unsafe { ffi::dpdk_port_mac(self.id, mac.as_mut_ptr()) })?;
        Ok(mac)
    }

    pub fn receive(&self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        let capacity = u16::try_from(buffer.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "receive buffer exceeds 65535 bytes",
            )
        })?;
        // SAFETY: buffer is writable for capacity bytes and the port is open.
        match unsafe { ffi::dpdk_receive(self.id, buffer.as_mut_ptr(), capacity) } {
            0 => Ok(None),
            u16::MAX => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "received frame is too large",
            )),
            length => Ok(Some(length.into())),
        }
    }

    pub fn send(&self, frame: &[u8]) -> io::Result<()> {
        let length = u16::try_from(frame.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "frame exceeds 65535 bytes")
        })?;
        // SAFETY: frame is readable for length bytes; port and pool are live.
        check(unsafe { ffi::dpdk_send(self.id, self.pool.as_ptr(), frame.as_ptr(), length) })
    }
}

impl Drop for Port {
    fn drop(&mut self) {
        // SAFETY: this Port uniquely owns the open/close lifecycle for this id.
        unsafe { ffi::dpdk_port_close(self.id) }
    }
}

fn check(code: i32) -> io::Result<()> {
    (code >= 0)
        .then_some(())
        .ok_or_else(|| io::Error::from_raw_os_error(-code))
}
