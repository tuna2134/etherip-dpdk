//! Safe ownership and burst-oriented access to the DPDK C API.

use std::{
    cell::RefCell,
    ffi::CString,
    io,
    ptr::{self, NonNull},
    rc::Rc,
    slice,
};

#[allow(
    dead_code,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unsafe_op_in_unsafe_fn,
    clippy::all,
    clippy::pedantic
)]
mod ffi {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[derive(Clone, Copy, Debug)]
pub struct MempoolConfig {
    pub packet_count: u32,
    pub cache_size: u32,
    pub data_room_size: u16,
    pub socket_id: Option<i32>,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            packet_count: 8191,
            cache_size: 256,
            data_room_size: 2176,
            socket_id: None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PortConfig {
    pub rx_queue: u16,
    pub tx_queue: u16,
    pub rx_descriptors: u16,
    pub tx_descriptors: u16,
    pub socket_id: Option<u32>,
    pub promiscuous: bool,
}

impl Default for PortConfig {
    fn default() -> Self {
        Self {
            rx_queue: 0,
            tx_queue: 0,
            rx_descriptors: 1024,
            tx_descriptors: 1024,
            socket_id: None,
            promiscuous: true,
        }
    }
}

pub struct Environment {
    pool: Rc<Pool>,
}

struct Pool(NonNull<ffi::rte_mempool>);

impl Drop for Pool {
    fn drop(&mut self) {
        // SAFETY: Rc ensures that no Port or Packet using this pool remains.
        unsafe { ffi::rte_mempool_free(self.0.as_ptr()) }
    }
}

impl Environment {
    pub fn init(arguments: &[String]) -> io::Result<(Self, usize)> {
        Self::init_with_config(arguments, MempoolConfig::default())
    }

    pub fn init_with_config(
        arguments: &[String],
        config: MempoolConfig,
    ) -> io::Result<(Self, usize)> {
        let mut arguments: Vec<Vec<u8>> = arguments
            .iter()
            .map(|arg| CString::new(arg.as_str()).map(CString::into_bytes_with_nul))
            .collect::<Result<_, _>>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "argument contains NUL"))?;
        let mut pointers: Vec<_> = arguments
            .iter_mut()
            .map(|arg| arg.as_mut_ptr().cast())
            .collect();
        // SAFETY: every pointer is writable and NUL-terminated for the duration of the call.
        let consumed = unsafe { ffi::rte_eal_init(pointers.len() as i32, pointers.as_mut_ptr()) };
        if consumed < 0 {
            return Err(last_error());
        }

        let name = CString::new(format!("etherip_{}", std::process::id())).unwrap();
        let socket_id = config.socket_id.unwrap_or_else(|| {
            // SAFETY: EAL was initialized successfully above.
            unsafe { ffi::rte_socket_id() as i32 }
        });
        // SAFETY: arguments match rte_pktmbuf_pool_create and name remains live for the call.
        let pool = unsafe {
            ffi::rte_pktmbuf_pool_create(
                name.as_ptr(),
                config.packet_count,
                config.cache_size,
                0,
                config.data_room_size,
                socket_id,
            )
        };
        let pool = NonNull::new(pool).ok_or_else(last_error)?;
        Ok((
            Self {
                pool: Rc::new(Pool(pool)),
            },
            consumed as usize,
        ))
    }

    pub fn port_count(&self) -> u16 {
        // SAFETY: EAL remains initialized for Environment's lifetime.
        unsafe { ffi::rte_eth_dev_count_avail() }
    }

    pub fn open(&self, id: u16) -> io::Result<Port> {
        self.open_with_config(id, PortConfig::default())
    }

    pub fn open_with_config(&self, id: u16, config: PortConfig) -> io::Result<Port> {
        if id >= self.port_count() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DPDK port does not exist",
            ));
        }
        let rx_queue_count = config.rx_queue.checked_add(1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "RX queue ID is too large")
        })?;
        let tx_queue_count = config.tx_queue.checked_add(1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "TX queue ID is too large")
        })?;
        // SAFETY: all-zero rte_eth_conf is DPDK's documented default configuration.
        let eth_config = unsafe { std::mem::zeroed::<ffi::rte_eth_conf>() };
        // SAFETY: id is valid and eth_config remains live for the call.
        check(unsafe {
            ffi::rte_eth_dev_configure(id, rx_queue_count, tx_queue_count, &raw const eth_config)
        })?;

        let result = (|| {
            let socket = match config.socket_id {
                Some(socket) => socket,
                None => {
                    // SAFETY: id is a configured port.
                    let socket = unsafe { ffi::rte_eth_dev_socket_id(id) };
                    check(socket)?;
                    socket as u32
                }
            };
            for queue in 0..rx_queue_count {
                // SAFETY: port, queue, pool and descriptor arguments are valid for queue setup.
                check(unsafe {
                    ffi::rte_eth_rx_queue_setup(
                        id,
                        queue,
                        config.rx_descriptors,
                        socket,
                        ptr::null(),
                        self.pool.0.as_ptr(),
                    )
                })?;
            }
            for queue in 0..tx_queue_count {
                // SAFETY: port, queue and descriptor arguments are valid for queue setup.
                check(unsafe {
                    ffi::rte_eth_tx_queue_setup(
                        id,
                        queue,
                        config.tx_descriptors,
                        socket,
                        ptr::null(),
                    )
                })?;
            }
            // SAFETY: both queues were configured successfully.
            check(unsafe { ffi::rte_eth_dev_start(id) })?;
            if config.promiscuous {
                // SAFETY: the port is started.
                check(unsafe { ffi::rte_eth_promiscuous_enable(id) })?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            // SAFETY: closes partial configuration after an error.
            unsafe { ffi::rte_eth_dev_close(id) };
            return Err(error);
        }
        Ok(Port {
            id,
            rx_queue: config.rx_queue,
            tx_queue: config.tx_queue,
            pool: Rc::clone(&self.pool),
            rx_scratch: RefCell::new(Vec::new()),
            tx_scratch: RefCell::new(Vec::new()),
        })
    }

    pub fn packet(&self, bytes: &[u8]) -> io::Result<Packet> {
        Packet::from_bytes(Rc::clone(&self.pool), bytes)
    }
}

pub struct Port {
    id: u16,
    rx_queue: u16,
    tx_queue: u16,
    pool: Rc<Pool>,
    rx_scratch: RefCell<Vec<*mut ffi::rte_mbuf>>,
    tx_scratch: RefCell<Vec<*mut ffi::rte_mbuf>>,
}

impl Port {
    pub fn mac(&self) -> io::Result<[u8; 6]> {
        // SAFETY: zero is a valid bit pattern for rte_ether_addr.
        let mut address = unsafe { std::mem::zeroed::<ffi::rte_ether_addr>() };
        // SAFETY: address is writable and the port is open.
        check(unsafe { ffi::rte_eth_macaddr_get(self.id, &raw mut address) })?;
        Ok(address.addr_bytes)
    }

    pub fn receive_burst(&self, count: u16) -> io::Result<Vec<Packet>> {
        let mut packets = Vec::with_capacity(usize::from(count));
        self.receive_burst_into(&mut packets, count)?;
        Ok(packets)
    }

    pub fn receive_burst_into(&self, packets: &mut Vec<Packet>, count: u16) -> io::Result<()> {
        validate_burst(count)?;
        packets.clear();
        packets.reserve(usize::from(count));
        let mut pointers = self.rx_scratch.borrow_mut();
        pointers.resize(usize::from(count), ptr::null_mut());
        // SAFETY: pointers has count writable entries and the RX queue is configured.
        let received =
            unsafe { ffi::dpdk_rx_burst(self.id, self.rx_queue, pointers.as_mut_ptr(), count) };
        for &pointer in &pointers[..usize::from(received)] {
            packets.push(Packet {
                pointer: Some(NonNull::new(pointer).expect("DPDK returned a null mbuf")),
                _pool: Rc::clone(&self.pool),
            });
        }
        Ok(())
    }

    /// Transfers ownership of the successfully transmitted prefix to DPDK.
    pub fn send_burst(&self, packets: &mut [Packet]) -> io::Result<usize> {
        let count = u16::try_from(packets.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "TX burst exceeds 65535 packets",
            )
        })?;
        if count == 0 {
            return Ok(0);
        }
        let mut pointers = self.tx_scratch.borrow_mut();
        pointers.clear();
        pointers.extend(packets.iter().map(Packet::as_ptr));
        // SAFETY: every pointer is owned by the corresponding Packet until this call succeeds.
        let sent =
            unsafe { ffi::dpdk_tx_burst(self.id, self.tx_queue, pointers.as_mut_ptr(), count) };
        for packet in &mut packets[..usize::from(sent)] {
            packet.pointer.take();
        }
        Ok(usize::from(sent))
    }
}

impl Drop for Port {
    fn drop(&mut self) {
        // SAFETY: this Port owns the configured port lifecycle.
        unsafe {
            ffi::rte_eth_dev_stop(self.id);
            ffi::rte_eth_dev_close(self.id);
        }
    }
}

pub struct Packet {
    pointer: Option<NonNull<ffi::rte_mbuf>>,
    _pool: Rc<Pool>,
}

impl Packet {
    fn from_bytes(pool: Rc<Pool>, bytes: &[u8]) -> io::Result<Self> {
        // SAFETY: pool remains alive through the Rc stored in Packet.
        let pointer = unsafe { ffi::dpdk_pktmbuf_alloc(pool.0.as_ptr()) };
        let mut packet = Self {
            pointer: Some(
                NonNull::new(pointer).ok_or_else(|| io::Error::other("mbuf allocation failed"))?,
            ),
            _pool: pool,
        };
        let target = packet.append(bytes.len())?;
        target.copy_from_slice(bytes);
        Ok(packet)
    }

    pub fn len(&self) -> usize {
        // SAFETY: as_ptr is a live owned mbuf.
        unsafe { ffi::dpdk_mbuf_packet_length(self.as_ptr()) as usize }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn data(&self) -> Option<&[u8]> {
        if self.segment_count() != 1 {
            return None;
        }
        // SAFETY: a single-segment mbuf owns data_length initialized bytes.
        Some(unsafe {
            slice::from_raw_parts(
                ffi::dpdk_mbuf_data(self.as_ptr()).cast(),
                self.data_length(),
            )
        })
    }

    pub fn data_mut(&mut self) -> Option<&mut [u8]> {
        if self.segment_count() != 1 {
            return None;
        }
        let length = self.data_length();
        // SAFETY: &mut self provides exclusive access to the live mbuf data.
        Some(unsafe {
            slice::from_raw_parts_mut(ffi::dpdk_mbuf_data(self.as_ptr()).cast(), length)
        })
    }

    pub fn prepend(&mut self, length: usize) -> io::Result<&mut [u8]> {
        let length = packet_length(length)?;
        // SAFETY: the packet is live; DPDK checks available headroom.
        let data = unsafe { ffi::dpdk_pktmbuf_prepend(self.as_ptr(), length) };
        NonNull::new(data.cast::<u8>())
            .map(|data| {
                // SAFETY: successful prepend returns length writable bytes exclusively owned here.
                unsafe { slice::from_raw_parts_mut(data.as_ptr(), usize::from(length)) }
            })
            .ok_or_else(|| io::Error::other("mbuf has insufficient headroom"))
    }

    pub fn adjust(&mut self, length: usize) -> io::Result<()> {
        let length = packet_length(length)?;
        // SAFETY: the packet is live; DPDK rejects adjustment beyond first segment.
        let data = unsafe { ffi::dpdk_pktmbuf_adj(self.as_ptr(), length) };
        NonNull::new(data)
            .map(|_| ())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid mbuf adjustment"))
    }

    fn append(&mut self, length: usize) -> io::Result<&mut [u8]> {
        let length = packet_length(length)?;
        // SAFETY: the packet is live; DPDK checks available tailroom.
        let data = unsafe { ffi::dpdk_pktmbuf_append(self.as_ptr(), length) };
        NonNull::new(data.cast::<u8>())
            .map(|data| {
                // SAFETY: successful append returns length writable bytes exclusively owned here.
                unsafe { slice::from_raw_parts_mut(data.as_ptr(), usize::from(length)) }
            })
            .ok_or_else(|| io::Error::other("mbuf has insufficient tailroom"))
    }

    fn as_ptr(&self) -> *mut ffi::rte_mbuf {
        self.pointer
            .expect("packet ownership was transferred")
            .as_ptr()
    }

    fn data_length(&self) -> usize {
        // SAFETY: as_ptr is a live owned mbuf.
        unsafe { ffi::dpdk_mbuf_data_length(self.as_ptr()) as usize }
    }

    fn segment_count(&self) -> u16 {
        // SAFETY: as_ptr is a live owned mbuf.
        unsafe { ffi::dpdk_mbuf_segment_count(self.as_ptr()) }
    }
}

impl Drop for Packet {
    fn drop(&mut self) {
        if let Some(pointer) = self.pointer {
            // SAFETY: pointer is still owned by this Packet and has not been submitted to TX.
            unsafe { ffi::dpdk_pktmbuf_free(pointer.as_ptr()) }
        }
    }
}

fn validate_burst(count: u16) -> io::Result<()> {
    (count != 0 && count.is_multiple_of(8))
        .then_some(())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "RX burst must be a non-zero multiple of 8",
            )
        })
}

fn packet_length(length: usize) -> io::Result<u16> {
    u16::try_from(length)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "packet length exceeds 65535"))
}

fn check(code: i32) -> io::Result<i32> {
    (code >= 0)
        .then_some(code)
        .ok_or_else(|| io::Error::from_raw_os_error(-code))
}

fn last_error() -> io::Error {
    // SAFETY: rte_errno is available after DPDK reported an error.
    let errno = unsafe { ffi::dpdk_errno() };
    if errno > 0 {
        io::Error::from_raw_os_error(errno)
    } else {
        io::Error::other("DPDK operation failed without setting rte_errno")
    }
}
