#[macro_use]
extern crate nom;
extern crate strum;
#[macro_use]
extern crate strum_macros;

use nom::IResult::*;
use nom::{IResult, Needed};
use std::convert::From;
use std::io::{self,BufRead,BufReader,Read,Write};
use std::str::{self, FromStr};

const MAX_PACKET_SIZE: usize = 65 * 1024;


named!(checksum<&[u8], u8>,
       map_res!(map_res!(take!(2), str::from_utf8),
                |s| u8::from_str_radix(s, 16)));

named!(packet<&[u8], (Vec<u8>, u8)>,
       preceded!(tag!("$"),
                 separated_pair!(map!(opt!(is_not!("#")), |o: Option<&[u8]>| {
                     o.map_or(vec!(), |s| s.to_vec())
                 }),
                                 tag!("#"),
                                 checksum)));

#[derive(Debug,PartialEq,Eq)]
enum Packet {
    Ack,
    Nack,
    Interrupt,
    Data(Vec<u8>, u8),
}

named!(packet_or_response<Packet>, alt!(
    packet => { |(d, chk)| Packet::Data(d, chk) }
    | tag!("+") => { |_| Packet::Ack }
    | tag!("-") => { |_| Packet::Nack }
    | tag!("\x03") => { |_| Packet::Interrupt }
    ));

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, EnumString, PartialEq)]
enum GDBFeature {
    multiprocess,
    xmlRegisters,
    qRelocInsn,
    swbreak,
    hwbreak,
    #[strum(serialize="fork-events")]
    fork_events,
    #[strum(serialize="vfork-events")]
    vfork_events,
    #[strum(serialize="exec-events")]
    exec_events,
    vContSupported,
    // these are not listed in the docs but GDB sends them
    #[strum(serialize="no-resumed")]
    no_resumed,
    QThreadEvents,
}

#[derive(Clone, Debug, PartialEq)]
enum Known<'a> {
    Yes(GDBFeature),
    No(&'a str),
}

#[derive(Clone, Debug, PartialEq)]
struct GDBFeatureSupported<'a>(Known<'a>, FeatureSupported<'a>);

#[derive(Clone, Debug, PartialEq)]
enum FeatureSupported<'a> {
    Yes,
    No,
    #[allow(unused)]
    Maybe,
    Value(&'a str),
}

#[derive(Clone, Debug, PartialEq)]
enum Query<'a> {
    /// Return the attached state of the indicated process.
    // FIXME the PID only needs to be optional in the
    // non-multi-process case, which we aren't supporting; but we
    // don't send multiprocess+ in the feature response yet.
    Attached(Option<u64>),
    /// Return the current thread ID.
    CurrentThread,
    /// Search memory for some bytes.
    SearchMemory { address: u64, length: u64, bytes: Vec<u8> },
    /// Compute the CRC checksum of a block of memory.
    // Uncomment this when qC is implemented.
    // #[allow(unused)]
    // CRC { addr: u64, length: u64 },
    /// Tell the remote stub about features supported by gdb, and query the stub for features
    /// it supports.
    SupportedFeatures(Vec<GDBFeatureSupported<'a>>),
    /// Disable acknowledgments.
    StartNoAckMode,
    /// Invoke a command on the server.  The server defines commands
    /// and how to parse them.
    Invoke(Vec<u8>),
    /// Enable or disable address space randomization.
    AddressRandomization(bool),
    /// Enable or disable catching of syscalls.
    CatchSyscalls(Option<Vec<u64>>),
    /// Set the list of pass signals.
    PassSignals(Vec<u64>),
    /// Set the list of program signals.
    ProgramSignals(Vec<u64>),
    /// Get a string description of a thread.
    ThreadInfo(ThreadId),
}

/// Part of a process id.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Id {
    /// A process or thread id.  This value may not be 0 or -1.
    Id(u32),
    /// A special form meaning all processes or all threads of a given
    /// process.
    All,
    /// A special form meaning any process or any thread of a given
    /// process.
    Any,
}

/// A thread identifier.  In the RSP this is just a numeric handle
/// that is passed across the wire.  It needn't correspond to any real
/// thread or process id (though obviously it may be more convenient
/// when it does).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ThreadId {
    /// The process id.
    pub pid: Id,
    /// The thread id.
    pub tid: Id,
}

/// GDB remote protocol commands, as defined in (the GDB documentation)[1]
/// [1]: https://sourceware.org/gdb/onlinedocs/gdb/Packets.html#Packets
#[derive(Clone, Debug, PartialEq)]
enum Command<'a> {
    /// Detach from a process or from all processes.
    Detach(Option<u64>),
    /// Enable extended mode.
    EnableExtendedMode,
    /// Indicate the reason the target halted.
    TargetHaltReason,
    // Read general registers.
    ReadGeneralRegisters,
    // Write general registers.
    WriteGeneralRegisters(Vec<u8>),
    // Read a single register.
    ReadRegister(u64),
    // Write a single register.
    WriteRegister(u64, Vec<u8>),
    // Kill request.  The argument is the optional PID, provided when the vKill
    // packet was used, and None when the k packet was used.
    Kill(Option<u64>),
    // Read specified region of memory.
    ReadMemory(u64, u64),
    // Write specified region of memory.
    WriteMemory(u64, u64, Vec<u8>),
    Query(Query<'a>),
    Reset,
    PingThread(ThreadId),
    CtrlC,
    UnknownVCommand,
    /// Set the current thread for future commands, such as `ReadRegister`.
    SetCurrentThread(ThreadId),
}

named!(gdbfeature<Known>, map!(map_res!(is_not_s!(";="), str::from_utf8), |s| {
    match GDBFeature::from_str(s) {
        Ok(f) => Known::Yes(f),
        Err(_) => Known::No(s),
    }
}));

fn gdbfeaturesupported<'a>(i: &'a [u8]) -> IResult<&'a [u8], GDBFeatureSupported<'a>> {
    flat_map!(i, is_not!(";"), |f: &'a [u8]| {
        match f.split_last() {
            None => IResult::Incomplete(Needed::Size(2)),
            Some((&b'+', first)) => {
                map!(first, gdbfeature, |feat| GDBFeatureSupported(feat, FeatureSupported::Yes))
            }
            Some((&b'-', first)) => {
                map!(first, gdbfeature, |feat| GDBFeatureSupported(feat, FeatureSupported::No))
            }
            Some((_, _)) => {
                map!(f, separated_pair!(gdbfeature, tag!("="),
                                        map_res!(is_not!(";"), str::from_utf8)),
                     |(feat, value)| GDBFeatureSupported(feat, FeatureSupported::Value(value)))
            }
        }
    })
}

named!(q_search_memory<&[u8], (u64, u64, Vec<u8>)>,
       complete!(do_parse!(
           tag!("qSearch:memory:") >>
           address: hex_value >>
           tag!(";") >>
           length: hex_value >>
           tag!(";") >>
           data: hex_byte_sequence >>
           (address, length, data))));

fn query<'a>(i: &'a [u8]) -> IResult<&'a [u8], Query<'a>> {
    alt_complete!(i,
                  tag!("qC") => { |_| Query::CurrentThread }
                  | preceded!(tag!("qSupported"),
                              preceded!(tag!(":"),
                                        separated_list_complete!(tag!(";"),
                                                                 gdbfeaturesupported))) => {
                      |features: Vec<GDBFeatureSupported<'a>>| Query::SupportedFeatures(features)
                  }
                  | preceded!(tag!("qRcmd,"), hex_byte_sequence) => {
                      |bytes| Query::Invoke(bytes)
                  }
                  | q_search_memory => {
                      |(address, length, bytes)| Query::SearchMemory { address, length, bytes }
                  }
                  | tag!("QStartNoAckMode") => { |_| Query::StartNoAckMode }
                  | preceded!(tag!("qAttached:"), hex_value) => {
                      |value| Query::Attached(Some(value))
                  }
                  | tag!("qAttached") => { |_| Query::Attached(None) }
                  | tag!("QDisableRandomization:0") => { |_| Query::AddressRandomization(true) }
                  | tag!("QDisableRandomization:1") => { |_| Query::AddressRandomization(false) }
                  | tag!("QCatchSyscalls:0") => { |_| Query::CatchSyscalls(None) }
                  | preceded!(tag!("QCatchSyscalls:1"),
                              many0!(preceded!(tag!(";"), hex_value))) => {
                      |syscalls| Query::CatchSyscalls(Some(syscalls))
                  }
                  | preceded!(tag!("QPassSignals:"),
                              separated_nonempty_list_complete!(tag!(";"), hex_value)) => {
                      |signals| Query::PassSignals(signals)
                  }
                  | preceded!(tag!("QProgramSignals:"),
                              separated_nonempty_list_complete!(tag!(";"), hex_value)) => {
                      |signals| Query::ProgramSignals(signals)
                  }
                  | preceded!(tag!("qThreadExtraInfo,"), parse_thread_id) => {
                      |thread_id| Query::ThreadInfo(thread_id)
                  }
                  )
}

// TODO: should the caller be responsible for determining whether they actually
// wanted a u32, or should we provide different versions of this function with
// extra checking?
named!(hex_value<&[u8], u64>,
       map!(take_while1!(&nom::is_hex_digit),
            |hex| {
                let s = str::from_utf8(hex).unwrap();
                let r = u64::from_str_radix(s, 16);
                r.unwrap()
            }));

named!(hex_digit<&[u8], char>,
       one_of!("0123456789abcdefABCDEF"));

named!(hex_byte<&[u8], u8>,
       do_parse!(
           digit0: hex_digit >>
           digit1: hex_digit >>
           (((16 * digit0.to_digit(16).unwrap() + digit1.to_digit(16).unwrap())) as u8)
       )
);

named!(hex_byte_sequence<&[u8], Vec<u8>>,
       many1!(hex_byte));

named!(write_memory<&[u8], (u64, u64, Vec<u8>)>,
       complete!(do_parse!(
           tag!("M") >>
           address: hex_value >>
           tag!(",") >>
           length: hex_value >>
           tag!(":") >>
           data: hex_byte_sequence >>
           (address, length, data))));

named!(read_memory<&[u8], (u64, u64)>,
       preceded!(tag!("m"),
                 separated_pair!(hex_value,
                                 tag!(","),
                                 hex_value)));

named!(read_register<&[u8], u64>,
       preceded!(tag!("p"), hex_value));

named!(write_register<&[u8], (u64, Vec<u8>)>,
       preceded!(tag!("P"),
                 separated_pair!(hex_value,
                                 tag!("="),
                                 hex_byte_sequence)));

named!(write_general_registers<&[u8], Vec<u8>>,
       preceded!(tag!("G"), hex_byte_sequence));

/// Helper for parse_thread_id that parses a single thread-id element.
named!(parse_thread_id_element<&[u8], Id>,
       alt_complete!(tag!("0") => { |_| Id::Any }
                     | tag!("-1") => { |_| Id::All }
                     | hex_value => { |val: u64| Id::Id(val as u32) }));

/// Parse a thread-id.
named!(parse_thread_id<&[u8], ThreadId>,
       alt_complete!(parse_thread_id_element => { |pid| ThreadId { pid: pid, tid: Id::Any } }
                     | preceded!(tag!("p"),
                                 separated_pair!(parse_thread_id_element,
                                                 tag!("."),
                                                 parse_thread_id_element)) => {
                         |pair: (Id, Id)| ThreadId { pid: pair.0, tid: pair.1 }
                     }
                     | preceded!(tag!("p"), parse_thread_id_element) => {
                         |id: Id| ThreadId { pid: id, tid: Id::All }
                     }));

/// Parse the T packet.
named!(parse_ping_thread<&[u8], ThreadId>,
       preceded!(tag!("T"), parse_thread_id));

fn v_command<'a>(i: &'a [u8]) -> IResult<&'a [u8], Command<'a>> {
    alt_complete!(i,
                  tag!("vCtrlC") => { |_| Command::CtrlC }
                  | preceded!(tag!("vKill;"), hex_value) => {
                      |pid| Command::Kill(Some(pid))
                  }
                  // TODO: log the unknown command for debugging purposes.
                  | preceded!(tag!("v"), take_till!(|_| { false })) => {
                      |_| Command::UnknownVCommand
                  })
}

/// Parse the H packet.
named!(parse_h_packet<&[u8], ThreadId>,
       preceded!(tag!("Hg"), parse_thread_id));

/// Parse the D packet.
named!(parse_d_packet<&[u8], Option<u64>>,
       alt_complete!(preceded!(tag!("D;"), hex_value) => {
           |pid| Some(pid)
       }
       | tag!("D") => { |_| None }));

fn command<'a>(i: &'a [u8]) -> IResult<&'a [u8], Command<'a>> {
    alt!(i,
         tag!("!") => { |_|   Command::EnableExtendedMode }
         | tag!("?") => { |_| Command::TargetHaltReason }
         | parse_d_packet => { |pid| Command::Detach(pid) }
         | tag!("g") => { |_| Command::ReadGeneralRegisters }
         | write_general_registers => { |bytes| Command::WriteGeneralRegisters(bytes) }
         | parse_h_packet => { |thread_id| Command::SetCurrentThread(thread_id) }
         | tag!("k") => { |_| Command::Kill(None) }
         | read_memory => { |(addr, length)| Command::ReadMemory(addr, length) }
         | write_memory => { |(addr, length, bytes)| Command::WriteMemory(addr, length, bytes) }
         | read_register => { |regno| Command::ReadRegister(regno) }
         | write_register => { |(regno, bytes)| Command::WriteRegister(regno, bytes) }
         | query => { |q| Command::Query(q) }
         | tag!("r") => { |_| Command::Reset }
         | preceded!(tag!("R"), take!(2)) => { |_| Command::Reset }
         | parse_ping_thread => { |thread_id| Command::PingThread(thread_id) }
         | v_command => { |command| command }
    )
}

pub enum Error {
    // The meaning of the value is not defined by the protocol; so it
    // can be used by a handler for debugging.
    Error(u8),
    Unimplemented,
}

/// The `qAttached` packet lets the client distinguish between
/// attached and created processes, so that it knows whether to send a
/// detach request when disconnecting.
pub enum ProcessType {
    /// The process already existed and was attached to.
    Attached,
    /// The process was created by the server.
    Created,
}

/// The possible reasons for a thread to stop.
pub enum StopReason {
    /// Process stopped due to a signal.
    Signal(u8),
    /// The process with the given PID exited with the given status.
    Exited(u64, u8),
    /// The process with the given PID terminated due to the given
    /// signal.
    ExitedWithSignal(u64, u8),
    /// The indicated thread exited with the given status.
    ThreadExited(ThreadId, u64),
    /// There are no remaining resumed threads.
    // FIXME we should report the 'no-resumed' feature in response to
    // qSupports before emitting this; and we should also check that
    // the client knows about it.
    NoMoreThreads,
    // FIXME implement these as well.  These are used by the T packet,
    // which can also send along registers.
    // Watchpoint(u64),
    // ReadWatchpoint(u64),
    // AccessWatchpoint(u64),
    // SyscallEntry(u8),
    // SyscallExit(u8),
    // LibraryChange,
    // ReplayLogStart,
    // ReplayLogEnd,
    // SoftwareBreakpoint,
    // HardwareBreakpoint,
    // Fork(ThreadId),
    // VFork(ThreadId),
    // VForkDone,
    // Exec(String),
    // NewThread(ThreadId),
}

/// This trait should be implemented by servers.  Methods in the trait
/// generally default to returning `Error::Unimplemented`; but some
/// exceptions are noted below.  Methods that must be implemented in
/// order for the server to work at all do not have a default
/// implementation.
pub trait Handler {
    fn query_supported_features() {}

    /// Indicate whether the process in question already existed, and
    /// was attached to; or whether it was created by this server.
    fn attached(&self, _pid: Option<u64>) -> Result<ProcessType, Error>;

    /// Detach from the process.
    fn detach(&self, _pid: Option<u64>) -> Result<(), Error> {
        Err(Error::Unimplemented)
    }

    fn kill(&self, _pid: Option<u64>) -> Result<(), Error> {
        Err(Error::Unimplemented)
    }

    /// Check whether the indicated thread is alive.  If alive, return
    /// `()`.  Otherwise, return an error.
    fn ping_thread(&self, _id: ThreadId) -> Result<(), Error> {
        Err(Error::Unimplemented)
    }

    /// Read memory.  The address and number of bytes to read are
    /// provided.
    fn read_memory(&self, _address: u64, _length: u64) -> Result<Vec<u8>, Error> {
        Err(Error::Unimplemented)
    }

    /// Write the provided bytes to memory at the given address.
    fn write_memory(&self, _address: u64, _bytes: &[u8]) -> Result<(), Error> {
        Err(Error::Unimplemented)
    }

    /// Read the contents of the indicated register.  The results
    /// should be in target byte order.  Note that a value-based API
    /// is not provided here because on some architectures, there are
    /// registers wider than ordinary integer types.
    fn read_register(&self, _register: u64) -> Result<Vec<u8>, Error> {
        Err(Error::Unimplemented)
    }

    /// Set the contents of the indicated register to the given
    /// contents.  The contents are in target byte order.  Note that a
    /// value-based API is not provided here because on some
    /// architectures, there are registers wider than ordinary integer
    /// types.
    fn write_register(&self, _register: u64, _contents: &[u8]) -> Result<(), Error> {
        Err(Error::Unimplemented)
    }

    fn read_general_registers(&self) -> Result<Vec<u8>, Error> {
        Err(Error::Unimplemented)
    }

    fn write_general_registers(&self, _contents: &[u8]) -> Result<(), Error> {
        Err(Error::Unimplemented)
    }

    /// Return the identifier of the current thread.
    fn current_thread(&self) -> Result<Option<ThreadId>, Error> {
        Ok(None)
    }

    /// Set the current thread for future operations.
    fn set_current_thread(&self, _id: ThreadId) -> Result<(), Error> {
        Err(Error::Unimplemented)
    }

    /// Search memory.  The search begins at the given address, and
    /// ends after length bytes have been searched.  If the provided
    /// bytes are not seen, `None` should be returned; otherwise, the
    /// address at which the bytes were found should be returned.
    fn search_memory(&self, _address: u64, _length: u64, _bytes: &[u8])
                     -> Result<Option<u64>, Error> {
        Err(Error::Unimplemented)
    }

    /// Return the reason that the inferior has halted.
    fn halt_reason(&self) -> Result<StopReason, Error>;

    /// Invoke a command.  The command is just a sequence of bytes
    /// (typically ASCII characters), to be interpreted by the server
    /// in any way it likes.  The result is output to send back to the
    /// client.  This is used to implement gdb's `monitor` command.
    fn invoke(&self, &[u8]) -> Result<String, Error> {
        Err(Error::Unimplemented)
    }

    /// Enable or disable address space randomization.  This setting
    /// should be used when launching a new process.
    fn set_address_randomization(&self, _enable: bool) -> Result<(), Error> {
        Err(Error::Unimplemented)
    }

    /// Start or stop catch syscalls.  If the argument is `None`, then
    /// stop catchin syscalls.  Otherwise, start catching syscalls.
    /// If any syscalls are specified, then only those need be caught;
    /// however, it is ok to report syscall stops that aren't in the
    /// list if that is convenient.
    fn catch_syscalls(&self, _syscalls: Option<Vec<u64>>) -> Result<(), Error> {
        Err(Error::Unimplemented)
    }

    /// Set the list of "pass signals".  A signal marked as a pass
    /// signal can be delivered to the inferior.  No stopping or
    /// notification of the client is required.
    fn set_pass_signals(&self, _signals: Vec<u64>) -> Result<(), Error> {
        Ok(())
    }

    /// Set the list of "program signals".  A signal marked as a
    /// program signal can be delivered to the inferior; other signals
    /// should be silently discarded.
    fn set_program_signals(&self, _signals: Vec<u64>) -> Result<(), Error> {
        Ok(())
    }

    /// Return information about a given thread.  The returned
    /// information is just a string description that can be presented
    /// to the user.
    fn thread_info(&self, _thread: ThreadId) -> Result<String, Error> {
        Err(Error::Unimplemented)
    }
}

fn compute_checksum_incremental(bytes: &[u8], init: u8) -> u8 {
    bytes.iter().fold(init, |sum, &b| sum.wrapping_add(b))
}

enum Response<'a> {
    Empty,
    Ok,
    Error(u8),
    String(&'a str),
    StringAsString(String),
    Output(String),
    Bytes(Vec<u8>),
    CurrentThread(Option<ThreadId>),
    ProcessType(ProcessType),
    Stopped(StopReason),
    SearchResult(Option<u64>),
}

impl<'a, T> From<Result<T, Error>> for Response<'a>
    where Response<'a>: From<T>
{
    fn from(result: Result<T, Error>) -> Self {
        match result {
            Result::Ok(val) => val.into(),
            Result::Err(Error::Error(val)) => Response::Error(val),
            Result::Err(Error::Unimplemented) => Response::Empty,
        }
    }
}

impl<'a> From<()> for Response<'a>
{
    fn from(_: ()) -> Self {
        Response::Ok
    }
}

impl<'a> From<Vec<u8>> for Response<'a>
{
    fn from(response: Vec<u8>) -> Self {
        Response::Bytes(response)
    }
}

impl<'a> From<Option<ThreadId>> for Response<'a>
{
    fn from(response: Option<ThreadId>) -> Self {
        Response::CurrentThread(response)
    }
}

// This seems a bit specific -- what if some other handler method
// wants to return an Option<u64>?
impl<'a> From<Option<u64>> for Response<'a>
{
    fn from(response: Option<u64>) -> Self {
        Response::SearchResult(response)
    }
}

impl<'a> From<ProcessType> for Response<'a>
{
    fn from(process_type: ProcessType) -> Self {
        Response::ProcessType(process_type)
    }
}

impl<'a> From<StopReason> for Response<'a>
{
    fn from(reason: StopReason) -> Self {
        Response::Stopped(reason)
    }
}

impl<'a> From<String> for Response<'a>
{
    fn from(reason: String) -> Self {
        Response::StringAsString(reason)
    }
}

// A writer which sends a single packet.
struct PacketWriter<'a, W>
    where W: Write,
          W: 'a
{
    writer: &'a mut W,
    checksum: u8,
}

impl<'a, W> PacketWriter<'a, W>
    where W: Write
{
    fn new(writer: &'a mut W) -> PacketWriter<'a, W> {
        PacketWriter {
            writer: writer,
            checksum: 0,
        }
    }

    fn finish(&mut self) -> io::Result<()> {
        write!(self.writer, "#{:02x}", self.checksum)?;
        self.writer.flush()?;
        self.checksum = 0;
        Ok(())
    }
}

impl<'a, W> Write for PacketWriter<'a, W>
    where W: Write
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let count = self.writer.write(buf)?;
        self.checksum = compute_checksum_incremental(&buf[0..count], self.checksum);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

fn write_thread_id<W>(writer: &mut W, thread_id: ThreadId) -> io::Result<()>
    where W: Write
{
    write!(writer, "p")?;
    match thread_id.pid {
        Id::All => write!(writer, "-1"),
        Id::Any => write!(writer, "0"),
        Id::Id(num) => write!(writer, "{:x}", num),
    }?;
    write!(writer, ".")?;
    match thread_id.tid {
        Id::All => write!(writer, "-1"),
        Id::Any => write!(writer, "0"),
        Id::Id(num) => write!(writer, "{:x}", num),
    }
}

fn write_response<W>(response: Response, writer: &mut W) -> io::Result<()>
    where W: Write,
{
    write!(writer, "$")?;

    let mut writer = PacketWriter::new(writer);
    match response {
        Response::Ok => {
            write!(writer, "OK")?;
        }
        Response::Empty => {
        }
        Response::Error(val) => {
            write!(writer, "E{:02x}", val)?;
        }
        Response::String(s) => {
            write!(writer, "{}", s)?;
        }
        Response::StringAsString(s) => {
            write!(writer, "{}", s)?;
        }
        Response::Output(s) => {
            write!(writer, "O")?;
            for byte in s.as_bytes() {
                write!(writer, "{:02x}", byte)?;
            }
        }
        Response::Bytes(bytes) => {
            for byte in bytes {
                write!(writer, "{:02x}", byte)?;
            }
        }
        Response::CurrentThread(tid) => {
            // This is incorrect if multiprocess hasn't yet been enabled.
            match tid {
                None => write!(writer, "OK")?,
                Some(thread_id) => {
                    write!(writer, "QC")?;
                    write_thread_id(&mut writer, thread_id)?;
                }
            };
        }
        Response::ProcessType(process_type) => {
            match process_type {
                ProcessType::Attached => write!(writer, "1")?,
                ProcessType::Created => write!(writer, "0")?,
            };
        }
        Response::SearchResult(maybe_addr) => {
            match maybe_addr {
                Some(addr) => write!(writer, "1,{:x}", addr)?,
                None => write!(writer, "0")?,
            }
        }
        Response::Stopped(stop_reason) => {
            match stop_reason {
                StopReason::Signal(signo) => write!(writer, "S{:02x}", signo)?,
                StopReason::Exited(pid, status) => {
                    // Non-multi-process gdb only accepts 2 hex digits
                    // for the status.
                    write!(writer, "W{:02x};process:{:x}", status, pid)?;
                },
                StopReason::ExitedWithSignal(pid, status) => {
                    // Non-multi-process gdb only accepts 2 hex digits
                    // for the status.
                    write!(writer, "X{:x};process:{:x}", status, pid)?;
                },
                StopReason::ThreadExited(thread_id, status) => {
                    write!(writer, "w{:x};", status)?;
                    write_thread_id(&mut writer, thread_id)?;
                },
                StopReason::NoMoreThreads => write!(writer, "N")?,
            }
        }
    }

    writer.finish()
}

fn handle_supported_features<'a, H>(_handler: &H, _features: &Vec<GDBFeatureSupported<'a>>) -> Response<'static>
    where H: Handler,
{
    Response::String(concat!("PacketSize=65536;QStartNoAckMode+;multiprocess+;QDisableRandomization+",
                             ";QCatchSyscalls+;QPassSignals+;QProgramSignals+"))
}

/// Handle a single packet `data` with `handler` and write a response to `writer`.
fn handle_packet<H, W>(data: &[u8],
                       handler: &H,
                       writer: &mut W) -> io::Result<bool>
    where H: Handler,
          W: Write,
{
    println!("Command: {}", str::from_utf8(data).unwrap());
    let mut no_ack_mode = false;
    let response = if let Done(_, command) = command(data) {
        match command {
            // We unconditionally support extended mode.
            Command::EnableExtendedMode => Response::Ok,
            Command::TargetHaltReason => {
                handler.halt_reason().into()
            },
            Command::ReadGeneralRegisters => {
                handler.read_general_registers().into()
            },
            Command::WriteGeneralRegisters(bytes) => {
                handler.write_general_registers(&bytes[..]).into()
            },
            Command::Kill(None) => {
                // The k packet requires no response, so purposely
                // ignore the result.
                drop(handler.kill(None));
                Response::Empty
            },
            Command::Kill(pid) => {
                handler.kill(pid).into()
            },
            Command::Reset => Response::Empty,
            Command::ReadRegister(regno) => {
                handler.read_register(regno).into()
            },
            Command::WriteRegister(regno, bytes) => {
                handler.write_register(regno, &bytes[..]).into()
            },
            Command::ReadMemory(address, length) => {
                handler.read_memory(address, length).into()
            },
            Command::WriteMemory(address, length, bytes) => {
                // The docs don't really say what to do if the given
                // length disagrees with the number of bytes sent, so
                // just error if they disagree.
                if length as usize != bytes.len() {
                    Response::Error(1)
                } else {
                    handler.write_memory(address, &bytes[..]).into()
                }
            },
            Command::SetCurrentThread(thread_id) => {
                handler.set_current_thread(thread_id).into()
            },
            Command::Detach(pid) => {
                handler.detach(pid).into()
            },

            Command::Query(Query::Attached(pid)) => {
                handler.attached(pid).into()
            },
            Command::Query(Query::CurrentThread) => {
                handler.current_thread().into()
            },
            Command::Query(Query::Invoke(cmd)) => {
                match handler.invoke(&cmd[..]) {
                    Result::Ok(val) => {
                        if val.len() == 0 {
                            Response::Ok
                        } else {
                            Response::Output(val)
                        }
                    },
                    Result::Err(Error::Error(val)) => Response::Error(val),
                    Result::Err(Error::Unimplemented) => Response::Empty,
                }
            },
            Command::Query(Query::SearchMemory { address, length, bytes }) => {
                handler.search_memory(address, length, &bytes[..]).into()
            },
            Command::Query(Query::SupportedFeatures(features)) =>
                handle_supported_features(handler, &features),
            Command::Query(Query::StartNoAckMode) => {
                no_ack_mode = true;
                Response::Ok
            }
            Command::Query(Query::AddressRandomization(randomize)) => {
                handler.set_address_randomization(randomize).into()
            }
            Command::Query(Query::CatchSyscalls(calls)) => {
                handler.catch_syscalls(calls).into()
            }
            Command::Query(Query::PassSignals(signals)) => {
                handler.set_pass_signals(signals).into()
            }
            Command::Query(Query::ProgramSignals(signals)) => {
                handler.set_program_signals(signals).into()
            }
            Command::Query(Query::ThreadInfo(thread_info)) => {
                handler.thread_info(thread_info).into()
            }

            Command::PingThread(thread_id) => handler.ping_thread(thread_id).into(),
            // Empty means "not implemented".
            Command::CtrlC => Response::Empty,

            // Unknown v commands are required to give an empty
            // response.
            Command::UnknownVCommand => Response::Empty,
        }
    } else { Response::Empty };
    write_response(response, writer)?;
    Ok(no_ack_mode)
}

fn offset(from: &[u8], to: &[u8]) -> usize {
    let fst = from.as_ptr();
    let snd = to.as_ptr();

    snd as usize - fst as usize
}

fn run_parser(buf: &[u8]) -> Option<(usize, Packet)> {
    if let Done(rest, packet) = packet_or_response(buf) {
        Some((offset(buf, rest), packet))
    } else {
        None
    }
}

/// Read gdbserver packets from `reader` and call methods on `handler` to handle them and write
/// responses to `writer`.
pub fn process_packets_from<R, W, H>(reader: R,
                                     mut writer: W,
                                     handler: H)
    where R: Read,
          W: Write,
          H: Handler
{
    let mut bufreader = BufReader::with_capacity(MAX_PACKET_SIZE, reader);
    let mut done = false;
    let mut ack_mode = true;
    while !done {
        let length = if let Ok(buf) = bufreader.fill_buf() {
            if buf.len() == 0 {
                done = true;
            }
            if let Some((len, packet)) = run_parser(buf) {
                match packet {
                    Packet::Data(ref data, ref _checksum) => {
                        // Write an ACK
                        if ack_mode && !writer.write_all(&b"+"[..]).is_ok() {
                            //TODO: propagate errors to caller?
                            return;
                        }
                        let no_ack_mode = handle_packet(&data, &handler, &mut writer).unwrap_or(false);
                        if no_ack_mode {
                            ack_mode = false;
                        }
                    },
                    // Just ignore ACK/NACK/Interrupt
                    _ => {},
                };
                len
            } else {
                0
            }
        } else {
            // Error reading
            done = true;
            0
        };
        bufreader.consume(length);
    }
}

#[test]
fn test_compute_checksum() {
    assert_eq!(compute_checksum_incremental(&b""[..], 0), 0);
    assert_eq!(compute_checksum_incremental(&b"qSupported:multiprocess+;xmlRegisters=i386;qRelocInsn+"[..],
                                0),
               0xb5);
}

#[test]
fn test_checksum() {
    assert_eq!(checksum(&b"00"[..]), Done(&b""[..], 0));
    assert_eq!(checksum(&b"a1"[..]), Done(&b""[..], 0xa1));
    assert_eq!(checksum(&b"1d"[..]), Done(&b""[..], 0x1d));
    assert_eq!(checksum(&b"ff"[..]), Done(&b""[..], 0xff));
}

#[test]
fn test_packet() {
    use nom::Needed;
    assert_eq!(packet(&b"$#00"[..]), Done(&b""[..], (b""[..].to_vec(), 0)));
    assert_eq!(packet(&b"$xyz#00"[..]), Done(&b""[..], (b"xyz"[..].to_vec(), 0)));
    assert_eq!(packet(&b"$a#a1"[..]), Done(&b""[..], (b"a"[..].to_vec(), 0xa1)));
    assert_eq!(packet(&b"$foo#ffxyz"[..]), Done(&b"xyz"[..], (b"foo"[..].to_vec(), 0xff)));
    assert_eq!(packet(&b"$qSupported:multiprocess+;xmlRegisters=i386;qRelocInsn+#b5"[..]),
               Done(&b""[..],
                    (b"qSupported:multiprocess+;xmlRegisters=i386;qRelocInsn+"[..].to_vec(),
                     0xb5)));
    assert_eq!(packet(&b"$"[..]), Incomplete(Needed::Size(2)));
    assert_eq!(packet(&b"$#"[..]), Incomplete(Needed::Size(4)));
    assert_eq!(packet(&b"$xyz"[..]), Incomplete(Needed::Size(5)));
    assert_eq!(packet(&b"$xyz#"[..]), Incomplete(Needed::Size(7)));
    assert_eq!(packet(&b"$xyz#a"[..]), Incomplete(Needed::Size(7)));
}

#[test]
fn test_packet_or_response() {
    assert_eq!(packet_or_response(&b"$#00"[..]), Done(&b""[..], Packet::Data(b""[..].to_vec(), 0)));
    assert_eq!(packet_or_response(&b"+"[..]), Done(&b""[..], Packet::Ack));
    assert_eq!(packet_or_response(&b"-"[..]), Done(&b""[..], Packet::Nack));
}

#[test]
fn test_gdbfeaturesupported() {
    assert_eq!(gdbfeaturesupported(&b"multiprocess+"[..]),
               Done(&b""[..], GDBFeatureSupported(Known::Yes(GDBFeature::multiprocess),
                                                  FeatureSupported::Yes)));
    assert_eq!(gdbfeaturesupported(&b"xmlRegisters=i386"[..]),
               Done(&b""[..], GDBFeatureSupported(Known::Yes(GDBFeature::xmlRegisters),
                                                  FeatureSupported::Value("i386"))));
    assert_eq!(gdbfeaturesupported(&b"qRelocInsn-"[..]),
               Done(&b""[..], GDBFeatureSupported(Known::Yes(GDBFeature::qRelocInsn),
                                                  FeatureSupported::No)));
    assert_eq!(gdbfeaturesupported(&b"vfork-events+"[..]),
               Done(&b""[..], GDBFeatureSupported(Known::Yes(GDBFeature::vfork_events),
                                                  FeatureSupported::Yes)));
    assert_eq!(gdbfeaturesupported(&b"vfork-events-"[..]),
               Done(&b""[..], GDBFeatureSupported(Known::Yes(GDBFeature::vfork_events),
                                                  FeatureSupported::No)));
    assert_eq!(gdbfeaturesupported(&b"unknown-feature+"[..]),
               Done(&b""[..], GDBFeatureSupported(Known::No("unknown-feature"),
                                                  FeatureSupported::Yes)));
    assert_eq!(gdbfeaturesupported(&b"unknown-feature-"[..]),
               Done(&b""[..], GDBFeatureSupported(Known::No("unknown-feature"),
                                                  FeatureSupported::No)));
}

#[test]
fn test_gdbfeature() {
    assert_eq!(gdbfeature(&b"multiprocess"[..]),
               Done(&b""[..], Known::Yes(GDBFeature::multiprocess)));
    assert_eq!(gdbfeature(&b"fork-events"[..]),
               Done(&b""[..], Known::Yes(GDBFeature::fork_events)));
    assert_eq!(gdbfeature(&b"some-unknown-feature"[..]),
               Done(&b""[..], Known::No("some-unknown-feature")));
}

#[test]
fn test_query() {
    // From a gdbserve packet capture.
    let b = concat!("qSupported:multiprocess+;swbreak+;hwbreak+;qRelocInsn+;fork-events+;",
                    "vfork-events+;exec-events+;vContSupported+;QThreadEvents+;no-resumed+;",
                    "xmlRegisters=i386");
    assert_eq!(query(b.as_bytes()),
               Done(&b""[..], Query::SupportedFeatures(vec![
                   GDBFeatureSupported(Known::Yes(GDBFeature::multiprocess), FeatureSupported::Yes),
                   GDBFeatureSupported(Known::Yes(GDBFeature::swbreak), FeatureSupported::Yes),
                   GDBFeatureSupported(Known::Yes(GDBFeature::hwbreak), FeatureSupported::Yes),
                   GDBFeatureSupported(Known::Yes(GDBFeature::qRelocInsn), FeatureSupported::Yes),
                   GDBFeatureSupported(Known::Yes(GDBFeature::fork_events), FeatureSupported::Yes),
                   GDBFeatureSupported(Known::Yes(GDBFeature::vfork_events), FeatureSupported::Yes),
                   GDBFeatureSupported(Known::Yes(GDBFeature::exec_events), FeatureSupported::Yes),
                   GDBFeatureSupported(Known::Yes(GDBFeature::vContSupported),
                                       FeatureSupported::Yes),
                   GDBFeatureSupported(Known::Yes(GDBFeature::QThreadEvents),
                                       FeatureSupported::Yes),
                   GDBFeatureSupported(Known::Yes(GDBFeature::no_resumed), FeatureSupported::Yes),
                   GDBFeatureSupported(Known::Yes(GDBFeature::xmlRegisters),
                                       FeatureSupported::Value("i386")),
                   ])));
}

#[test]
fn test_hex_value() {
    assert_eq!(hex_value(&b""[..]), Incomplete(Needed::Size(1)));
    assert_eq!(hex_value(&b","[..]), Error(nom::ErrorKind::TakeWhile1));
    assert_eq!(hex_value(&b"a"[..]), Done(&b""[..], 0xa));
    assert_eq!(hex_value(&b"10,"[..]), Done(&b","[..], 0x10));
    assert_eq!(hex_value(&b"ff"[..]), Done(&b""[..], 0xff));
}

#[test]
fn test_parse_thread_id_element() {
    assert_eq!(parse_thread_id_element(&b"0"[..]), Done(&b""[..], Id::Any));
    assert_eq!(parse_thread_id_element(&b"-1"[..]), Done(&b""[..], Id::All));
    assert_eq!(parse_thread_id_element(&b"23"[..]), Done(&b""[..], Id::Id(0x23)));
}

#[test]
fn test_parse_thread_id() {
    assert_eq!(parse_thread_id(&b"0"[..]),
               Done(&b""[..], ThreadId{pid: Id::Any, tid: Id::Any}));
    assert_eq!(parse_thread_id(&b"-1"[..]),
               Done(&b""[..], ThreadId{pid: Id::All, tid: Id::Any}));
    assert_eq!(parse_thread_id(&b"23"[..]),
               Done(&b""[..], ThreadId{pid: Id::Id(0x23), tid: Id::Any}));

    assert_eq!(parse_thread_id(&b"p23"[..]),
               Done(&b""[..], ThreadId{pid: Id::Id(0x23), tid: Id::All}));

    assert_eq!(parse_thread_id(&b"p0.0"[..]),
               Done(&b""[..], ThreadId{pid: Id::Any, tid: Id::Any}));
    assert_eq!(parse_thread_id(&b"p-1.23"[..]),
               Done(&b""[..], ThreadId{pid: Id::All, tid: Id::Id(0x23)}));
    assert_eq!(parse_thread_id(&b"pff.23"[..]),
               Done(&b""[..], ThreadId{pid: Id::Id(0xff), tid: Id::Id(0x23)}));
}

#[test]
fn test_parse_v_commands() {
    assert_eq!(v_command(&b"vKill;33"[..]),
               Done(&b""[..], Command::Kill(Some(0x33))));
    assert_eq!(v_command(&b"vCtrlC"[..]),
               Done(&b""[..], Command::CtrlC));
    assert_eq!(v_command(&b"vMustReplyEmpty"[..]),
               Done(&b""[..], Command::UnknownVCommand));
    assert_eq!(v_command(&b"vFile:close:0"[..]),
               Done(&b""[..], Command::UnknownVCommand));
}

#[test]
fn test_parse_d_packets() {
    assert_eq!(parse_d_packet(&b"D"[..]),
               Done(&b""[..], None));
    assert_eq!(parse_d_packet(&b"D;f0"[..]),
               Done(&b""[..], Some(240)));
}

#[test]
fn test_parse_write_memory() {
    assert_eq!(write_memory(&b"Mf0,3:ff0102"[..]),
               Done(&b""[..], (240, 3, vec!(255, 1, 2))));
}

#[test]
fn test_parse_qrcmd() {
    assert_eq!(query(&b"qRcmd,736f6d657468696e67"[..]),
               Done(&b""[..], Query::Invoke(b"something".to_vec())));
}

#[test]
fn test_parse_randomization() {
    assert_eq!(query(&b"QDisableRandomization:0"[..]),
               Done(&b""[..], Query::AddressRandomization(true)));
    assert_eq!(query(&b"QDisableRandomization:1"[..]),
               Done(&b""[..], Query::AddressRandomization(false)));
}

#[test]
fn test_parse_syscalls() {
    assert_eq!(query(&b"QCatchSyscalls:0"[..]),
               Done(&b""[..], Query::CatchSyscalls(None)));
    assert_eq!(query(&b"QCatchSyscalls:1"[..]),
               Done(&b""[..], Query::CatchSyscalls(Some(vec!()))));
    assert_eq!(query(&b"QCatchSyscalls:1;0;1;ff"[..]),
               Done(&b""[..], Query::CatchSyscalls(Some(vec!(0, 1, 255)))));
}

#[test]
fn test_parse_signals() {
    assert_eq!(query(&b"QPassSignals:0"[..]),
               Done(&b""[..], Query::PassSignals(vec!(0))));
    assert_eq!(query(&b"QPassSignals:1;2;ff"[..]),
               Done(&b""[..], Query::PassSignals(vec!(1, 2, 255))));
    assert_eq!(query(&b"QProgramSignals:0"[..]),
               Done(&b""[..], Query::ProgramSignals(vec!(0))));
    assert_eq!(query(&b"QProgramSignals:1;2;ff"[..]),
               Done(&b""[..], Query::ProgramSignals(vec!(1, 2, 255))));
}

#[test]
fn test_thread_info() {
    assert_eq!(query(&b"qThreadExtraInfo,ffff"[..]),
               Done(&b""[..], Query::ThreadInfo(ThreadId { pid: Id::Id(65535), tid: Id::Any })));
}

#[test]
fn test_parse_write_register() {
    assert_eq!(write_register(&b"Pff=1020"[..]),
               Done(&b""[..], (255, vec!(16, 32))));
}

#[test]
fn test_parse_write_general_registers() {
    assert_eq!(write_general_registers(&b"G0001020304"[..]),
               Done(&b""[..], vec!(0, 1, 2, 3, 4)));
}

#[test]
fn test_write_response() {
    fn write_one(input: Response) -> io::Result<String> {
        let mut result = Vec::new();
        write_response(input, &mut result)?;
        Ok(String::from_utf8(result).unwrap())
    }

    assert_eq!(write_one(Response::Empty).unwrap(), "$#00");
    assert_eq!(write_one(Response::Ok).unwrap(), "$OK#9a");
    assert_eq!(write_one(Response::Error(1)).unwrap(), "$E01#a6");

    assert_eq!(write_one(Response::CurrentThread(Some(ThreadId {
        pid: Id::Id(255),
        tid: Id::Id(1)
    }))).unwrap(),
               "$QCpff.1#2f");
}
