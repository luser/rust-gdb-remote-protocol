//! An implementation of the server side of the GDB Remote Serial
//! Protocol -- the protocol used by GDB and LLDB to talk to remote
//! targets.
//!
//! This library attempts to hide many of the protocol warts from
//! server implementations.  It is also mildly opinionated, in that it
//! implements certain features itself and requires users of the
//! library to conform.  For example, it unconditionally implements
//! the multiprocess and non-stop modes.
//!
//! ## Protocol Documentation
//!
//! * [Documentation of the protocol](https://sourceware.org/gdb/onlinedocs/gdb/Remote-Protocol.html)
//! * [LLDB extensions](https://github.com/llvm-mirror/lldb/blob/master/docs/lldb-gdb-remote.txt)

#![deny(missing_docs)]

#[macro_use]
extern crate bitflags;
extern crate byteorder;
#[macro_use]
extern crate nom;
extern crate strum;
#[macro_use]
extern crate strum_macros;

use nom::IResult::*;
use nom::{IResult, Needed};
use std::borrow::Cow;
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

/// A descriptor for a watchpoint.  The particular semantics of the watchpoint
/// (watching memory for read or write access) are addressed elsewhere.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Watchpoint {
    /// The address.
    pub addr: u64,

    /// The number of bytes covered.
    pub n_bytes: u64,
}

impl Watchpoint {
    fn new(addr: u64, n_bytes: u64) -> Watchpoint {
        Watchpoint{addr, n_bytes}
    }
}

/// Target-specific bytecode.
#[derive(Clone, Debug, PartialEq)]
pub struct Bytecode {
    /// The bytecodes.
    pub bytecode: Vec<u8>
}

/// A descriptor for a breakpoint.  The particular implementation technique
/// of the breakpoint, hardware or software, is handled elsewhere.
#[derive(Clone, Debug, PartialEq)]
pub struct Breakpoint {
    /// The address.
    pub addr: u64,

    /// The kind of breakpoint.  This field is generally 0 and its
    /// interpretation is target-specific.  A typical use of it is for
    /// targets that support multiple execution modes (e.g. ARM/Thumb);
    /// different values for this field would identify the kind of code
    /// region in which the breakpoint is being inserted.
    pub kind: u64,

    /// An optional list of target-specific bytecodes representing
    /// conditions.  Each condition should be evaluated by the target when
    /// the breakpoint is hit to determine whether the hit should be reported
    /// back to the debugger.
    pub conditions: Option<Vec<Bytecode>>,

    /// An optional list of target-specific bytecodes representing commands.
    /// These commands should be evaluated when a breakpoint is hit; any
    /// results are not reported back to the debugger.
    pub commands: Option<Vec<Bytecode>>,
}

impl Breakpoint {
    fn new(addr: u64, kind: u64, conditions: Option<Vec<Bytecode>>,
           commands: Option<Vec<Bytecode>>) -> Breakpoint {
        Breakpoint{addr, kind, conditions, commands}
    }
}

/// A descriptor for a region of memory.
#[derive(Clone, Debug, PartialEq)]
pub struct MemoryRegion {
    /// The base address.
    pub address: u64,
    /// The length.
    pub length: u64,
}

impl MemoryRegion {
    fn new(address: u64, length: u64) -> MemoryRegion {
        MemoryRegion{address, length}
    }
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
    ReadMemory(MemoryRegion),
    // Write specified region of memory.
    WriteMemory(MemoryRegion, Vec<u8>),
    Query(Query<'a>),
    Reset,
    PingThread(ThreadId),
    CtrlC,
    UnknownVCommand,
    /// Set the current thread for future commands, such as `ReadRegister`.
    SetCurrentThread(ThreadId),
    /// Insert a software breakpoint.
    InsertSoftwareBreakpoint(Breakpoint),
    /// Insert a hardware breakpoint
    InsertHardwareBreakpoint(Breakpoint),
    /// Insert a write watchpoint.
    InsertWriteWatchpoint(Watchpoint),
    /// Insert a read watchpoint.
    InsertReadWatchpoint(Watchpoint),
    /// Insert an access watchpoint.
    InsertAccessWatchpoint(Watchpoint),
    /// Remove a software breakpoint.
    RemoveSoftwareBreakpoint(Breakpoint),
    /// Remove a hardware breakpoint.
    RemoveHardwareBreakpoint(Breakpoint),
    /// Remove a write watchpoint.
    RemoveWriteWatchpoint(Watchpoint),
    /// Remove a read watchpoint.
    RemoveReadWatchpoint(Watchpoint),
    /// Remove an access watchpoint.
    RemoveAccessWatchpoint(Watchpoint),
    /// Open a file on the remote stub's filesystem.
    /// TODO structured values for the flags and mode.
    HostOpen(Vec<u8>, u64, u64),
    /// Close an open filehandle from the remote stub's filesystem.
    HostClose(u64),
    /// Read data from an open filehandle from the remote stub's filesystem.
    HostPRead(u64, u64, u64),
    /// Write data to an open filehandle from the remote stub's filesystem.
    HostPWrite(u64, u64, Vec<u8>),
    /// Stat an open filehandle from the remote stub's filesystem.
    HostFStat(u64),
    /// Delete a file on the remote stub's filesystem.
    HostUnlink(Vec<u8>),
    /// Read a symbolic link on the remote stub's filesystem.
    HostReadlink(Vec<u8>),
    /// Set the filesystem for subsequent Host I/O operations, such as `HostOpen`.
    HostSetFS(u64),
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

named!(binary_byte<&[u8], u8>,
       alt_complete!(
           preceded!(tag!("}"), take!(1)) => { |b: &[u8]| b[0] ^ 0x20 } |
           take!(1) => { |b: &[u8]| b[0] }));

named!(binary_byte_sequence<&[u8], Vec<u8>>,
       many1!(binary_byte));

named!(write_memory_binary<&[u8], (u64, u64, Vec<u8>)>,
       complete!(do_parse!(
           tag!("X") >>
           address: hex_value >>
           tag!(",") >>
           length: hex_value >>
           tag!(":") >>
           data: binary_byte_sequence >>
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

fn parse_vfile_open<'a>(i: &'a [u8]) -> IResult<&'a [u8], Command<'a>> {
    println!("attempting vfile open! {:?}", i);
    do_parse!(i,
              tag!("open:") >>
              filename: hex_byte_sequence >>
              tag!(",") >>
              flags: hex_value >>
              tag!(",") >>
              mode: hex_value >>
              (Command::HostOpen(filename, flags, mode)))
}

fn parse_vfile_close<'a>(i: &'a [u8]) -> IResult<&'a [u8], Command<'a>> {
    do_parse!(i,
              tag!("close:") >>
              fd: hex_value >>
              (Command::HostClose(fd)))
}

fn parse_vfile_pread<'a>(i: &'a [u8]) -> IResult<&'a [u8], Command<'a>> {
    do_parse!(i,
              tag!("pread:") >>
              fd: hex_value >>
              tag!(",") >>
              count: hex_value >>
              tag!(",") >>
              offset: hex_value >>
              (Command::HostPRead(fd, count, offset)))
}

fn parse_vfile_pwrite<'a>(i: &'a [u8]) -> IResult<&'a [u8], Command<'a>> {
    do_parse!(i,
              tag!("pwrite:") >>
              fd: hex_value >>
              tag!(",") >>
              offset: hex_value >>
              tag!(",") >>
              data: binary_byte_sequence >>
              (Command::HostPWrite(fd, offset, data)))
}

fn parse_vfile_fstat<'a>(i: &'a [u8]) -> IResult<&'a [u8], Command<'a>> {
    do_parse!(i,
              tag!("fstat:") >>
              fd: hex_value >>
              (Command::HostFStat(fd)))
}

fn parse_vfile_unlink<'a>(i: &'a [u8]) -> IResult<&'a [u8], Command<'a>> {
    do_parse!(i,
              tag!("unlink:") >>
              filename: hex_byte_sequence >>
              (Command::HostUnlink(filename)))
}

fn parse_vfile_readlink<'a>(i: &'a [u8]) -> IResult<&'a [u8], Command<'a>> {
    do_parse!(i,
              tag!("readlink:") >>
              filename: hex_byte_sequence >>
              (Command::HostReadlink(filename)))
}

fn parse_vfile_setfs<'a>(i: &'a [u8]) -> IResult<&'a [u8], Command<'a>> {
    do_parse!(i,
              tag!("setfs:") >>
              pid: hex_value >>
              (Command::HostSetFS(pid)))
}

fn parse_unknown_vfile_op<'a>(i: &'a [u8]) -> IResult<&'a [u8], Command<'a>> {
    // TODO: log the unknown operation for debugging purposes.
    map!(i, take_till!(|_| { false}), { |_: &[u8]| Command::UnknownVCommand })
}

fn parse_vfile_op<'a>(i: &'a [u8]) -> IResult<&'a [u8], Command<'a>> {
    alt_complete!(i,
                  parse_vfile_open |
                  parse_vfile_close |
                  parse_vfile_pread |
                  parse_vfile_pwrite |
                  parse_vfile_fstat |
                  parse_vfile_unlink |
                  parse_vfile_readlink |
                  parse_vfile_setfs |
                  parse_unknown_vfile_op)
}

fn v_command<'a>(i: &'a [u8]) -> IResult<&'a [u8], Command<'a>> {
    alt_complete!(i,
                  tag!("vCtrlC") => { |_| Command::CtrlC }
                  | preceded!(tag!("vKill;"), hex_value) => {
                      |pid| Command::Kill(Some(pid))
                  }
                  | preceded!(tag!("vFile:"), parse_vfile_op) => {
                      |c| c
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

#[derive(Copy, Clone)]
enum ZAction {
    Insert,
    Remove,
}

named!(parse_z_action<&[u8], ZAction>,
       alt_complete!(tag!("z") => { |_| ZAction::Remove } |
                     tag!("Z") => { |_| ZAction::Insert }));

#[derive(Copy, Clone)]
enum ZType {
    SoftwareBreakpoint,
    HardwareBreakpoint,
    WriteWatchpoint,
    ReadWatchpoint,
    AccessWatchpoint,
}

named!(parse_z_type<&[u8], ZType>,
       alt_complete!(tag!("0") => { |_| ZType::SoftwareBreakpoint } |
                     tag!("1") => { |_| ZType::HardwareBreakpoint } |
                     tag!("2") => { |_| ZType::WriteWatchpoint } |
                     tag!("3") => { |_| ZType::ReadWatchpoint } |
                     tag!("4") => { |_| ZType::AccessWatchpoint }));

named!(parse_cond_or_command_expression<&[u8], Bytecode>,
       do_parse!(tag!("X") >>
                 len: hex_value >>
                 tag!(",") >>
                 expr: take!(len) >>
                 (Bytecode { bytecode: expr.to_vec() })));

named!(parse_condition_list<&[u8], Vec<Bytecode>>,
       do_parse!(tag!(";") >>
                 list: many1!(parse_cond_or_command_expression) >>
                 (list)));

fn maybe_condition_list<'a>(i: &'a[u8]) -> IResult<&'a [u8], Option<Vec<Bytecode>>> {
    // An Incomplete here really means "not enough input to match a
    // condition list", and that's OK.  An Error is *probably* that the
    // input contains a command list rather than a condition list; the
    // two are identical in their first character.  So just ignore that
    // FIXME.
    match parse_condition_list(i) {
        Done(rest, v) => Done(rest, Some(v)),
        Incomplete(_i) => Done(i, None),
        Error(_) => Done(i, None),
    }
}

named!(parse_command_list<&[u8], Vec<Bytecode>>,
       // FIXME we drop the persistence flag here. 
       do_parse!(tag!(";cmds") >>
                 list: alt_complete!(do_parse!(persist_flag: hex_value >>
                                               tag!(",") >>
                                               cmd_list: many1!(parse_cond_or_command_expression) >>
                                               (cmd_list)) |
                                     many1!(parse_cond_or_command_expression)) >>
                 (list)));

fn maybe_command_list<'a>(i: &'a[u8]) -> IResult<&'a [u8], Option<Vec<Bytecode>>> {
    // An Incomplete here really means "not enough input to match a
    // command list", and that's OK.
    match parse_command_list(i) {
        Done(rest, v) => Done(rest, Some(v)),
        Incomplete(_i) => Done(i, None),
        Error(e) => Error(e),
    }
}

named!(parse_cond_and_command_list<&[u8], (Option<Vec<Bytecode>>,
                                           Option<Vec<Bytecode>>)>,
       do_parse!(cond_list: maybe_condition_list >>
                 cmd_list: maybe_command_list >>
                 (cond_list, cmd_list)));

fn parse_z_packet<'a>(i: &'a [u8]) -> IResult<&'a [u8], Command<'a>> {
    let (rest, (action, type_, addr, kind)) = try_parse!(i, do_parse!(
                                                      action: parse_z_action >>
                                                      type_: parse_z_type >>
                                                      tag!(",") >>
                                                      addr: hex_value >>
                                                      tag!(",") >>
                                                      kind: hex_value >>
                                                      (action, type_, addr, kind)));

    return match action {
        ZAction::Insert => {
            insert_command(rest, type_, addr, kind)
        },
        ZAction::Remove => {
            Done(rest, remove_command(type_, addr, kind))
        }
    };

    fn insert_command<'a>(rest: &'a [u8], type_: ZType, addr: u64, kind: u64) -> IResult<&'a [u8], Command<'a>> {
        match type_ {
            // Software and hardware breakpoints both permit optional condition
            // lists and commands that are evaluated on the target when
            // breakpoints are hit.
            ZType::SoftwareBreakpoint | ZType::HardwareBreakpoint => {
                let (rest, (cond_list, cmd_list)) = parse_cond_and_command_list(rest).unwrap();
                let c = (match type_ {
                    ZType::SoftwareBreakpoint => Command::InsertSoftwareBreakpoint,
                    ZType::HardwareBreakpoint => Command::InsertHardwareBreakpoint,
                    // Satisfy rustc's checking
                    _ => panic!("cannot get here"),
                })(Breakpoint::new(addr, kind, cond_list, cmd_list));
                Done(rest, c)
            },
            ZType::WriteWatchpoint => Done(rest, Command::InsertWriteWatchpoint(Watchpoint::new(addr, kind))),
            ZType::ReadWatchpoint => Done(rest, Command::InsertReadWatchpoint(Watchpoint::new(addr, kind))),
            ZType::AccessWatchpoint => Done(rest, Command::InsertAccessWatchpoint(Watchpoint::new(addr, kind))),
        }
    }

    fn remove_command<'a>(type_: ZType, addr: u64, kind: u64) -> Command<'a> {
        match type_ {
            ZType::SoftwareBreakpoint => Command::RemoveSoftwareBreakpoint(Breakpoint::new(addr, kind, None, None)),
            ZType::HardwareBreakpoint => Command::RemoveHardwareBreakpoint(Breakpoint::new(addr, kind, None, None)),
            ZType::WriteWatchpoint => Command::RemoveWriteWatchpoint(Watchpoint::new(addr, kind)),
            ZType::ReadWatchpoint => Command::RemoveReadWatchpoint(Watchpoint::new(addr, kind)),
            ZType::AccessWatchpoint => Command::RemoveAccessWatchpoint(Watchpoint::new(addr, kind)),
        }
    }
}

fn command<'a>(i: &'a [u8]) -> IResult<&'a [u8], Command<'a>> {
    alt!(i,
         tag!("!") => { |_|   Command::EnableExtendedMode }
         | tag!("?") => { |_| Command::TargetHaltReason }
         | parse_d_packet => { |pid| Command::Detach(pid) }
         | tag!("g") => { |_| Command::ReadGeneralRegisters }
         | write_general_registers => { |bytes| Command::WriteGeneralRegisters(bytes) }
         | parse_h_packet => { |thread_id| Command::SetCurrentThread(thread_id) }
         | tag!("k") => { |_| Command::Kill(None) }
         | read_memory => { |(addr, length)| Command::ReadMemory(MemoryRegion::new(addr, length)) }
         | write_memory => { |(addr, length, bytes)| Command::WriteMemory(MemoryRegion::new(addr, length), bytes) }
         | read_register => { |regno| Command::ReadRegister(regno) }
         | write_register => { |(regno, bytes)| Command::WriteRegister(regno, bytes) }
         | query => { |q| Command::Query(q) }
         | tag!("r") => { |_| Command::Reset }
         | preceded!(tag!("R"), take!(2)) => { |_| Command::Reset }
         | parse_ping_thread => { |thread_id| Command::PingThread(thread_id) }
         | v_command => { |command| command }
         | write_memory_binary => { |(addr, length, bytes)| Command::WriteMemory(MemoryRegion::new(addr, length), bytes) }
         | parse_z_packet => { |command| command }
    )
}

/// An error as returned by a `Handler` method.
pub enum Error {
    /// A plain error.  The meaning of the value is not defined by the
    /// protocol.  Different values can therefore be used by a handler
    /// for debugging purposes.
    Error(u8),
    /// The request is not implemented.  Note that, in some cases, the
    /// protocol implementation tells the client that a feature is implemented;
    /// if the handler method then returns `Unimplemented`, the client will
    /// be confused.  So, normally it is best either to not implement
    /// a `Handler` method, or to return `Error` from implementations.
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

bitflags! {
    /// Host file permissions.
    pub struct HostMode: u32 {
        /// A regular file.
        const S_IFREG = 0o100000;
        /// A directory.
        const S_IFDIR = 0o40000;
        /// User read permissions.
        const S_IRUSR = 0o400;
        /// User write permissions.
        const S_IWUSR = 0o200;
        /// User execute permissions.
        const S_IXUSR = 0o100;
        /// Group read permissions.
        const S_IRGRP = 0o40;
        /// Group write permissions
        const S_IWGRP = 0o20;
        /// Group execute permissions.
        const S_IXGRP = 0o10;
        /// World read permissions.
        const S_IROTH = 0o4;
        /// World write permissions
        const S_IWOTH = 0o2;
        /// World execute permissions.
        const S_IXOTH = 0o1;
    }
}

bitflags! {
    // The read/write flags below may look a little weird, but that is the way
    // they are defined in the protocol.
    /// Host flags for opening files.
    pub struct HostOpenFlags: u32 {
        /// A read-only file.
        const O_RDONLY = 0x0;
        /// A write-only file.
        const O_WRONLY = 0x1;
        /// A read-write file.
        const O_RDWR = 0x2;
        /// Append to an existing file.
        const O_APPEND = 0x8;
        /// Create a non-existent file.
        const O_CREAT = 0x200;
        /// Truncate an existing file.
        const O_TRUNC = 0x400;
        /// Exclusive access.
        const O_EXCL = 0x800;
    }
}

/// Data returned by a host fstat request.  The members of this structure are
/// specified by the remote protocol; conversion of actual host stat
/// information into this structure may therefore require truncation of some
/// members.
pub struct HostStat {
    /// The device.
    pub st_dev: u32,
    /// The inode.
    pub st_ino: u32,
    /// Protection bits.
    pub st_mode: u32,
    /// The number of hard links.
    pub st_nlink: u32,
    /// The user id of the owner.
    pub st_uid: u32,
    /// The group id of the owner.
    pub st_gid: u32,
    /// The device type, if an inode device.
    pub st_rdev: u32,
    /// The size of the file in bytes.
    pub st_size: u64,
    /// The blocksize for the filesystem.
    pub st_blksize: u64,
    /// The number of blocks allocated.
    pub st_blocks: u64,
    /// The last time the file was accessed, in seconds since the epoch.
    pub st_atime: u32,
    /// The last time the file was modified, in seconds since the epoch.
    pub st_mtime: u32,
    /// The last time the file was changed, in seconds since the epoch.
    pub st_ctime: u32,
}

// Having to write out all the fields for these two operations is annoying,
// but the alternatives are even more annoying.  For instance, we could
// represent HostStat as a big array, with fields at appropriate offsets, but
// we'd have to write a bunch of accessor methods.  Note that #[repr(C)]
// isn't quite good enough, since that might introduce C-mandated padding
// into the structure.
fn write_stat<W>(writer: &mut W, stat: HostStat) -> io::Result<()>
    where W: Write
{
    use byteorder::{BigEndian, WriteBytesExt};

    writer.write_u32::<BigEndian>(stat.st_dev)?;
    writer.write_u32::<BigEndian>(stat.st_ino)?;
    writer.write_u32::<BigEndian>(stat.st_mode)?;
    writer.write_u32::<BigEndian>(stat.st_nlink)?;
    writer.write_u32::<BigEndian>(stat.st_uid)?;
    writer.write_u32::<BigEndian>(stat.st_gid)?;
    writer.write_u32::<BigEndian>(stat.st_rdev)?;
    writer.write_u64::<BigEndian>(stat.st_size)?;
    writer.write_u64::<BigEndian>(stat.st_blksize)?;
    writer.write_u64::<BigEndian>(stat.st_blocks)?;
    writer.write_u32::<BigEndian>(stat.st_atime)?;
    writer.write_u32::<BigEndian>(stat.st_mtime)?;
    writer.write_u32::<BigEndian>(stat.st_ctime)
}

#[allow(dead_code)]
fn read_stat(v: &[u8]) -> io::Result<HostStat> {
    use byteorder::{BigEndian, ReadBytesExt};
    use std::io::Cursor;

    let mut r = Cursor::new(v);
    let st_dev = r.read_u32::<BigEndian>()?;
    let st_ino = r.read_u32::<BigEndian>()?;
    let st_mode = r.read_u32::<BigEndian>()?;
    let st_nlink = r.read_u32::<BigEndian>()?;
    let st_uid = r.read_u32::<BigEndian>()?;
    let st_gid = r.read_u32::<BigEndian>()?;
    let st_rdev = r.read_u32::<BigEndian>()?;
    let st_size = r.read_u64::<BigEndian>()?;
    let st_blksize = r.read_u64::<BigEndian>()?;
    let st_blocks = r.read_u64::<BigEndian>()?;
    let st_atime = r.read_u32::<BigEndian>()?;
    let st_mtime = r.read_u32::<BigEndian>()?;
    let st_ctime = r.read_u32::<BigEndian>()?;

    Ok(HostStat{ st_dev, st_ino, st_mode, st_nlink, st_uid, st_gid, st_rdev,
                 st_size, st_blksize, st_blocks, st_atime, st_mtime, st_ctime })
}

/// Errno values for Host I/O operations.
#[allow(missing_docs)]
pub enum HostErrno {
    EPERM = 1,
    ENOENT = 2,
    EINTR = 4,
    EBADF = 9,
    EACCES = 13,
    EFAULT = 14,
    EBUSY = 16,
    EEXIST = 17,
    ENODEV = 19,
    ENOTDIR = 20,
    EISDIR = 21,
    EINVAL = 22,
    ENFILE = 23,
    EMFILE = 24,
    EFBIG = 27,
    ENOSPC = 28,
    ESPIPE = 29,
    EROFS = 30,
    ENAMETOOLONG = 91,
    EUNKNOWN = 9999,
}

/// The result type for host I/O operations.  Return error if the operation
/// in question is not implemented.  Otherwise, the success type indicates
/// whether the operation succeeded, with `HostErrno` values for failure.
pub type IOResult<T> = Result<Result<T, HostErrno>, ()>;

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
    /// Return a vector of additional features supported by this handler.
    /// Note that there currently is no way to override the built-in
    /// features that are always handled by the protocol
    /// implementation.
    fn query_supported_features(&self) -> Vec<String> {
        vec!()
    }

    /// Indicate whether the process in question already existed, and
    /// was attached to; or whether it was created by this server.
    fn attached(&self, _pid: Option<u64>) -> Result<ProcessType, Error>;

    /// Detach from the process.
    fn detach(&self, _pid: Option<u64>) -> Result<(), Error> {
        Err(Error::Unimplemented)
    }

    /// Kill the indicated process.  If no process is given, then the
    /// precise effect is unspecified; but killing any or all
    /// processes, or even rebooting an entire bare-metal target,
    /// would be appropriate.
    fn kill(&self, _pid: Option<u64>) -> Result<(), Error> {
        Err(Error::Unimplemented)
    }

    /// Check whether the indicated thread is alive.  If alive, return
    /// `()`.  Otherwise, return an error.
    fn ping_thread(&self, _id: ThreadId) -> Result<(), Error> {
        Err(Error::Unimplemented)
    }

    /// Read a memory region.
    fn read_memory(&self, _region: MemoryRegion) -> Result<Vec<u8>, Error> {
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

    /// Return the general registers.  The registers are returned as a
    /// vector of bytes, with the registers appearing contiguously in
    /// a target-specific order, with the bytes laid out in the target
    /// byte order.
    fn read_general_registers(&self) -> Result<Vec<u8>, Error> {
        Err(Error::Unimplemented)
    }

    /// Write the general registers.  The registers are specified as a
    /// vector of bytes, with the registers appearing contiguously in
    /// a target-specific order, with the bytes laid out in the target
    /// byte order.
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

    /// Start or stop catching syscalls.  If the argument is `None`, then
    /// stop catching syscalls.  Otherwise, start catching syscalls.
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

    /// Insert a software breakpoint.
    fn insert_software_breakpoint(&self, _breakpoint: Breakpoint) -> Result<(), Error> {
        Err(Error::Unimplemented)
    }

    /// Insert a hardware breakpoint.
    fn insert_hardware_breakpoint(&self, _breakpoint: Breakpoint) -> Result<(), Error> {
        Err(Error::Unimplemented)
    }

    /// Insert a write watchpoint.
    fn insert_write_watchpoint(&self, _watchpoint: Watchpoint) -> Result<(), Error> {
        Err(Error::Unimplemented)
    }

    /// Insert a read watchpoint.
    fn insert_read_watchpoint(&self, _watchpoint: Watchpoint) -> Result<(), Error> {
        Err(Error::Unimplemented)
    }

    /// Insert an access watchpoint.
    fn insert_access_watchpoint(&self, _watchpoint: Watchpoint) -> Result<(), Error> {
        Err(Error::Unimplemented)
    }

    /// Remove a software breakpoint.
    fn remove_software_breakpoint(&self, _breakpoint: Breakpoint) -> Result<(), Error> {
        Err(Error::Unimplemented)
    }

    /// Remove a hardware breakpoint.
    fn remove_hardware_breakpoint(&self, _breakpoint: Breakpoint) -> Result<(), Error> {
        Err(Error::Unimplemented)
    }

    /// Remove a write watchpoint.
    fn remove_write_watchpoint(&self, _watchpoint: Watchpoint) -> Result<(), Error> {
        Err(Error::Unimplemented)
    }

    /// Remove a read watchpoint.
    fn remove_read_watchpoint(&self, _watchpoint: Watchpoint) -> Result<(), Error> {
        Err(Error::Unimplemented)
    }

    /// Remove an access watchpoint.
    fn remove_access_watchpoint(&self, _watchpoint: Watchpoint) -> Result<(), Error> {
        Err(Error::Unimplemented)
    }

    /// Open a file on the remote stub's current filesystem.
    fn host_open(&self, _filename: Vec<u8>, _flags: u64, _mode: u64) -> IOResult<u64> {
        Err(())
    }

    /// Close a file opened with `host_open`.
    fn host_close(&self, _fd: u64) -> IOResult<()> {
        Err(())
    }

    /// Read data from an open file at the given offset.
    fn host_pread(&self, _fd: u64, _count: u64, _offset: u64) -> IOResult<Vec<u8>> {
        Err(())
    }

    /// Write data to an open file at the given offset.
    fn host_pwrite(&self, _fd: u64, _offset: u64, _data: Vec<u8>) -> IOResult<u64> {
        Err(())
    }

    /// Return a `HostStat` describing the attributes of the given open file.
    fn host_fstat(&self, _fd: u64) -> IOResult<HostStat> {
        Err(())
    }

    /// Remove a file from the remote stub's current filesystem.
    fn host_unlink(&self, _filename: Vec<u8>) -> IOResult<()> {
        Err(())
    }

    /// Read the contents of a symbolic link on the remote stub's current filesystem.
    fn host_readlink(&self, _filename: Vec<u8>) -> IOResult<Vec<u8>> {
        Err(())
    }

    /// Set the current filesystem for subsequent host I/O requests.  If the
    /// given pid is 0, select the filesystem of the remote stub.  Otherwise,
    /// select the filesystem as seen by the process with the given pid.
    fn host_setfs(&self, _pid: u64) -> IOResult<()> {
        Err(())
    }
}

fn compute_checksum_incremental(bytes: &[u8], init: u8) -> u8 {
    bytes.iter().fold(init, |sum, &b| sum.wrapping_add(b))
}

enum HostIOResult {
    Ok,                         // close, unlink, setfs
    Error(HostErrno),           // error result for any operation
    Integer(u64),               // open, pwrite
    Data(Vec<u8>),              // pread, readlink
    Stat(HostStat),             // fstat
}

enum Response<'a> {
    Empty,
    Ok,
    Error(u8),
    String(Cow<'a, str>),
    Output(String),
    Bytes(Vec<u8>),
    CurrentThread(Option<ThreadId>),
    ProcessType(ProcessType),
    Stopped(StopReason),
    SearchResult(Option<u64>),
    HostIOResult(HostIOResult),
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

impl<'a, T> From<Result<T, HostErrno>> for HostIOResult
    where HostIOResult: From<T>
{
    fn from(result: Result<T, HostErrno>) -> Self {
        match result {
            Result::Ok(val) => val.into(),
            Result::Err(errno) => HostIOResult::Error(errno),
        }
    }
}

impl From<()> for HostIOResult
{
    fn from(_: ()) -> Self {
        HostIOResult::Ok
    }
}

impl From<u64> for HostIOResult
{
    fn from(i: u64) -> Self {
        HostIOResult::Integer(i)
    }
}

impl From<Vec<u8>> for HostIOResult
{
    fn from(data: Vec<u8>) -> Self {
        HostIOResult::Data(data)
    }
}

impl From<HostStat> for HostIOResult
{
    fn from(stat: HostStat) -> Self {
        HostIOResult::Stat(stat)
    }
}

impl<'a, T> From<IOResult<T>> for Response<'a>
    where HostIOResult: From<T>
{
    fn from(result: IOResult<T>) -> Self {
        match result {
            Result::Ok(val) => Response::HostIOResult(val.into()),
            // Indicates the operation wasn't supported.
            Result::Err(_) => Response::Empty,
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
        Response::String(Cow::Owned(reason) as Cow<str>)
    }
}

impl<'a> From<HostIOResult> for Response<'a>
{
    fn from(result: HostIOResult) -> Self {
        Response::HostIOResult(result)
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

impl From<HostStat> for Vec<u8>
{
    fn from(stat: HostStat) -> Self {
        let mut v = vec![];
        // XXX: this can technically fail, and we shouldn't be ignoring it.
        write_stat(&mut v, stat).unwrap();
        v
    }
}

fn write_binary_data<W>(writer: &mut W, data: Vec<u8>) -> io::Result<()>
    where W: Write,
{
    let mut v: &[u8] = &data;

    while let Some(p) = v.iter().position(&needs_escape) {
        let (head, rest) = data.split_at(p);
        writer.write_all(head)?;

        let tmp = [0x7d, rest[0] ^ 0x20];
        writer.write_all(&tmp)?;

        v = &rest[1..];
    }

    return writer.write_all(&v);

    fn needs_escape(byte: &u8) -> bool {
        *byte == 0x23 || *byte == 0x24 || *byte == 0x7d || *byte == 0x2a
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
        Response::HostIOResult(result) => {
            match result {
                HostIOResult::Ok => write!(writer, "F0")?,
                HostIOResult::Error(errno) => {
                    write!(writer, "F-1,{:x}", errno as u32)?;
                },
                HostIOResult::Integer(i) => write!(writer, "F{:x}", i)?,
                HostIOResult::Data(v) => {
                    write!(writer, "F{:x};", v.len())?;
                    write_binary_data(&mut writer, v)?;
                },
                HostIOResult::Stat(stat) => {
                    write!(writer, "F0;")?;
                    write_binary_data(&mut writer, stat.into())?
                },
            }
        }
    }

    writer.finish()
}

fn handle_supported_features<'a, H>(handler: &H, _features: &Vec<GDBFeatureSupported<'a>>) -> Response<'static>
    where H: Handler,
{
    let mut features = vec!("PacketSize=65536".to_string(),
                            "QStartNoAckMode+".to_string(),
                            "multiprocess+".to_string(),
                            "QDisableRandomization+".to_string(),
                            "QCatchSyscalls+".to_string(),
                            "QPassSignals+".to_string(),
                            "QProgramSignals+".to_string());
    let mut new_features = handler.query_supported_features();
    features.append(&mut new_features);
    Response::String(Cow::Owned(features.join(";")) as Cow<str>)
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
            Command::ReadMemory(region) => {
                handler.read_memory(region).into()
            },
            Command::WriteMemory(region, bytes) => {
                // The docs don't really say what to do if the given
                // length disagrees with the number of bytes sent, so
                // just error if they disagree.
                if region.length as usize != bytes.len() {
                    Response::Error(1)
                } else {
                    handler.write_memory(region.address, &bytes[..]).into()
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

            Command::InsertSoftwareBreakpoint(bp) => {
                handler.insert_software_breakpoint(bp).into()
            }
            Command::InsertHardwareBreakpoint(bp) => {
                handler.insert_hardware_breakpoint(bp).into()
            }
            Command::InsertWriteWatchpoint(wp) => {
                handler.insert_write_watchpoint(wp).into()
            }
            Command::InsertReadWatchpoint(wp) => {
                handler.insert_read_watchpoint(wp).into()
            }
            Command::InsertAccessWatchpoint(wp) => {
                handler.insert_access_watchpoint(wp).into()
            }
            Command::RemoveSoftwareBreakpoint(bp) => {
                handler.remove_software_breakpoint(bp).into()
            }
            Command::RemoveHardwareBreakpoint(bp) => {
                handler.remove_hardware_breakpoint(bp).into()
            }
            Command::RemoveWriteWatchpoint(wp) => {
                handler.remove_write_watchpoint(wp).into()
            }
            Command::RemoveReadWatchpoint(wp) => {
                handler.remove_read_watchpoint(wp).into()
            }
            Command::RemoveAccessWatchpoint(wp) => {
                handler.remove_access_watchpoint(wp).into()
            }

            Command::HostOpen(filename, mode, flags) => {
                handler.host_open(filename, mode, flags).into()
            }
            Command::HostClose(fd) => {
                handler.host_close(fd).into()
            }
            Command::HostPRead(fd, count, offset) => {
                handler.host_pread(fd, count, offset).into()
            }
            Command::HostPWrite(fd, offset, data) => {
                handler.host_pwrite(fd, offset, data).into()
            }
            Command::HostFStat(fd) => {
                handler.host_fstat(fd).into()
            }
            Command::HostUnlink(filename) => {
                handler.host_unlink(filename).into()
            }
            Command::HostReadlink(filename) => {
                handler.host_readlink(filename).into()
            }
            Command::HostSetFS(pid) => {
                handler.host_setfs(pid).into()
            }
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

    assert_eq!(v_command(&b"vFile:open:2f766d6c696e757a,0,0"[..]),
               Done(&b""[..], Command::HostOpen(vec!(47, 118, 109, 108, 105, 110, 117, 122), 0, 0)));
    assert_eq!(v_command(&b"vFile:close:85"[..]),
               Done(&b""[..], Command::HostClose(0x85)));
    assert_eq!(v_command(&b"vFile:pread:5,96,327"[..]),
               Done(&b""[..], Command::HostPRead(5, 0x96, 0x327)));
    assert_eq!(v_command(&b"vFile:pwrite:6,83,\x00"[..]),
               Done(&b""[..], Command::HostPWrite(6, 0x83, vec![0])));
    assert_eq!(v_command(&b"vFile:pwrite:6,83,\x7d\x5d"[..]),
               Done(&b""[..], Command::HostPWrite(6, 0x83, vec![0x7d])));
    assert_eq!(v_command(&b"vFile:fstat:32"[..]),
               Done(&b""[..], Command::HostFStat(0x32)));
    assert_eq!(v_command(&b"vFile:unlink:2f766d6c696e757a"[..]),
               Done(&b""[..], Command::HostUnlink(vec!(47, 118, 109, 108, 105, 110, 117, 122))));
    assert_eq!(v_command(&b"vFile:readlink:2f766d6c696e757a"[..]),
               Done(&b""[..], Command::HostReadlink(vec!(47, 118, 109, 108, 105, 110, 117, 122))));
    assert_eq!(v_command(&b"vFile:setfs:0"[..]),
               Done(&b""[..], Command::HostSetFS(0)));
    assert_eq!(v_command(&b"vFile:fdopen:0"[..]),
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
fn test_parse_write_memory_binary() {
    assert_eq!(write_memory_binary(&b"Xf0,1: "[..]),
               Done(&b""[..], (240, 1, vec!(0x20))));
    assert_eq!(write_memory_binary(&b"X90,10:}\x5d"[..]),
               Done(&b""[..], (144, 16, vec!(0x7d))));
    assert_eq!(write_memory_binary(&b"X5,100:}\x5d}\x03"[..]),
               Done(&b""[..], (5, 256, vec!(0x7d, 0x23))));
    assert_eq!(write_memory_binary(&b"Xff,2:}\x04\x9a"[..]),
               Done(&b""[..], (255, 2, vec!(0x24, 0x9a))));
    assert_eq!(write_memory_binary(&b"Xff,2:\xce}\x0a\x9a"[..]),
               Done(&b""[..], (255, 2, vec!(0xce, 0x2a, 0x9a))));
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

#[cfg(test)]
macro_rules! bytecode {
    ($elem:expr; $n:expr) => (Bytecode { bytecode: vec![$elem; $n] });
    ($($x:expr),*) => (Bytecode { bytecode: vec!($($x),*) })
}

#[test]
fn test_breakpoints() {
    assert_eq!(parse_z_packet(&b"Z0,1ff,0"[..]),
               Done(&b""[..], Command::InsertSoftwareBreakpoint(Breakpoint::new(0x1ff, 0, None, None))));
    assert_eq!(parse_z_packet(&b"z0,1fff,0"[..]),
               Done(&b""[..], Command::RemoveSoftwareBreakpoint(Breakpoint::new(0x1fff, 0, None, None))));
    assert_eq!(parse_z_packet(&b"Z1,ae,0"[..]),
               Done(&b""[..], Command::InsertHardwareBreakpoint(Breakpoint::new(0xae, 0, None, None))));
    assert_eq!(parse_z_packet(&b"z1,aec,0"[..]),
               Done(&b""[..], Command::RemoveHardwareBreakpoint(Breakpoint::new(0xaec, 0, None, None))));
    assert_eq!(parse_z_packet(&b"Z2,4cc,2"[..]),
               Done(&b""[..], Command::InsertWriteWatchpoint(Watchpoint::new(0x4cc, 2))));
    assert_eq!(parse_z_packet(&b"z2,4ccf,4"[..]),
               Done(&b""[..], Command::RemoveWriteWatchpoint(Watchpoint::new(0x4ccf, 4))));
    assert_eq!(parse_z_packet(&b"Z3,7777,4"[..]),
               Done(&b""[..], Command::InsertReadWatchpoint(Watchpoint::new(0x7777, 4))));
    assert_eq!(parse_z_packet(&b"z3,77778,8"[..]),
               Done(&b""[..], Command::RemoveReadWatchpoint(Watchpoint::new(0x77778, 8))));
    assert_eq!(parse_z_packet(&b"Z4,7777,10"[..]),
               Done(&b""[..], Command::InsertAccessWatchpoint(Watchpoint::new(0x7777, 16))));
    assert_eq!(parse_z_packet(&b"z4,77778,20"[..]),
               Done(&b""[..], Command::RemoveAccessWatchpoint(Watchpoint::new(0x77778, 32))));

    assert_eq!(parse_z_packet(&b"Z0,1ff,2;X1,0"[..]),
               Done(&b""[..], Command::InsertSoftwareBreakpoint(Breakpoint::new(0x1ff, 2,
                                                                Some(vec!(bytecode!('0' as u8))), None))));
    assert_eq!(parse_z_packet(&b"Z1,1ff,2;X1,0"[..]),
               Done(&b""[..], Command::InsertHardwareBreakpoint(Breakpoint::new(0x1ff, 2,
                                                                Some(vec!(bytecode!('0' as u8))), None))));

    assert_eq!(parse_z_packet(&b"Z0,1ff,2;cmdsX1,z"[..]),
               Done(&b""[..], Command::InsertSoftwareBreakpoint(Breakpoint::new(0x1ff, 2,
                                                                None, Some(vec!(bytecode!('z' as u8)))))));
    assert_eq!(parse_z_packet(&b"Z1,1ff,2;cmdsX1,z"[..]),
               Done(&b""[..], Command::InsertHardwareBreakpoint(Breakpoint::new(0x1ff, 2,
                                                                None, Some(vec!(bytecode!('z' as u8)))))));

    assert_eq!(parse_z_packet(&b"Z0,1ff,2;X1,0;cmdsX1,a"[..]),
               Done(&b""[..], Command::InsertSoftwareBreakpoint(Breakpoint::new(0x1ff, 2,
                                                                Some(vec!(bytecode!('0' as u8))),
                                                                Some(vec!(bytecode!('a' as u8)))))));
    assert_eq!(parse_z_packet(&b"Z1,1ff,2;X1,0;cmdsX1,a"[..]),
               Done(&b""[..], Command::InsertHardwareBreakpoint(Breakpoint::new(0x1ff, 2,
                                                                Some(vec!(bytecode!('0' as u8))),
                                                                Some(vec!(bytecode!('a' as u8)))))));
}

#[test]
fn test_cond_or_command_list() {
    assert_eq!(parse_condition_list(&b";X1,a"[..]),
               Done(&b""[..], vec!(bytecode!('a' as u8))));
    assert_eq!(parse_condition_list(&b";X2,ab"[..]),
               Done(&b""[..], vec!(bytecode!('a' as u8, 'b' as u8))));
    assert_eq!(parse_condition_list(&b";X1,zX1,y"[..]),
               Done(&b""[..], vec!(bytecode!('z' as u8),
                                   bytecode!('y' as u8))));
    assert_eq!(parse_condition_list(&b";X1,zX10,yyyyyyyyyyyyyyyy"[..]),
               Done(&b""[..], vec!(bytecode!('z' as u8),
                                   bytecode!['y' as u8; 16])));

    assert_eq!(parse_command_list(&b";cmdsX1,a"[..]),
               Done(&b""[..], vec!(bytecode!('a' as u8))));
    assert_eq!(parse_command_list(&b";cmdsX2,ab"[..]),
               Done(&b""[..], vec!(bytecode!('a' as u8, 'b' as u8))));
    assert_eq!(parse_command_list(&b";cmdsX1,zX1,y"[..]),
               Done(&b""[..], vec!(bytecode!('z' as u8),
                                   bytecode!('y' as u8))));
    assert_eq!(parse_command_list(&b";cmdsX1,zX10,yyyyyyyyyyyyyyyy"[..]),
               Done(&b""[..], vec!(bytecode!('z' as u8),
                                   bytecode!['y' as u8; 16])));
}

#[test]
fn test_write_binary_data() {
    // Ordinary data, no escapes.
    check(vec!(1, 2, 3), vec!(1, 2, 3));
    // Escape required at the beginning.
    check(vec!(0x7d, 2, 3), vec!(0x7d, 0x5d, 2, 3));
    check(vec!(0x23, 2, 3), vec!(0x7d, 0x03, 2, 3));
    check(vec!(0x24, 2, 3), vec!(0x7d, 0x04, 2, 3));
    check(vec!(0x2a, 2, 3), vec!(0x7d, 0x0a, 2, 3));
    // Escape required at the end.
    check(vec!(8, 9, 0x7d), vec!(8, 9, 0x7d, 0x5d));
    check(vec!(8, 9, 0x23), vec!(8, 9, 0x7d, 0x03));
    check(vec!(8, 9, 0x24), vec!(8, 9, 0x7d, 0x04));
    check(vec!(8, 9, 0x2a), vec!(8, 9, 0x7d, 0x0a));
    // Escape required in the middle.
    check(vec!(8, 9, 0x7d, 5, 6), vec!(8, 9, 0x7d, 0x5d, 5, 6));
    check(vec!(8, 9, 0x23, 5, 6), vec!(8, 9, 0x7d, 0x03, 5, 6));
    check(vec!(8, 9, 0x24, 5, 6), vec!(8, 9, 0x7d, 0x04, 5, 6));
    check(vec!(8, 9, 0x2a, 5, 6), vec!(8, 9, 0x7d, 0x0a, 5, 6));

    fn check(data: Vec<u8>, output: Vec<u8>) {
        let mut v = vec![];
        write_binary_data(&mut v, data).unwrap();
        assert_eq!(v, output);
    }
}
