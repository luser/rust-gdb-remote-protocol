/*
Still needed to get a working session up with GDB (possibly incomplete):

 *. Return a sensible feature list from qSupported.
 2. Support vMustReplyEmpty, QStartNoAckMode.
 3. Support qXfer:features:read for target descriptions (take xml files from GDB repo).
 4. Support qXfer:auxv:read
 5. Support nqXfer:threads:read
 6. Support qAttached
 7. Support qXfer:libraries-svr4:read
 8. Support m (memory read)
 9. Support H (set thread)
10. Support ? (stop reason)
11. Support qOffsets? (not sure)
12. Support qSymbol
13. Support vKill

*/
#[macro_use]
extern crate nom;
extern crate strum;
#[macro_use]
extern crate strum_macros;

use nom::IResult::*;
use nom::{IResult, Needed};
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

#[derive(Debug, PartialEq)]
enum Known<'a> {
    Yes(GDBFeature),
    No(&'a str),
}

#[derive(Debug, PartialEq)]
struct GDBFeatureSupported<'a>(Known<'a>, FeatureSupported<'a>);

#[derive(Debug, PartialEq)]
enum FeatureSupported<'a> {
    Yes,
    No,
    #[allow(unused)]
    Maybe,
    Value(&'a str),
}

#[derive(Debug, PartialEq)]
enum Query<'a> {
    /// Return the current thread ID.
    CurrentThread,
    /// Compute the CRC checksum of a block of memory.
    #[allow(unused)]
    CRC { addr: u64, length: u64 },
    /// Tell the remote stub about features supported by gdb, and query the stub for features
    /// it supports.
    SupportedFeatures(Vec<GDBFeatureSupported<'a>>),
    /// Disable acknowledgments.
    StartNoAckMode,
}

/// GDB remote protocol commands, as defined in (the GDB documentation)[1]
/// [1]: https://sourceware.org/gdb/onlinedocs/gdb/Packets.html#Packets
enum Command<'a> {
    /// Enable extended mode.
    EnableExtendedMode,
    /// Indicate the reason the target halted.
    TargetHaltReason,
    /// Toggle debug flag.
    ToggleDebug,
    // Read general registers.
    ReadGeneralRegisters,
    // Kill request.
    Kill,
    Query(Query<'a>),
    Reset,
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

fn query<'a>(i: &'a [u8]) -> IResult<&'a [u8], Query<'a>> {
    alt_complete!(i,
                  tag!("qC") => { |_| Query::CurrentThread }
                  | preceded!(tag!("qSupported"),
                              preceded!(tag!(":"),
                                        separated_list_complete!(tag!(";"),
                                                                 gdbfeaturesupported))) => {
                      |features: Vec<GDBFeatureSupported<'a>>| Query::SupportedFeatures(features)
                  }
                  | tag!("QStartNoAckMode") => { |_| Query::StartNoAckMode }
                  )
}
/*
fn v_command<'a>(i: &'a [u8]) -> IResult<&'a [u8], Command<'a>> {
    preceded!(i, tag!("v"),
              CtrlC
              alt_complete!(tag!("MustReplyEmpty")
*/

fn command<'a>(i: &'a [u8]) -> IResult<&'a [u8], Command<'a>> {
    alt!(i,
    tag!("!") => { |_|   Command::EnableExtendedMode }
    | tag!("?") => { |_| Command::TargetHaltReason }
    // A arglen,argnum,arg,
    // b baud
    // B addr,mode
    // bc
    // bs
    // c [addr]
    // c sig[;addr]
    | tag!("d") => { |_| Command::ToggleDebug }
    // D
    // D;pid
    // F RC,EE,CF;XX’
    | tag!("g") => { |_| Command::ReadGeneralRegisters }
    // G XX...
    // H op thread-id
    // i [addr[,nnn]]
    | tag!("k") => { |_| Command::Kill }
    // m addr,length
    // M addr,length:XX...
    // p n
    // P n...=r...
    // ‘q name params...’
    | query => { |q| Command::Query(q) }
    // ‘Q name params...’
    //TODO: support QStartNoAckMode
    | tag!("r") => { |_| Command::Reset }
    | preceded!(tag!("R"), take!(2)) => { |_| Command::Reset }
    // s [addr]
    // S sig[;addr]
    // t addr:PP,MM
    // T thread-id
    //| v_command => { |v| v }
    // X addr,length:XX...
    // ‘z type,addr,kind’
    // ‘Z type,addr,kind’
    // ‘z0,addr,kind’
    // ‘Z0,addr,kind[;cond_list...][;cmds:persist,cmd_list...]’
    // ‘z1,addr,kind’
    // ‘Z1,addr,kind[;cond_list...]’
    // ‘z2,addr,kind’
    // ‘Z2,addr,kind’
    // ‘z3,addr,kind’
    // ‘Z3,addr,kind’
    // ‘z4,addr,kind’
    // ‘Z4,addr,kind’
         )
}

pub trait Handler {
    fn query_supported_features() {}
}

/// Compute a checksum of `bytes`: modulo-256 sum of each byte in `bytes`.
fn compute_checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0, |sum, &b| sum.wrapping_add(b))
}

enum Response<'a> {
    Empty,
    String(&'a str),
}

fn write_response<W>(response: Response, writer: &mut W) -> io::Result<()>
    where W: Write,
{
    match response {
        Response::Empty => {
            writer.write_all(&b"$#00"[..])
        }
        Response::String(s) => {
            write!(writer, "${}#{:02x}", s, compute_checksum(s.as_bytes()))
        }
    }
}

fn handle_supported_features<'a, H>(_handler: &H, _features: &Vec<GDBFeatureSupported<'a>>) -> Response<'static>
    where H: Handler,
{
    Response::String("PacketSize=65536;QStartNoAckMode+")
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
            Command::EnableExtendedMode => Response::Empty,
            Command::TargetHaltReason => Response::Empty,
            Command::ToggleDebug => Response::Empty,
            Command::ReadGeneralRegisters => Response::Empty,
            Command::Kill => Response::Empty,
            Command::Reset => Response::Empty,
            Command::Query(Query::SupportedFeatures(features)) =>
                handle_supported_features(handler, &features),
            Command::Query(Query::StartNoAckMode) => {
                no_ack_mode = true;
                Response::String("OK")
            }
            _ => Response::Empty,
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
                        ack_mode = handle_packet(&data, &handler, &mut writer).unwrap() || ack_mode;
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
    assert_eq!(compute_checksum(&b""[..]), 0);
    assert_eq!(compute_checksum(&b"qSupported:multiprocess+;xmlRegisters=i386;qRelocInsn+"[..]),
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

