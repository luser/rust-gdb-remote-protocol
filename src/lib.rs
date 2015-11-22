#[macro_use]
extern crate nom;

use nom::IResult::*;
use nom::{Consumer,ConsumerState,Move,Input,Producer};
use std::io::{BufRead,BufReader,Read,SeekFrom,Write};
use std::str;

named!(checksum<&[u8], u8>,
       map_res!(map_res!(take!(2), str::from_utf8),
                |s| u8::from_str_radix(s, 16)));

named!(packet<&[u8], (Vec<u8>, u8)>,
       preceded!(tag!("$"),
                 separated_pair!(map!(opt!(is_not!("#")), |o : Option<&[u8]>| o.map_or(vec!(), |s| s.to_vec())),
                                 tag!("#"),
                                 checksum)));

#[derive(Debug,PartialEq,Eq)]
enum Packet {
    Ack,
    Nack,
    Data(Vec<u8>, u8),
}

named!(packet_or_response<Packet>, alt!(
    packet => { |(d, chk)| Packet::Data(d, chk) }
    | tag!("+") => { |_|   Packet::Ack }
    | tag!("-") => { |_|   Packet::Nack }
    ));

consumer_from_parser!(GdbConsumer<Packet>, packet_or_response);

#[derive(PartialEq)]
enum ReadProducerState {
    Ok,
    Eof,
    Error,
}

struct ReadProducer<T : Read> {
    reader : BufReader<T>,
    /// Current state of this producer.
    pub state : ReadProducerState,
}

impl<T : Read> ReadProducer<T> {
    pub fn new(read : T) -> ReadProducer<T> {
        ReadProducer {
            reader : BufReader::new(read),
            state : ReadProducerState::Ok,
        }
    }
}

impl<'x, T : Read> Producer<'x,&'x [u8],Move> for ReadProducer<T> {
    fn apply<'a,O,E>(&'x mut self, consumer: &'a mut Consumer<&'x[u8],O,E,Move>) -> &'a ConsumerState<O,E,Move> {
        if {
            match consumer.state() {
                &ConsumerState::Continue(ref m) | &ConsumerState::Done(ref m, _) => {
                    match *m {
                        Move::Consume(s) => {
                            if s > 0 {
                                self.reader.consume(s);
                            }
                        },
                        Move::Await(a) => {
                            panic!("not handled for now: await({:?}", a);
                        }
                        Move::Seek(SeekFrom::Start(_)) => {
                            panic!("ReadProducer can't SeekFrom::Start");
                        },
                        Move::Seek(SeekFrom::Current(offset)) => {
                            if offset < 0 {
                                panic!("ReadProducer can't SeekFrom::Current backwards!");
                            }
                            panic!("Not yet implemented");
                        },
                        Move::Seek(SeekFrom::End(_)) => {
                            panic!("ReadProducer can't SeekFrom::End");
                        }
                    }
                    true
                },
                _ => false,
            }
        }
        {
            if let Ok(buf) = self.reader.fill_buf() {
                if buf.len() == 0 {
                    self.state = ReadProducerState::Eof;
                    consumer.handle(Input::Eof(None))
                } else {
                    consumer.handle(Input::Element(buf))
                }
            } else {
                self.state = ReadProducerState::Error;
                consumer.handle(Input::Eof(None))
            }
        } else {
            consumer.state()
        }
    }
}

pub trait Handler {
}

/// Compute a checksum of `bytes`: modulo-265 sum of each byte in `bytes`.
fn compute_checksum(bytes : &[u8]) -> u8 {
    bytes.iter().fold(0, |sum, &b| sum.wrapping_add(b))
}

/// Read gdbserver packets from `reader` and call methods on `handler` to handle them and write responses to `writer`.
pub fn process_packets_from<R, W, H>(reader : R,
                                     mut writer : W,
                                     _handler : H) where R : Read, W : Write, H : Handler {
    let mut p = ReadProducer::new(reader);
    let mut c = GdbConsumer::new();
    while p.state == ReadProducerState::Ok {
        if let Some(ref packet) = p.run(&mut c) {
            match **packet {
                Packet::Data(ref data, ref checksum) => {
                    let chk = compute_checksum(&data);
                    if chk == checksum {
                        // Write an ACK
                        if !writer.write_all(&b"+"[..]).is_ok() {
                            //TODO: propogate errors to caller?
                            return;
                        }
                        //TODO: process packet, write result
                    } else {
                        // Write a NACK
                        if !writer.write_all(&b"-"[..]).is_ok() {
                            //TODO: propogate errors to caller?
                            return;
                        }
                    }
                },
                // Just ignore ACK/NACK
                _ => {},
            }
        }
    }
}

#[test]
fn test_compute_checksum() {
    assert_eq!(compute_checksum(&b""[..]), 0);
    assert_eq!(compute_checksum(&b"qSupported:multiprocess+;xmlRegisters=i386;qRelocInsn+"[..]), 0xb5);
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
               Done(&b""[..], (b"qSupported:multiprocess+;xmlRegisters=i386;qRelocInsn+"[..].to_vec(), 0xb5)));
    assert_eq!(packet(&b"$"[..]), Incomplete(Needed::Size(1)));
    assert_eq!(packet(&b"$#"[..]), Incomplete(Needed::Size(2)));
    assert_eq!(packet(&b"$xyz"[..]), Incomplete(Needed::Size(1)));
    assert_eq!(packet(&b"$xyz#"[..]), Incomplete(Needed::Size(2)));
    assert_eq!(packet(&b"$xyz#a"[..]), Incomplete(Needed::Size(2)));
}

#[test]
fn test_packet_or_response() {
    assert_eq!(packet_or_response(&b"$#00"[..]), Done(&b""[..], Packet::Data(b""[..].to_vec(), 0)));
    assert_eq!(packet_or_response(&b"+"[..]), Done(&b""[..], Packet::Ack));
    assert_eq!(packet_or_response(&b"-"[..]), Done(&b""[..], Packet::Nack));
}

#[test]
fn test_consumer() {
    let mut c = GdbConsumer::new();
    {
        let state = c.state();
        if let &ConsumerState::Continue(Move::Consume(n)) = state {
            assert_eq!(n, 0);
        } else {
            assert!(false, format!("Bad state: {:?}", state));
        }
    }
    {
        let state = c.handle(Input::Empty);
        if let &ConsumerState::Continue(Move::Consume(n)) = state {
            assert_eq!(n, 0);
        } else {
            assert!(false, format!("Bad state: {:?}", state));
        }
    }
    {
        let state = c.handle(Input::Element(&b"+"[..]));
        if let &ConsumerState::Done(Move::Consume(n),
                                    Packet::Ack) = state {
            assert_eq!(n, 1);
        } else {
            assert!(false, format!("Bad state: {:?}", state));
        }
    }
    {
        let state = c.handle(Input::Element(&b"-"[..]));
        if let &ConsumerState::Done(Move::Consume(n),
                                    Packet::Nack) = state {
            assert_eq!(n, 1);
        } else {
            assert!(false, format!("Bad state: {:?}", state));
        }
    }
    {
        let state = c.handle(Input::Element(&b"$#00"[..]));
        if let &ConsumerState::Done(Move::Consume(n),
                                    Packet::Data(ref d, 0)) = state {
            assert_eq!(n, 4);
            assert_eq!(*d, b""[..].to_vec());
        } else {
            assert!(false, format!("Bad state: {:?}", state));
        }
    }
    {
        let state = c.handle(Input::Element(&b"$xyz#a1"[..]));
        if let &ConsumerState::Done(Move::Consume(n),
                                    Packet::Data(ref d, 0xa1)) = state {
            assert_eq!(n, 7);
            assert_eq!(*d, b"xyz"[..].to_vec());
        } else {
            assert!(false, format!("Bad state: {:?}", state));
        }
    }
    {
        let state = c.handle(Input::Element(&b"$xyz"[..]));
        if let &ConsumerState::Continue(Move::Await(_)) = state {
            assert!(true, "OK!");
        } else {
            assert!(false, format!("Bad state: {:?}", state));
        }
    }
    {
        let state = c.handle(Input::Element(&b"$xyz#"[..]));
        if let &ConsumerState::Continue(Move::Await(_)) = state {
            assert!(true, "OK!");
        } else {
            assert!(false, format!("Bad state: {:?}", state));
        }
    }
    {
        let state = c.handle(Input::Element(&b"$xyz#a"[..]));
        if let &ConsumerState::Continue(Move::Await(_)) = state {
            assert!(true, "OK!");
        } else {
            assert!(false, format!("Bad state: {:?}", state));
        }
    }
}

#[test]
fn test_producer_consumer() {
    use std::io::Cursor;
    let bytes = b"+$qSupported:multiprocess+;xmlRegisters=i386;qRelocInsn+#b5$qSupported:multiprocess+;xmlRegisters=i386;qRelocInsn+#b5-";
    let cur = Cursor::new(&bytes[..]);
    let mut p = ReadProducer::new(cur);
    let mut c = GdbConsumer::new();
    {
        let state = p.apply(&mut c);
        if let &ConsumerState::Done(Move::Consume(n), Packet::Ack) = state {
            assert_eq!(n, 1);
        } else {
            assert!(false, format!("Bad state: {:?}", state));
        }
    }
    {
        let state = p.apply(&mut c);
        if let &ConsumerState::Done(Move::Consume(n), Packet::Data(ref d, chk)) = state {
            assert_eq!(*d, b"qSupported:multiprocess+;xmlRegisters=i386;qRelocInsn+"[..].to_vec());
            assert_eq!(n, 58);
            assert_eq!(chk, 0xb5);
        } else {
            assert!(false, format!("Bad state: {:?}", state));
        }
    }
    {
        let state = p.apply(&mut c);
        if let &ConsumerState::Done(Move::Consume(n), Packet::Data(ref d, chk)) = state {
            assert_eq!(*d, b"qSupported:multiprocess+;xmlRegisters=i386;qRelocInsn+"[..].to_vec());
            assert_eq!(n, 58);
            assert_eq!(chk, 0xb5);
        } else {
            assert!(false, format!("Bad state: {:?}", state));
        }
    }
    {
        let state = p.apply(&mut c);
        if let &ConsumerState::Done(Move::Consume(n), Packet::Nack) = state {
            assert_eq!(n, 1);
        } else {
            assert!(false, format!("Bad state: {:?}", state));
        }
    }
}
