#[macro_use]
extern crate nom;

use nom::IResult::*;
use nom::{Consumer,ConsumerState,Move,Input,Producer};
use std::io::{BufRead,BufReader,Read,SeekFrom};
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
pub enum Packet {
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
