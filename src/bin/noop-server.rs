extern crate gdbserver;

use gdbserver::{Handler,process_packets_from};
use std::net::TcpListener;

struct NoopHandler;

impl Handler for NoopHandler {}

#[cfg_attr(test, allow(dead_code))]
fn main() {
    let listener = TcpListener::bind("0.0.0.0:2424").unwrap();
    for res in listener.incoming() {
        println!("Got connection");
        if let Ok(stream) = res {
            let h = NoopHandler;
            process_packets_from(stream.try_clone().unwrap(), stream, h);
        }
        println!("Connection closed");
    }
}
