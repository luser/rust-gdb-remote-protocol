// GDB integration tests
//
// These tests run a server using `TestHandler` as the handler and then run gdb in batch mode,
// connect it to the server, feed it some commands, and exit. Tests can add assertions about the
// gdb process such as matching stdout / stderr by calling `assert` and using the APIs from
// assert-cli: https://docs.rs/assert_cli/ .
//
// The gdb executable to use is found from PATH.
//
// `gdb_test` configures logging using env_logger, so you can get log output from tests by running:
// RUST_LOG=gdb_remote_protocol=trace,integration=trace cargo test -- --nocapture

#[macro_use]
extern crate log;

use assert_cli::Assert;
use gdb_remote_protocol::{process_packets_from, Error, Handler, ProcessType, StopReason};
use std::net::TcpListener;
use std::thread;

struct TestHandler {
    process_type: ProcessType,
    stop_reason: StopReason,
}

impl Default for TestHandler {
    fn default() -> TestHandler {
        TestHandler {
            process_type: ProcessType::Created,
            stop_reason: StopReason::Exited(23, 0),
        }
    }
}

impl Handler for TestHandler {
    fn attached(&self, _pid: Option<u64>) -> Result<ProcessType, Error> {
        Ok(self.process_type)
    }

    fn halt_reason(&self) -> Result<StopReason, Error> {
        Ok(self.stop_reason)
    }
}

struct GDBTestBuilder {
    assert: Assert,
    handler: TestHandler,
    listener: TcpListener,
}

#[allow(unused)]
impl GDBTestBuilder {
    /// Add `cmd` to the list of GDB commands to execute.
    fn command<T>(self, cmd: T) -> GDBTestBuilder
    where
        T: AsRef<str>,
    {
        let GDBTestBuilder {
            assert,
            handler,
            listener,
        } = self;
        GDBTestBuilder {
            assert: assert.with_args(&["-ex", cmd.as_ref()]),
            handler,
            listener,
        }
    }

    /// Add assertions for the GDB process. `f` will receive an `Assert` that can
    /// be used to add assertions and must return it.
    fn assert<F>(self, f: F) -> GDBTestBuilder
    where
        F: FnOnce(Assert) -> Assert,
    {
        let GDBTestBuilder {
            assert,
            handler,
            listener,
        } = self;
        let assert = f(assert);
        GDBTestBuilder {
            assert,
            handler,
            listener,
        }
    }

    /// Change the behavior of the `TestHandler`. `f` will receive a `&mut TestHandler` argument
    /// which can be changed as desired.
    fn handler<F>(self, f: F) -> GDBTestBuilder
    where
        F: FnOnce(&mut TestHandler),
    {
        let GDBTestBuilder {
            assert,
            mut handler,
            listener,
        } = self;
        f(&mut handler);
        GDBTestBuilder {
            assert,
            handler,
            listener,
        }
    }

    /// Run the prepared test, panicing on failure.
    fn execute(self) {
        let GDBTestBuilder {
            assert,
            handler,
            listener,
        } = self;
        let assert = assert.with_args(&["-ex", "quit"]);
        // Run the server on a background thread.
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("Listener's accept failed!");
            process_packets_from(
                stream.try_clone().expect("TCPStream::try_clone failed!"),
                stream,
                handler,
            );
        });
        debug!("Running GDB as {:?}", assert);
        assert.unwrap();
        handle.join().expect("Failed to join server thread!");
    }
}

/// Create a `GDBTestBuilder` and return it.
fn gdb_test() -> GDBTestBuilder {
    drop(env_logger::init());
    // First, ensure that we have a GDB binary.
    let gdb = which::which("gdb").expect("Couldn't locate gdb!");
    let gdb_s = gdb.to_string_lossy();
    // Next, create a TCP socket to listen on.
    let listener = TcpListener::bind("0.0.0.0:0").expect("Failed to bind TCP listen socket!");
    let addr = listener
        .local_addr()
        .expect("Failed to get listen socket address!");
    let remote_cmd = format!("target remote {}", addr);
    let assert = Assert::command(&[&gdb_s, "-nx", "-batch", "-ex", &remote_cmd]);
    let handler = Default::default();
    GDBTestBuilder {
        assert,
        handler,
        listener,
    }
}

#[test]
fn simple() {
    // GDB will not do much with a process that has already exited, which is the default
    // stop_reason.
    gdb_test()
        .assert(|a| a.stderr().contains("The target is not running"))
        .execute()
}
