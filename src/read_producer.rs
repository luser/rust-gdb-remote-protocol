use nom::IResult::*;
use nom::{Consumer,ConsumerState,Move,Input,Producer};
use std::io::{BufRead,BufReader,Read,SeekFrom};

#[derive(PartialEq)]
pub enum ReadProducerState {
    Ok,
    Eof,
    Error,
}

pub struct ReadProducer<T : Read> {
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
