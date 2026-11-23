//! Standard input, read on a thread of its own (#496).
//!
//! `tokio::io::stdin` reads on the runtime's blocking pool, and a blocking
//! read cannot be cancelled: runtime shutdown waits for it. The serve loop
//! always has a read in flight, so a server told to stop by a signal would
//! hang until its client closed the pipe. Shutdown must wait for one thing
//! only, the supervisors that kill and reap the workers of dropped calls, and
//! those are on the blocking pool too.
//!
//! So stdin is read by a plain thread, which nothing joins, and handed to the
//! loop through a channel. The process can exit while that thread is still
//! blocked in `read`.

use std::io::Read;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::mpsc;

/// Bytes from standard input, as an [`AsyncRead`].
pub struct Stdin {
    chunks: mpsc::Receiver<std::io::Result<Vec<u8>>>,
    current: Vec<u8>,
    offset: usize,
}

/// Start the reader thread.
pub fn stdin() -> std::io::Result<Stdin> {
    // A small bound: the thread waits for the loop instead of buffering input
    // without limit.
    let (tx, chunks) = mpsc::channel(4);
    std::thread::Builder::new()
        .name("mcp-stdin".to_string())
        .spawn(move || {
            let mut input = std::io::stdin().lock();
            let mut buf = vec![0_u8; 64 * 1024];
            loop {
                let sent = match input.read(&mut buf) {
                    // End of input: dropping the sender ends the stream.
                    Ok(0) => break,
                    Ok(n) => tx.blocking_send(Ok(buf[..n].to_vec())),
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => {
                        let _ = tx.blocking_send(Err(error));
                        break;
                    }
                };
                if sent.is_err() {
                    break; // the server stopped reading
                }
            }
        })?;
    Ok(Stdin {
        chunks,
        current: Vec::new(),
        offset: 0,
    })
}

impl AsyncRead for Stdin {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if self.offset < self.current.len() {
                let n = buf.remaining().min(self.current.len() - self.offset);
                buf.put_slice(&self.current[self.offset..self.offset + n]);
                self.offset += n;
                return Poll::Ready(Ok(()));
            }
            match self.chunks.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                // The reader thread ended at end of input: report EOF.
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(error)),
                Poll::Ready(Some(Ok(chunk))) => {
                    self.current = chunk;
                    self.offset = 0;
                }
            }
        }
    }
}
