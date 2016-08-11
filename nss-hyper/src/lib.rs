extern crate hyper;
extern crate nss;

use hyper::net::{NetworkStream, SslClient};
use nss::{File, FileMethods, FileWrapper, TLSSocket};
use nss::nspr::error::PR_NOT_CONNECTED_ERROR;
use nss::nspr::fd::PR_DESC_SOCKET_TCP;

use std::io;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub struct NssClient<N: NetworkStream = hyper::net::HttpStream> {
    factory: FileWrapper<StreamToFile<N>>,
} 

impl<N: NetworkStream> NssClient<N> {
    pub fn new() -> Self {
        nss::init().unwrap(); // FIXME unwrap
        NssClient {
            factory: FileWrapper::new(PR_DESC_SOCKET_TCP),
        }
    }
}

macro_rules! nss_try {
    ($e:expr) => { try!($e.map_err(Into::<io::Error>::into)) }
}

impl<N: NetworkStream + Clone> SslClient<N> for NssClient<N> {
    type Stream = FileToStream;

    fn wrap_client(&self, mut stream: N, _host: &str) -> hyper::error::Result<Self::Stream> {
        let peer_addr = try!(stream.peer_addr());
        let backend = StreamToFile::new(stream);
        let inner = self.factory.wrap(backend);
        let mut outer = nss_try!(TLSSocket::new(inner));
        nss_try!(outer.disable_security());
        // This "connect" just fixes NSS's state; handshake isn't send until first write.
        nss_try!(outer.connect(peer_addr, None));
        Ok(FileToStream::new(outer.into_file()))
    }
}

struct StreamToFile<N: NetworkStream> {
    stream: Mutex<N>,
    connected: AtomicBool,
}

impl<N: NetworkStream> StreamToFile<N> {
    fn new(stream: N) -> Self {
        StreamToFile {
            stream: Mutex::new(stream),
            connected: AtomicBool::new(false),
        }
    }
}

impl<N: NetworkStream> FileMethods for StreamToFile<N> {
    // FIXME: do I need these?
    fn read(&self, buf: &mut [u8]) -> nss::Result<usize> {
        self.recv(buf, false, None)
    }
    fn write(&self, buf: &[u8]) -> nss::Result<usize> {
        self.send(buf, None)
    }

    fn connect(&self, _addr: SocketAddr, _timeout: Option<Duration>) -> nss::Result<()> {
        self.connected.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn recv(&self, buf: &mut [u8], peek: bool, timeout: Option<Duration>) -> nss::Result<usize> {
        if peek {
            unimplemented!()
        }
        let mut stream = self.stream.lock().unwrap();
        try!(stream.set_read_timeout(timeout));
        Ok(try!(stream.read(buf)))
    }

    fn send(&self, buf: &[u8], timeout: Option<Duration>) -> nss::Result<usize> {
        let mut stream = self.stream.lock().unwrap();
        try!(stream.set_write_timeout(timeout));
        Ok(try!(stream.write(buf)))
    }

    fn getpeername(&self) -> nss::Result<SocketAddr> {
        if self.connected.load(Ordering::SeqCst) {
            self.stream.lock().unwrap().peer_addr().map_err(Into::into)
        } else {
            Err(PR_NOT_CONNECTED_ERROR.into())
        }
    }

    fn get_nonblocking(&self) -> nss::Result<bool> {
        Ok(false)
    }
}


#[derive(Clone)]
pub struct FileToStream {
    // The Arc is because network streams need to be Clone for unexplained reasons.
    inner: Arc<FileToStreamInner>,
}

struct FileToStreamInner {
    file: File,
    // The Mutex is because the timeouts are changed by &self methods, which makes no sense.
    timeouts: Mutex<[Option<Duration>; 2]>,
}

impl FileToStream {
    pub fn new(file: File) -> Self {
        FileToStream {
            inner: Arc::new(FileToStreamInner {
                file: file,
                timeouts: Mutex::new([None; 2])
            })
        }
    }
}

impl Read for FileToStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let timeout = self.inner.timeouts.lock().unwrap()[0];
        // Is there some reason why try! insists on From instead of the weaker bound Into?
        self.inner.file.recv(buf, false, timeout).map_err(Into::into)
    }
}

impl Write for FileToStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let timeout = self.inner.timeouts.lock().unwrap()[1];
        self.inner.file.send(buf, timeout).map_err(Into::into)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl NetworkStream for FileToStream {
    fn peer_addr(&mut self) -> io::Result<SocketAddr> {
        self.inner.file.getpeername().map_err(Into::into)
    }
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.timeouts.lock().unwrap()[0] = dur;
        Ok(())
    }
    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.timeouts.lock().unwrap()[1] = dur;
        Ok(())
    }
    // TODO: map close() to PR_Shutdown?
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
