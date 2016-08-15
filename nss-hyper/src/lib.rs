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
use std::time::Duration;

pub struct NssClient<N: NetworkStream = hyper::net::HttpStream> {
    factory: FileWrapper<StreamToFile<N>>,
} 

impl<N: NetworkStream> NssClient<N> {
    pub fn new() -> Self {
        nss::init().unwrap(); // FIXME don't use unwrap
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
    inner: Mutex<StreamToFileInner<N>>,
}

struct StreamToFileInner<N: NetworkStream> {
    stream: N,
    timeouts: Timeouts,
    connected: bool,
}

struct Timeouts {
    read: Option<Duration>,
    write: Option<Duration>,
}
impl Timeouts {
    fn new() -> Self {
        Timeouts {
            read: None,
            write: None,
        }
    }
}

impl<N: NetworkStream> StreamToFile<N> {
    fn new(stream: N) -> Self {
        StreamToFile {
            inner: Mutex::new(StreamToFileInner {
                stream: stream,
                timeouts: Timeouts::new(),
                connected: false,
            })
        }
    }
}

impl<N: NetworkStream> FileMethods for StreamToFile<N> {
    // FIXME: do I even need `read` and `write`?
    fn read(&self, buf: &mut [u8]) -> nss::Result<usize> {
        self.recv(buf, false, None)
    }
    fn write(&self, buf: &[u8]) -> nss::Result<usize> {
        self.send(buf, None)
    }

    fn connect(&self, _addr: SocketAddr, _timeout: Option<Duration>) -> nss::Result<()> {
        let mut this = self.inner.lock().unwrap();
        this.connected = true;
        Ok(())
    }

    fn recv(&self, buf: &mut [u8], peek: bool, timeout: Option<Duration>) -> nss::Result<usize> {
        if peek {
            unimplemented!()
        }
        let mut this = self.inner.lock().unwrap();
        if this.timeouts.read != timeout {
            try!(this.stream.set_read_timeout(timeout));
            this.timeouts.read = timeout
        }
        Ok(try!(this.stream.read(buf)))
    }

    fn send(&self, buf: &[u8], timeout: Option<Duration>) -> nss::Result<usize> {
        let mut this = self.inner.lock().unwrap();
        if this.timeouts.write != timeout {
            try!(this.stream.set_write_timeout(timeout));
            this.timeouts.write = timeout
        }
        Ok(try!(this.stream.write(buf)))
    }

    fn getpeername(&self) -> nss::Result<SocketAddr> {
        let mut this = self.inner.lock().unwrap();
        if this.connected {
            this.stream.peer_addr().map_err(Into::into)
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
    // This Arc is because network streams need to be Clone... because
    // they're like file descriptors, I guess?  But what does that
    // mean for stateful streams like TLS?  Is this actually the right
    // Clone behavior?
    inner: Arc<FileToStreamInner>,
}

struct FileToStreamInner {
    file: File,
    // This Mutex is because the timeouts are changed by &self methods,
    // which sort of makes sense as being like `setsockopt` on a file
    // descriptor... but `peer_addr` takes &mut self so ???.
    timeouts: Mutex<Timeouts>,
}

impl FileToStream {
    pub fn new(file: File) -> Self {
        FileToStream {
            inner: Arc::new(FileToStreamInner {
                file: file,
                timeouts: Mutex::new(Timeouts::new()),
            })
        }
    }
}

impl Read for FileToStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let timeout = self.inner.timeouts.lock().unwrap().read;
        // Is there some reason why try! insists on From instead of the weaker bound Into?
        self.inner.file.recv(buf, false, timeout).map_err(Into::into)
    }
}

impl Write for FileToStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let timeout = self.inner.timeouts.lock().unwrap().write;
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
        self.inner.timeouts.lock().unwrap().read = dur;
        Ok(())
    }
    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.timeouts.lock().unwrap().write = dur;
        Ok(())
    }
    // TODO: map NetworkStream::close() to PR_Shutdown?
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
