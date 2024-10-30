pub struct TcpListener {
    // TODO: add a TcpListener struct to hold the TcpListener object
}

impl TcpListener {

    pub fn listen(port: u16) -> Result<(TcpListener)> {
        // TODO: Implement TCP listening
        unimplemented!();
    }

    pub fn accept(&self) -> Result<(TcpStream, SocketAddr)> {
        // TODO: Implement TCP accepting
        unimplemented!();
    }

    pub fn close(&self) -> Result<()> {
        // TODO: Implement TCP closing
        unimplemented!();
    }
}