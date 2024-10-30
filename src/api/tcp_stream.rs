pub struct TcpStream {
    // TODO: add a TcpStream struct to hold the TcpStream object    
}

pub fn connect(addr: SocketAddr) -> Result<(TcpStream)> {
    // TODO: Implement TCP connecting
    unimplemented!();   
}

pub fn read(&self, buf: &mut[u8]) -> Result<usize> {
    // TODO: Implement TCP reading
    unimplemented!();
}

pub fn write(&self, buf: &[u8]) -> Result<usize> {
    // TODO: Implement TCP writing
    unimplemented!();
}   

pub fn close(&self) -> Result<()> {
    // TODO: Implement TCP closing
    unimplemented!();
}