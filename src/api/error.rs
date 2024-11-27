use thiserror::Error;

#[derive(Error, Debug)]
pub enum TcpError {
    #[error("TcpPacket Error: {}", message)]
    PacketError { message: String },
    #[error("TcpListener Error: {}", message)]
    ListenerError { message: String },
    #[error("TcpStream Error: {}", message)]
    StreamError { message: String },
    #[error("Connection Error: {}", message)]
    ConnectionError { message: String },
    #[error("REPL Error: {}", message)]
    ReplError { message: String },
    #[error("File Error: {}", message)]
    FileError { message: String },
    #[error("Read Error: {}", message)]
    ReadError { message: String },
    #[error("Retransmission Error: {}", message)]
    RTError { message: String },
}
