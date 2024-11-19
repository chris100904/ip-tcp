use rustyline::{DefaultEditor, Result};
use std::{net::Ipv4Addr, sync::mpsc::Sender};

use super::{error::TcpError, CommandType, IPCommand, TCPCommand};

pub fn repl(sender: Sender<CommandType>) -> Result<()> {
    let mut rl = DefaultEditor::new()?;
    
    loop {
        let readline = rl.readline("> ");
        match readline {
            Ok(line) => {
                let args: Vec<&str> = line.split_whitespace().collect();
                if args.is_empty() {
                    continue;
                }
                match args[0] {
                    "li" => sender.send(CommandType::IP(IPCommand::ListInterfaces)).unwrap(),
                    "ln" => sender.send(CommandType::IP(IPCommand::ListNeighbors)).unwrap(),
                    "lr" => sender.send(CommandType::IP(IPCommand::ListRoutes)).unwrap(),
                    "down" => {
                        if args.len() == 2 {
                            sender.send(CommandType::IP(IPCommand::DisableInterface(args[1].to_string()))).unwrap();
                        } else {
                            println!("Usage: down <ifname>");
                        }
                    }
                    "up" => {
                        if args.len() == 2 {
                            sender.send(CommandType::IP(IPCommand::EnableInterface(args[1].to_string()))).unwrap();
                        } else {
                            println!("Usage: up <ifname>");
                        }
                    }
                    "send" => {
                        if args.len() >= 3 {
                            let addr = args[1];
                            let message = &line[args[0].len() + args[1].len() + 2..];
                            sender.send(CommandType::IP(IPCommand::SendTestPacket(addr.to_string(), message.to_string()))).unwrap();
                        } else {
                            println!("Usage: send <addr> <message>");
                        }
                    }
                    "a" => {
                        if args.len() == 2 {
                            sender.send(CommandType::TCP(TCPCommand::ListenAccept(args[1].parse().unwrap()))).unwrap();
                        } else {
                            println!("Usage: a <port>");
                        }
                    }
                    "c" => {
                      if args.len() < 3 {
                        println!("Usage: c <vip> <port>");
                      }
                      // Attempt to parse the virtual IP and port
                      let connect: std::result::Result<(Ipv4Addr, u16), TcpError> = (||
                        Ok((args[1].parse().map_err(|_| {
                            println!("Invalid virtual IP: {}", args[1]);
                            TcpError::ReplError { message: "Invalid virtual IP".to_string() }
                        })?,
                        args[2].parse().map_err(|_| {
                            println!("Invalid port: {}", args[2]);
                            TcpError::ReplError { message: "Invalid port".to_string() }
                        })?))
                      )();
                  
                      match connect {
                        Ok((vip, port)) => {
                            // If parsing was successful, send the command
                            sender
                                .send(CommandType::TCP(TCPCommand::TCPConnect(vip, port)))
                                .unwrap();
                        }
                        Err(_) => {
                            // In case of an error, show usage information
                            println!("Usage: c <vip> <port>");
                        }
                    }
                    }
                    "s" => {
                        if args.len() == 3 {
                            sender.send(CommandType::TCP(TCPCommand::TCPSend(args[1].parse().unwrap(), args[2].to_string()))).unwrap();
                        } else {
                            println!("Usage: s <socket ID> <bytes>");
                        }
                    }
                    "r" => {
                        if args.len() == 3 {
                            sender.send(CommandType::TCP(TCPCommand::TCPReceive(args[1].parse().unwrap(), args[2].parse().unwrap()))).unwrap();
                        } else {
                            println!("Usage: r <socket ID> <numbytes>");
                        }
                    }
                    "cl" => {
                        if args.len() == 2 {
                            sender.send(CommandType::TCP(TCPCommand::TCPClose(args[1].parse().unwrap()))).unwrap();
                        } else {
                            println!("Usage: cl <socket ID>");
                        }
                    }
                    "ls" => sender.send(CommandType::TCP(TCPCommand::ListSockets)).unwrap(),
                    "sf" => {
                        if args.len() == 4 {
                            // Attempt to parse the addr and port
                            let connect: std::result::Result<(Ipv4Addr, u16), TcpError> = (||
                                Ok((args[2].parse().map_err(|_| {
                                    println!("Invalid IP addr: {}", args[2]);
                                    TcpError::ReplError { message: "Invalid virtual IP".to_string() }
                                })?,
                                args[3].parse().map_err(|_| {
                                    println!("Invalid port: {}", args[3]);
                                    TcpError::ReplError { message: "Invalid port".to_string() }
                                })?))
                            )();
                            match connect {
                                Ok((addr, port)) => {
                                    // If parsing was successful, send the command
                                    sender
                                        .send(CommandType::TCP(TCPCommand::SendFile(args[1].to_string(), addr, port)))
                                        .unwrap();
                                }
                                Err(_) => {
                                    // In case of an error, show usage information
                                    println!("Usage: sf <file path> <addr> <port>");
                                }
                            }
                        } else {
                            println!("Usage: sf <file path> <addr> <port>");
                        }
                    }
                    "rf" => {
                        if args.len() == 3 {
                            sender.send(CommandType::TCP(TCPCommand::ReceiveFile(args[1].to_string(), args[2].parse().unwrap()))).unwrap();
                        } else {
                            println!("Usage: rf <dest file> <port>")
                        }
                    }
                    "exit" => {
                        sender.send(CommandType::IP(IPCommand::Exit)).unwrap();
                        break;
                    }
                    _ => println!("Unknown command: {}", args[0]),
                }
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }
    Ok(())
}
