use rustyline::{DefaultEditor, Result};
use std::sync::mpsc::Sender;
use crate::api::Command;

pub fn repl(sender: Sender<Command>) -> Result<()> {
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
                    "li" => sender.send(Command::ListInterfaces).unwrap(),
                    "ln" => sender.send(Command::ListNeighbors).unwrap(),
                    "lr" => sender.send(Command::ListRoutes).unwrap(),
                    "down" => {
                        if args.len() == 2 {
                            sender.send(Command::DisableInterface(args[1].to_string())).unwrap();
                        } else {
                            println!("Usage: down <ifname>");
                        }
                    }
                    "up" => {
                        if args.len() == 2 {
                            sender.send(Command::EnableInterface(args[1].to_string())).unwrap();
                        } else {
                            println!("Usage: up <ifname>");
                        }
                    }
                    "send" => {
                        if args.len() >= 3 {
                            let addr = args[1];
                            let message = &line[args[0].len() + args[1].len() + 2..];
                            sender.send(Command::SendTestPacket(addr.to_string(), message.to_string())).unwrap();
                        } else {
                            println!("Usage: send <addr> <message>");
                        }
                    }
                    "a" => {
                        if args.len() == 2 {
                            sender.send(Command::ListenAccept(args[1].to_string())).unwrap();
                        } else {
                            println!("Usage: a <port>");
                        }
                    }
                    "c" => {
                        if args.len() == 3 {
                            sender.send(Command::TCPConnect(args[1].to_string(), args[2].to_string())).unwrap();
                        } else {
                            println!("Usage: c <vip> <port>");
                        }
                    }
                    "s" => {
                        if args.len() == 3 {
                            sender.send(Command::TCPSend(args[1].parse().unwrap(), args[2].to_string())).unwrap();
                        } else {
                            println!("Usage: s <socket ID> <bytes>");
                        }
                    }
                    "r" => {
                        if args.len() == 3 {
                            sender.send(Command::TCPReceive(args[1].parse().unwrap(), args[2].parse().unwrap())).unwrap();
                        } else {
                            println!("Usage: r <socket ID> <numbytes>");
                        }
                    }
                    "cl" => {
                        if args.len() == 2 {
                            sender.send(Command::TCPClose(args[1].parse().unwrap())).unwrap();
                        } else {
                            println!("Usage: cl <socket ID>");
                        }
                    }
                    "ls" => sender.send(Command::ListSockets).unwrap(),
                    "sf" => {
                        if args.len() == 4 {
                            sender.send(Command::SendFile(args[1].to_string(), args[2].to_string(), args[3].parse().unwrap())).unwrap();
                        } else {
                            println!("Usage: sf <file path> <addr> <port>");
                        }
                    }
                    "rf" => {
                        if args.len() == 3 {
                            sender.send(Command::ReceiveFile(args[1].to_string(), args[2].parse().unwrap())).unwrap();
                        } else {
                            println!("Usage: rf <dest file> <port>")
                        }
                    }
                    "exit" => {
                        sender.send(Command::Exit).unwrap();
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
