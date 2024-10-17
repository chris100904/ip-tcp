use rustyline::error::ReadlineError;
use rustyline::Editor; 
use std::sync::mpsc::Sender;

fn list_interfaces() {}

fn list_neighbors() {}

fn list_routes() {}

fn disable_interface(ifname: &str) {}

fn enable_interface(ifname: &str) {}

fn send_test_packet(addr: &str, message: &str){

}

fn repl() {
    let mut rl = Editor::<()>::new(); 

    loop {
        let readline= rl.readline("> ");
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str());

                // split the input command into parts
                let args: Vec<&str> = line.split_whitespace().collect();
                if args.is_empty() {
                    continue; 
                }

                // match the command
                match args[0] {
                    "li" => list_interfaces(),
                    "ln" => list_neighbors(),
                    "lr" => list_routes(),
                    "down" => {
                        if args.len() == 2 {
                            disable_interface(args[1]);
                        } else {
                            println!("Usage: down <ifname>");
                        }
                    }
                    "up" => {
                        if args.len() == 2 {
                            enable_interface(args[1]);
                        } else {
                            println!("Usage: up <ifname>");
                        }
                    }
                    "send" => {
                        if args.len() >= 3 {
                            let addr = args[1];
                            let message = &line[args[0].len() + args[1].len() + 2..];
                            send_test_packet(addr, message);
                        } else {
                            println!("Usage: send <addr> <message>");
                        }
                    }
                    "exit" => break,
                    _ => println!("Unknown command: {}", args[0]),
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C detected, exiting...");
                break;
            }
            Err(ReadlineError::Eof) => {
                println!("CTRL-D detected, exiting...");
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }
}