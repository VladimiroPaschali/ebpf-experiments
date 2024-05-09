use serde_derive::{Deserialize, Serialize};
use serde_json::{self, Map, Value};
use std::io::{self, Read, Write};
use std::net::TcpStream;

#[derive(Serialize, Deserialize)]
struct InxpectServerMessage {
    code: i32,
    value: i32,
    buffer: Value,
}

impl InxpectServerMessage {
    fn new(code: i32, value: i32, buffer: Value) -> Self {
        Self {
            code,
            value,
            buffer,
        }
    }
}

struct InxpectClient {
    stream: TcpStream,
}

impl InxpectClient {
    fn new(addr: String, port: i32) -> Self {
        Self {
            stream: TcpStream::connect(format!("{}:{}", addr, port)).unwrap(),
        }
    }

    fn send_message(&mut self, message: InxpectServerMessage) -> io::Result<()> {
        // Serialize the data to JSON
        let json_data = serde_json::to_string(&message)?;

        // Send the JSON data to the server
        self.stream.write_all(json_data.as_bytes())?;

        Ok(())
    }

    fn receive_message(&mut self) -> io::Result<InxpectServerMessage> {
        // Read the response from the server
        let mut buffer = [0; 1024];
        let bytes_read = self.stream.read(&mut buffer)?;

        // Convert the response to a string
        let response = String::from_utf8_lossy(&buffer[..bytes_read]);

        // Deserialize the response JSON
        let received_data: InxpectServerMessage = serde_json::from_str(&response)?;

        Ok(received_data)
    }

    fn request_get_psections(&mut self) -> io::Result<Value> {
        let mut message = InxpectServerMessage::new(4, 0, Value::Null);

        // Send the message to the server
        self.send_message(message)?;

        message = self.receive_message()?;

        Ok(message.buffer)
    }

    fn request_psection_change_event(
        &mut self,
        psection_name: &str,
        event_name: &str,
    ) -> io::Result<Value> {
        let mut buffer_map = Map::new();
        buffer_map.insert("name".to_string(), Value::String(psection_name.to_string()));
        buffer_map.insert("event".to_string(), Value::String(event_name.to_string()));

        // Convert the map to a JSON value
        let buffer_value = Value::Object(buffer_map);

        let mut message = InxpectServerMessage::new(1, 0, buffer_value);

        // Send the message to the server
        self.send_message(message)?;

        message = self.receive_message()?;

        Ok(message.buffer)
    }
}

struct Console {
    client: InxpectClient,
}

impl Console {
    fn new(client: InxpectClient) -> Self {
        Self { client }
    }

    fn run(&mut self) -> io::Result<()> {
        let mut rl = rustyline::Editor::<()>::new();
        loop {
            let readline = rl.readline(">> ");
            match readline {
                Ok(line) => {
                    let command: Vec<&str> = line.trim().split_whitespace().collect();
                    if command[0] == "quit" {
                        break;
                    }

                    match command[0] {
                        "get" => {
                            self.parse_get_command(command[1..].to_vec());
                        }
                        "set" => {
                            self.parse_set_command(command[1..].to_vec());
                        }
                        _ => println!("Comando sconosciuto!"),
                    }
                }
                Err(_) => {
                    println!("Errore durante la lettura dell'input");
                    break;
                }
            }
        }
        Ok(())
    }

    fn parse_get_command(&mut self, get_command: Vec<&str>) {
        match get_command[0] {
            "psections" => {
                if get_command.len() > 1 {
                    println!("{0} command not need arguments!", get_command[0]);
                    // this could be a macro
                }
                self.pretty_print_get_psections().unwrap();
            }
            _ => println!("Unkwon {0} command using get!", get_command[0]),
        }
    }

    fn parse_set_command(&mut self, set_command: Vec<&str>) {
        match set_command[0] {
            "event" => {
                let args = set_command.iter().skip(1).collect::<Vec<_>>();
                if args.len() != 2 {
                    println!(
                        "{0} command need 2 arguments!\n\t psection name and new event to set.",
                        set_command[0]
                    );
                    return;
                }
                _ = self.pretty_print_psection_change_event(args[0], args[1]);
            }
            _ => println!("Unkwon {0} command using set!", set_command[0]),
        }
    }
    // MISSING ERROR CHECKING
    fn pretty_print_get_psections(&mut self) -> io::Result<()> {
        let psections = self.client.request_get_psections()?;

        println!("Psections:");
        for psection in psections.as_array().unwrap() {
            println!("\t{}", psection);
        }

        Ok(())
    }

    fn pretty_print_psection_change_event(&mut self, psection_name: &str, event_name: &str) {
        _ = self
            .client
            .request_psection_change_event(&psection_name, &event_name);
        println!(
            "Psection {} changed event to {}!",
            psection_name, event_name
        )
    }
}

fn main() -> io::Result<()> {
    let ix = InxpectClient::new("0.0.0.0".to_string(), 8080);
    let mut console = Console::new(ix);
    console.run()?;
    Ok(())
}
