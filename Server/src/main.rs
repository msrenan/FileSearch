use std::fs;
use std::net::TcpListener;
use std::net::TcpStream;
use std::io::prelude::*;
use std::thread;
use std::path::Path;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use rand::Rng;
use sha2::{Sha256, Digest};
use colored::*;


/// Returns a random String
/// 
/// # Arguments
/// 
/// * `size: usize` - Limit the size of the string generated.
/// * `charset: &[u8]` - Reference to our charset database as bytes.
fn generate_secret_key_string(size: usize, charset: &[u8]) -> String {
    let mut rng = rand::rng();
    (0..size).map(|_|{
        let i = rng.random_range(0..charset.len());
        charset[i] as char
    }).collect()
}

/// Print a custom pattern message on concole
/// 
/// # Arguments
/// 
/// * `message: String` - Message that will be printed out.
fn report(message: String) -> () {
    println!("[{}] {} {}", "SERVER".blue(), "::".yellow(), message.truecolor(0, 255, 234));
}

/// Try to register a secret-key at proxy
/// 
/// # Arguments
/// 
/// * `secret: &str` - String reference that contains the secret-key.
/// 
/// ## Returns
/// Nothing if the registration is successfull
/// A String if any error occurr
fn register_with_proxy(secret: &str) -> Result<(), String> {
    match TcpStream::connect("0.0.0.0:2006") {
        Ok(mut stream) => {
            let request = format!(
                "POST /register-secret HTTP/1.1\r\n\
                Host: 0.0.0.0:2006\r\n\
                Content-Type: text/plain\r\n\
                Content-Length: {}\r\n\
                \r\n\
                {}",
                secret.len(),
                secret
            );

            stream.write(request.as_bytes()).unwrap();
            stream.flush().unwrap();

            let mut response_buffer = [0; 512];
            stream.read(&mut response_buffer).unwrap();
            let response_str = String::from_utf8_lossy(&response_buffer);

            if response_str.starts_with("HTTP/1.1 200 OK") {
                report(format!("Secret Key has been setted up with proxy."));
                stream.shutdown(std::net::Shutdown::Both).unwrap();
                Ok(())
            } else {
                Err(format!("Secret Key registration have failed. Proxy's answer: {}", response_str))
            }
        },
        Err(_) => Err(format!("Connection with proxy have failed!"))
    }
}

/// Container that store request data
/// 
/// # Arguments
/// All are String type:
/// * `sigature` - Proxy's Signature.
/// * `method` - Request's method.
/// * `uri` - Request's path.
/// * `host` - Request's host.
/// * `body` - Request's body.
/// * `file_name` - Request's file name.
#[allow(dead_code)]
struct Request {
    signature: String,
    method: String,
    uri: String,
    host: String,
    body: String,
    file_name: String,
}

/// Turn a request string into a struct
/// # Arguments
/// * `request: String` - Request that will be processed.
fn parse(request: String) -> Request {
    let method;
    let path;
    let host;
    let body;
    let proxy_signature;
    let main_header;
    let f_name;
    if request.contains("X-Proxy-Signature") {
        let proxy_signature_line = request.lines().nth(0).unwrap();
        proxy_signature = proxy_signature_line.split_once(": ").unwrap_or(("N/A", "N/A")).1;
        main_header = request.lines().skip(1).next().unwrap();
    } else {
        proxy_signature = "N/A";
        main_header = request.lines().next().unwrap();
    }

    let mut parts = main_header.split_whitespace();
    method = parts.next().unwrap();
    path = parts.next().unwrap();
    host = "0.0.0.0:2006";
    body = request.split_once("\r\n\r\n").unwrap().1;
    if method == "POST" && path == "/upload" {
        f_name = request.lines().nth(3).unwrap().split_once(": ").unwrap().1;
    } else {
        f_name = "None file has been passed";
    }

    Request {
        method: method.to_string(),
        signature: proxy_signature.to_string(),
        uri: path.to_string(),
        host: host.to_string(),
        body: body.to_string(),
        file_name: f_name.to_string()
    }
}

/// Handles the connection of a stream
/// 
/// # Arguments
/// * `mut stream: TcpStream` - Stream that holds the connection.
/// * `secret: Arc<String>` - Smart Pointer that holds the secret-key.
/// 
/// # Functionality
/// It recognizes a request, dissect it and if the request has the secret-key signature right,
/// sends the important parts of request to be routed. If the request has not the secret-key signature right,
/// or does not have any secret-key signature, it sends a error back.
fn handle_connection(mut stream: TcpStream, secret: Arc<String>) {
    let mut buffer = [0; 8192];
    stream.read(&mut buffer).unwrap();

    let request_string = String::from_utf8_lossy(&buffer[..]);

    let request = parse(request_string.to_string());

    report(format!("Received new request => \nSignature: {}\nMethod: {}\nURI: {}\nHost: {}\nProvider: {}\n\nBody: {}\n",
                            request.signature, request.method, request.uri, stream.peer_addr().unwrap(),request.host, request.body));
    
    if request.signature == secret.as_str() {
        report(format!("Request Signature Validated >>> Routing"));
        route(request, stream);
    } else {
        report(format!("Request Signature is invalid >>> Sending 403 Response"));
        let contents = fs::read_to_string("./pages/403.html").unwrap();

        let response = format!(
            "HTTP/1.1 403 FORBIDDEN\r\nContent-Length: {}\r\nContent-Type: text/html\r\n\r\n{}",
            contents.len(),
            contents
        );

        stream.write(response.as_bytes()).unwrap();
        stream.flush().unwrap();
    }

}

/// Secure texts that will be send in a html file
/// 
/// # Arguments
/// * `text: &str` - Text that will be secured.
fn escape_html(text: &str) -> String{
    let mut output = String::new();

    for c in text.chars() {
        match c {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            _ => output.push(c)
        }
    }
    output
}

/// Replace a html file's template by actually data and returns the whole html file content as a String
/// 
/// # Arguments
/// * `html_template: &str` - Html file content that will suffer a replacement.
/// * `placeholder: &str` - Local in the file where data will be placen.
/// * `data: &str` - Data that will substitute the placeholder.
fn fill_template(html_template: &str, placeholder: &str, data: &str) -> String {
    let safe_data = escape_html(data);

    html_template.replace(placeholder, &safe_data)
}

/// List all files in ```./data``` folder
fn list_files() -> String {
    let path = Path::new("./data");
    let all_files = fs::read_dir(path).unwrap();

    let mut file_names = Vec::new();

    for file in all_files {
        let file = file.unwrap();
        let file_type = file.file_type().unwrap();

        if file_type.is_file() {
            let file_os_name = file.file_name();
            let file_name = file_os_name.to_string_lossy().into_owned();
            file_names.push(file_name);
        }
    }

    file_names.sort();
    let all_names = file_names.join("\n");

    let index_content = fs::read_to_string("./pages/index.html").unwrap();

    fill_template(index_content.as_str(), "{{NOMES_DOS_ARQUIVOS}}", &all_names)

}

/// Routes a request and send it back to the stream
/// 
/// # Arguments
/// * `request: Request` - Request that will be routed.
/// * `mut stream: TcpStream` - Stream that holds connection.
fn route(request: Request, mut stream: TcpStream) {
    if request.method == "GET" {
        report(format!("Sending back routed (GET) request a response"));
        let file = match &request.uri {
            s if s.contains("?") => {
                let (_, file_var_and_value) = request.uri.split_once("?").unwrap();
                let (_, file_name) = file_var_and_value.split_once("=").unwrap();
                file_name.to_string()
            },
            _ => {
                let file_name = request.uri.replacen("/", "", 1);
                file_name.to_string()
            }
        };

        let (content_type, folder) = match file.as_str() {
            s if s.contains("html") || s == "" => {
                ("text/html;charset=utf-8", "pages")
            },
            s if s.contains("css") => {
                ("text/css", "pages")
            },
            s if s.contains("jpg") => {
                ("image/jpeg", "data")
            },
            s if s.contains("png") => {
                ("image/png", "data")
            }
            _ => ("text/html;charset=utf-8", "data")
        };

        let path = format!("./{}/{}", folder, file);

        let filepath = Path::new(path.as_str());
        let response;
        if filepath.exists() {
            report(format!("Requested file ({}) was found >>> Sending response", &file));
            let contents = match file {
                s if s == "" => {
                    let index_with_files_listed = list_files();

                    let index_w_fl_ofn = fill_template(&index_with_files_listed, "{{NOME_ARQUIVO_ABERTO}}", "N/A");
                    fill_template(&index_w_fl_ofn, "{{CONTEUDO_ARQUIVO_ABERTO}}", "")
                },
                _ => {
                    if !&file.ends_with(".css") {
                        let file_content = fs::read_to_string(filepath).unwrap();
                        let file_content = escape_html(&file_content);

                        let index_with_files_listed = list_files();

                        let index_w_fl_ofn = fill_template(&index_with_files_listed, "{{NOME_ARQUIVO_ABERTO}}", &file);
                        fill_template(&index_w_fl_ofn, "{{CONTEUDO_ARQUIVO_ABERTO}}", &file_content)
                    } else {
                        fs::read_to_string(filepath).unwrap()
                    }
                    
                }
            };
            
            response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\n\r\n{}",
                content_type,
                contents.len(),
                contents
            );
            
        } else {
            let contents = fs::read_to_string("./pages/404.html").unwrap();

            report(format!("Requested file ({}) was not found >>> Sending 404 response", &file));

            response = format!(
                "HTTP/1.1 404 NOT FOUND\r\nContent-Length: {}\r\nContent-Type: text/html\r\n\r\n{}",
                contents.len(),
                contents
            );
        }
        stream.write_all(response.as_bytes()).unwrap();
        stream.flush().unwrap();

    } else if request.method == "POST" && request.uri == "/upload" {
        report(format!("Storing file of (POST) request"));
        let mut path = format!("./data/{}", &request.file_name);
        let mut filepath = Path::new(&path);
        let mut counter = 2;
        while filepath.exists() {
            let (name, extention) = request.file_name.split_once(".").unwrap();
            path = format!("./data/{}_{}.{}", name, counter, extention);
            filepath = Path::new(&path);
            counter += 1;
        }

        let mut file = fs::File::create(filepath).unwrap();

        file.write_all(&request.body.trim().trim_end_matches('\0').as_bytes()).unwrap();

        report(format!("Client's file has been created"));

        let contents = {
            let index_with_files_listed = list_files();

            let index_w_fl_ofn = fill_template(&index_with_files_listed, "{{NOME_ARQUIVO_ABERTO}}", "N/A");
            fill_template(&index_w_fl_ofn, "{{CONTEUDO_ARQUIVO_ABERTO}}", "")
        };

        let response = format!(
                "HTTP/1.1 302 MOVED PERMANENTLY\r\nLocation:/\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
                contents.len(),
                contents
        );

        report("Sending back response".to_string());

        stream.write(&response.as_bytes()).unwrap();
        stream.flush().unwrap();
    }
}

fn main() {
    const SECRET_KEY_CHARSET: &[u8] = b"ABCDEFGIJKLMNOPQRTUVWXYZ\
                                        abcdefghijklmnopqrstuvwxyz\
                                        0123456789\
                                        !@#$%&*()-=[]{},.;?<>";
    
    //Generates a random String
    let secret_key_string = generate_secret_key_string(16, SECRET_KEY_CHARSET);
    
    //Make a SHA-256 key with random String data
    let mut hasher = Sha256::new();
    hasher.update(secret_key_string.as_bytes());
    let hash_as_bytes = hasher.finalize();
    let secret_key = hex::encode(hash_as_bytes);

    report(format!("Secret Key Generated! >>> {}", &secret_key[0..5]));

    //Server will keep trying to register secret_key on proxy until it succeeded
    while let Err(e) = register_with_proxy(&secret_key.as_str()) {
        eprintln!("[{}] {} {} >> {}", "SERVER".blue(), "::".yellow(), "Critical Error".red(),e);
        sleep(Duration::new(1, 0));
    }

    //Initializes secret_key in a smart pointer to avoid borrowing checker issues
    let arc_secret_key = Arc::new(secret_key);

    let listener =  TcpListener::bind("127.0.0.1:1445").unwrap();

    report(format!("Initialized at {}", listener.local_addr().unwrap()));

    for stream in listener.incoming() {
        let stream = stream.unwrap();
        let secret_key_clone = Arc::clone(&arc_secret_key);
        thread::spawn(move || {
            handle_connection(stream, secret_key_clone);
        });
    }
}
