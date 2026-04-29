use std::fs;
use std::io;
use std::net::TcpListener;
use std::net::TcpStream;
use std::io::prelude::*;
use std::thread;
use std::sync::{Arc, Mutex};
use colored::*;

type SharedSecret = Arc<Mutex<Option<String>>>;

/// Print a custom pattern message on concole
/// 
/// # Arguments
/// 
/// * `message: String` - Message that will be printed out.
fn report(message: String) -> () {
    println!("[{}] {} {}", "REVERSE PROXY".red(), "::".yellow(), message.truecolor(248, 150, 1));
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
#[allow(dead_code)]
struct Request {
    signature: String,
    method: String,
    uri: String,
    host: String,
    body: String
}

/// Turn a request string into a struct
/// # Arguments
/// * `request: String` - Request that will be processed.
fn parse(request: String) -> Request {
    let main_header = request.lines().next().unwrap();
    let mut parts = main_header.split_whitespace();
    let method = parts.next().unwrap();
    let path = parts.next().unwrap();
    let host = "0.0.0.0:2006";
    let (_, body)  = request.split_once("\r\n\r\n").unwrap();

    Request {
        method: method.to_string(),
        signature: "N/A".to_string(),
        uri: path.to_string(),
        host: host.to_string(),
        body: body.to_string()
    }
}

/// Handles proxy's connection
/// 
/// # Arguments
/// * `mut stream: TcpStream` - Stream that holds connection with client.
/// * `secret_state: SharedSecret` - Variable that holds secret-key came from server.
fn proxy_handler(mut stream: TcpStream, secret_state: SharedSecret) {
    let mut buffer = [0; 4096];
    stream.read(&mut buffer).unwrap();
    let request_string = String::from_utf8_lossy(&buffer[..]);

    let mut request = parse(request_string.to_string());

    if request.method == "POST" && request.uri == "/register-secret" {
        let body = request.body.trim().trim_end_matches('\0');
        //Locks local thread to keep secret_key value
        let mut signature_key = secret_state.lock().unwrap();
        *signature_key = Some(body.to_string());

        report(format!("Received server's key >>> {}...", &body[0..5]));
        report(format!("Sending back positive response"));

        let response = "HTTP/1.1 200 OK\r\n\r\n";
        stream.write(response.as_bytes()).unwrap();
        stream.flush().unwrap();
    } else if request.method == "GET" && request.uri == "/favicon.ico" {
        report(format!("Client requested favicon.ico >>> Sending 204 response"));
        let response = "HTTP/1.1 204 NO CONTENT\r\n\r\n";
        stream.write(response.as_bytes()).unwrap();
        stream.flush().unwrap();

    } else {
        report(format!("Received new request => \n\
                            Method: {}\nURI: {}\nHost: {}\nProvider: {}\n\nBody: {}\n",
                            request.method, request.uri, request.host, stream.peer_addr().unwrap(),request.body));
        //Secure that secret_state can be accessed by this local thread
        let signature_key_guard = match secret_state.lock() {
            Ok(guard) => guard,
            Err(_) => {
                let contents = fs::read_to_string("./pages/503.html").unwrap();
                let response = format!(
                    "HTTP/1.1 503 SERVICE UNAVAIBLE\r\n\
                    Content-Length: {}\r\n\
                    Content-Type: text/html;charset=utf-8\r\n\
                    \r\n\
                    {}",
                    contents.len(),
                    contents
                );
                stream.write(response.as_bytes()).unwrap();
                stream.flush().unwrap();
                panic!();
            }
        };
        //Access by reference the secret_key value from the lock_guard
        let signature_key = match &*signature_key_guard {
            Some(s) => s.clone(),
            None => {
                let contents = fs::read_to_string("./pages/503.html").unwrap();
                let response = format!(
                    "HTTP/1.1 503 SERVICE UNAVAIBLE\r\n\
                    Content-Length: {}\r\n\
                    Content-Type: text/html; charset=utf-8\r\n\
                    \r\n\
                    {}",
                    contents.len(),
                    contents
                );
                stream.write(response.as_bytes()).unwrap();
                stream.flush().unwrap();
                return;
            }
        };
        //Unlock thread, realeasing secret_key common value from this thread
        drop(signature_key_guard);

        request.signature = signature_key;

        proxy_forward(request, stream);
    }
}

/// Passes Forward a request of a client to the server
/// 
/// # Arguments
/// * `request: Request` - Container that holds request data.
/// * `mut stream: TcpStream` - Stream that holds connection with client.
fn proxy_forward(request: Request, mut stream: TcpStream) {
    let mut server_stream = TcpStream::connect("127.0.0.1:1445").unwrap();
    let server_request;
    if request.method == "GET" {
        server_request = format!(
            "X-Proxy-Signature: {}\r\n{} {} HTTP/1.1\r\nHost: {}\r\n\r\n{}",
            request.signature,
            request.method,
            request.uri,
            request.host,
            request.body
        );

    } else if request.method == "POST" && request.uri == "/upload" {

        let line = request.body.lines().nth(1).unwrap().split("; ").nth(2).unwrap();

        let file_name = line.split_once("=").unwrap().1.replace('"', "");

        let file_content = request.body.split_once("\r\n\r\n").unwrap().1.split_once("\r\n").unwrap().0.trim_end_matches('\0').trim();

        server_request = format!(
            "X-Proxy-Signature: {}\r\n{} {} HTTP/1.1\r\nHost: {}\r\nFile-Name: {}\r\nContent-Length: {}\r\n\r\n{}",
            request.signature,
            request.method, 
            request.uri,
            request.host,
            file_name,
            file_content.len(),
            file_content
        );

    } else {
        report(format!(
            "Strange Request >>> Method: {} | Path: {} | Body: {}", 
            request.method, request.uri, request.body
        ));
        return;
    }
    server_stream.write(server_request.as_bytes()).unwrap();
    server_stream.flush().unwrap();

    report(format!("Request ({}) successfuly forwarded", request.method));

    io::copy(&mut server_stream, &mut stream).unwrap();
    report(format!("Received answer from Server >>> Passing forward to Client"));
    stream.flush().unwrap();
    server_stream.shutdown(std::net::Shutdown::Both).unwrap();
}

fn main() {
    let listener = TcpListener::bind("0.0.0.0:2006").unwrap();

    report(format!("Initialized at {}", listener.local_addr().unwrap()));

    //Initializes the smart pointer that will hold the secret_key
    let secret_state: SharedSecret = Arc::new(Mutex::new(None));

    for stream in listener.incoming() {
        let stream = stream.unwrap();
        //Creates new pointer to secret_state
        let secret_state_clone = Arc::clone(&secret_state);
        thread::spawn(move || {
            proxy_handler(stream, secret_state_clone);
        });
    }
}
