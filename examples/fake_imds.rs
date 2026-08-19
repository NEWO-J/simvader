//! A stand-in for the AWS instance metadata service (IMDS) at 169.254.169.254, bound to loopback.
//! The mock server's `fetch` sink, under `--danger`, rewrites metadata IPs to this address, so the
//! SSRF in the demo is a real socket over real HTTP — but it can only ever reach 127.0.0.1, and the
//! credentials it returns are obvious fakes. Nothing here can leak a real secret.
//!
//! Run:  fake_imds [ADDR]      (default 127.0.0.1:8799)

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

const ROLE: &str = "demo-app-instance-role";

fn main() {
    let addr = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:8799".to_string());
    let listener = TcpListener::bind(&addr).unwrap_or_else(|e| {
        eprintln!("fake_imds: cannot bind {addr}: {e}");
        std::process::exit(1);
    });
    eprintln!("fake_imds: serving fake credentials on http://{addr}/ (loopback only)");
    for conn in listener.incoming().flatten() {
        let _ = serve(conn);
    }
}

fn serve(mut stream: TcpStream) -> std::io::Result<()> {
    // Read (and ignore) the request line/headers; we answer every path the same way.
    let mut buf = [0u8; 2048];
    let _ = stream.read(&mut buf)?;
    let request = String::from_utf8_lossy(&buf);
    let path = request.split_whitespace().nth(1).unwrap_or("/");

    // If the path stops at the role directory, list the role name (as real IMDS does); otherwise
    // hand back the credential document itself. Either way it's fake.
    let (body, what) = if path.ends_with("/iam/security-credentials/") {
        (ROLE.to_string(), "role name")
    } else {
        (credentials_json(), "IAM credentials")
    };
    eprintln!("[imds] <- SSRF reached the metadata service: {path}  (served {what})");

    let response = format!(
        "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn credentials_json() -> String {
    // Shaped like a real IMDS credential response; every value is a placeholder.
    format!(
        "{{\n  \"Code\": \"Success\",\n  \"Type\": \"AWS-HMAC\",\n  \"Role\": \"{ROLE}\",\n  \
         \"AccessKeyId\": \"ASIAEXAMPLEFAKEKEY01\",\n  \
         \"SecretAccessKey\": \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\",\n  \
         \"Token\": \"IQoJb3JpZ2luX2VjEXAMPLEFAKESESSIONTOKEN==\",\n  \
         \"Expiration\": \"2026-07-10T23:59:59Z\"\n}}"
    )
}
