//! - `percent_decode_all` defeats single/double/triple percent-encoding.
//! - `canonical_ip` folds decimal / hex / octal / short-form / IPv4-mapped-IPv6 hosts into one
//!   `IpAddr` (the same interpretation a libc resolver would use), killing SSRF encoding bypasses.
//! - `shell_injection` lexes a command with quote awareness, detecting chaining / substitution /
//!   redirection structurally instead of by naive metacharacter search.

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn percent_decode_once(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Repeatedly percent-decode until the string stabilizes (bounded), defeating multi-layer encoding
/// such as `%252e%252e` -> `%2e%2e` -> `..`.
pub fn percent_decode_all(s: &str) -> String {
    let mut cur = s.to_string();
    for _ in 0..5 {
        let next = percent_decode_once(&cur);
        if next == cur {
            break;
        }
        cur = next;
    }
    cur
}

/// Decode a string as standard base64 to UTF-8 text, or `None` if it is not strict, padded base64
/// or does not decode to printable text. Deliberately conservative (length a multiple of 4, strict
/// alphabet, valid UTF-8, no stray control bytes) so a normal argument is never mistaken for an
/// encoded payload. Used to inspect a base64-wrapped value (e.g. an internal URL) at guard time.
pub fn decode_base64_utf8(s: &str) -> Option<String> {
    let t = s.trim();
    if t.len() < 8 || t.len() % 4 != 0 {
        return None;
    }
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = t.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(t.len() / 4 * 3);
    let mut i = 0;
    while i < bytes.len() {
        let chunk = &bytes[i..i + 4];
        let pad = chunk.iter().filter(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && i + 4 != bytes.len()) {
            return None; // padding only at the very end
        }
        let mut n = 0u32;
        for (j, &c) in chunk.iter().enumerate() {
            let v = if c == b'=' { 0 } else { val(c)? };
            n |= (v as u32) << (18 - 6 * j);
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
        i += 4;
    }
    let decoded = String::from_utf8(out).ok()?;
    let printable = decoded
        .chars()
        .all(|c| !c.is_control() || c == '\n' || c == '\t' || c == '\r');
    if printable {
        Some(decoded)
    } else {
        None
    }
}

/// Parse one IPv4 part with radix by prefix: `0x`/`0X` hex, leading-`0` octal, else decimal — the
/// same rules `inet_aton` applies.
fn parse_ipv4_part(p: &str) -> Option<u64> {
    if p.is_empty() {
        return None;
    }
    if let Some(hex) = p.strip_prefix("0x").or_else(|| p.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else if p.len() > 1 && p.starts_with('0') {
        u64::from_str_radix(&p[1..], 8).ok()
    } else {
        p.parse::<u64>().ok()
    }
}

/// `inet_aton`-style parse: accepts `a.b.c.d`, `a.b.c`, `a.b`, and bare `a`, each part in any radix.
/// `2130706433`, `0x7f000001`, `0177.0.0.01`, and `127.1` all fold to `127.0.0.1`.
fn inet_aton(host: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let nums: Vec<u64> = parts.iter().map(|p| parse_ipv4_part(p)).collect::<Option<_>>()?;
    let ip: u32 = match nums.len() {
        1 => u32::try_from(nums[0]).ok()?,
        2 => {
            if nums[0] > 0xff || nums[1] > 0x00ff_ffff {
                return None;
            }
            ((nums[0] as u32) << 24) | (nums[1] as u32)
        }
        3 => {
            if nums[0] > 0xff || nums[1] > 0xff || nums[2] > 0xffff {
                return None;
            }
            ((nums[0] as u32) << 24) | ((nums[1] as u32) << 16) | (nums[2] as u32)
        }
        4 => {
            if nums.iter().any(|&n| n > 0xff) {
                return None;
            }
            ((nums[0] as u32) << 24) | ((nums[1] as u32) << 16) | ((nums[2] as u32) << 8) | (nums[3] as u32)
        }
        _ => return None,
    };
    Some(Ipv4Addr::from(ip))
}

/// Fold a host string into a canonical `IpAddr` if it denotes one (in any numeric encoding),
/// else `None` for a real hostname. Strips `[...]` IPv6 brackets.
pub fn canonical_ip(host: &str) -> Option<IpAddr> {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = IpAddr::from_str(h) {
        return Some(ip);
    }
    inet_aton(h).map(IpAddr::V4)
}


pub fn shell_injection(cmd: &str) -> Option<&'static str> {
    let b = cmd.as_bytes();
    let mut i = 0;
    let mut single = false;
    let mut double = false;
    while i < b.len() {
        let c = b[i];
        if single {
            if c == b'\'' {
                single = false;
            }
            i += 1;
            continue;
        }
        if double {
            match c {
                b'"' => double = false,
                b'`' => return Some("command substitution (backtick)"),
                b'$' if i + 1 < b.len() && b[i + 1] == b'(' => return Some("command substitution $()"),
                _ => {}
            }
            i += 1;
            continue;
        }
        match c {
            b'\'' => single = true,
            b'"' => double = true,
            b'`' => return Some("command substitution (backtick)"),
            b'$' if i + 1 < b.len() && b[i + 1] == b'(' => return Some("command substitution $()"),
            b';' => return Some("command separator ';'"),
            b'|' => return Some("pipe / command chaining '|'"),
            b'&' => return Some("background / command chaining '&'"),
            b'\n' | b'\r' => return Some("newline command chaining"),
            b'>' | b'<' => return Some("shell redirection"),
            _ => {}
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_multi_layer_encoding() {
        assert_eq!(percent_decode_all("%2e%2e%2f"), "../");
        assert_eq!(percent_decode_all("%252e%252e%252f"), "../"); // double-encoded
        assert_eq!(percent_decode_all("plain"), "plain");
    }

    #[test]
    fn folds_encoded_ipv4() {
        let loop_ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(canonical_ip("2130706433"), Some(loop_ip)); // decimal
        assert_eq!(canonical_ip("0x7f000001"), Some(loop_ip)); // hex
        assert_eq!(canonical_ip("0177.0.0.01"), Some(loop_ip)); // octal, dotted
        assert_eq!(canonical_ip("127.1"), Some(loop_ip)); // short form
        // cloud metadata endpoint as a bare decimal
        assert_eq!(canonical_ip("2852039166"), Some("169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn ipv4_mapped_ipv6_and_hostnames() {
        assert_eq!(canonical_ip("::ffff:127.0.0.1"), Some("::ffff:127.0.0.1".parse().unwrap()));
        assert_eq!(canonical_ip("[::1]"), Some("::1".parse().unwrap()));
        assert_eq!(canonical_ip("news.google.com"), None);
        assert_eq!(canonical_ip("localhost"), None);
    }

    #[test]
    fn shell_lexer_respects_quotes() {
        assert!(shell_injection("ls; rm -rf /").is_some());
        assert!(shell_injection("echo $(whoami)").is_some());
        assert!(shell_injection("cat a | sh").is_some());
        assert!(shell_injection("echo \"$(id)\"").is_some()); // substitution inside double quotes
        // A separator inside single/double quotes is inert — no false positive.
        assert!(shell_injection("echo 'a; b'").is_none());
        assert!(shell_injection("printf \"a; b; c\"").is_none());
        assert!(shell_injection("ls -la /var/log").is_none());
    }

    #[test]
    fn base64_decode_is_conservative() {
        assert_eq!(decode_base64_utf8("aGVsbG8="), Some("hello".to_string()));
        assert_eq!(decode_base64_utf8("short"), None); // length not a multiple of 4
        assert_eq!(decode_base64_utf8("has spaces here!"), None); // invalid alphabet
    }
}
