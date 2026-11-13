//! Encodings shared with the Dart implementation: standard base64, length
//! prefixes, the two-word big-endian `u64`, and compact JSON.
//!
//! JSON objects keep insertion order. Dart's `jsonEncode` does the same, and
//! the recovery backup encrypts that exact text. A missing field and a JSON
//! `null` are the same thing, because Dart's `j[k] == null` is true for both.

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::error::{Error, Result};

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding, matching `dart:convert` `base64Encode`.
pub fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = (u32::from(data[i]) << 16) | (u32::from(data[i + 1]) << 8) | u32::from(data[i + 2]);
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        out.push(B64[((n >> 6) & 63) as usize] as char);
        out.push(B64[(n & 63) as usize] as char);
        i += 3;
    }
    match data.len() - i {
        1 => {
            let n = u32::from(data[i]) << 16;
            out.push(B64[((n >> 18) & 63) as usize] as char);
            out.push(B64[((n >> 12) & 63) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = (u32::from(data[i]) << 16) | (u32::from(data[i + 1]) << 8);
            out.push(B64[((n >> 18) & 63) as usize] as char);
            out.push(B64[((n >> 12) & 63) as usize] as char);
            out.push(B64[((n >> 6) & 63) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

fn b64_value(c: u8) -> Result<u8> {
    Ok(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return Err(Error::Invalid("base64")),
    })
}

/// Standard base64. Padding is required, as in `dart:convert` `base64Decode`.
pub fn b64_decode(text: &str) -> Result<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err(Error::Invalid("base64"));
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut i = 0;
    while i < bytes.len() {
        let (a, b, c, d) = (bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]);
        let pad = match (c, d) {
            (b'=', b'=') => 2,
            (_, b'=') => 1,
            (b'=', _) => return Err(Error::Invalid("base64")),
            _ => 0,
        };
        if pad > 0 && i + 4 != bytes.len() {
            return Err(Error::Invalid("base64"));
        }
        let av = b64_value(a)?;
        let bv = b64_value(b)?;
        let cv = if pad == 2 { 0 } else { b64_value(c)? };
        let dv = if pad >= 1 { 0 } else { b64_value(d)? };
        let n =
            (u32::from(av) << 18) | (u32::from(bv) << 12) | (u32::from(cv) << 6) | u32::from(dv);
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
        i += 4;
    }
    Ok(out)
}

/// URL-safe base64 without padding (`+`/`/` swapped, `=` removed).
pub fn b64url_encode(data: &[u8]) -> String {
    b64_encode(data)
        .replace('+', "-")
        .replace('/', "_")
        .replace('=', "")
}

/// Length-prefixed concatenation. Each part is a big-endian `u32` length then
/// the bytes, matching `lp` in the Dart codec.
pub fn lp(parts: &[&[u8]]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for part in parts {
        let len = u32::try_from(part.len()).map_err(|_| Error::Invalid("length prefix"))?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(part);
    }
    Ok(out)
}

/// Inverse of [`lp`]. A trailing partial field is an error.
pub fn unlp(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut parts = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if i + 4 > data.len() {
            return Err(Error::Invalid("truncated length"));
        }
        let len = u32::from_be_bytes(data[i..i + 4].try_into().expect("4 bytes")) as usize;
        i += 4;
        if i + len > data.len() {
            return Err(Error::Invalid("truncated field"));
        }
        parts.push(data[i..i + len].to_vec());
        i += len;
    }
    Ok(parts)
}

/// Big-endian 64-bit encoding. Dart writes it as two big-endian 32-bit halves
/// so the browser build does not need `setUint64`. The bytes are the same.
pub fn u64_bytes(n: u64) -> [u8; 8] {
    n.to_be_bytes()
}

/// Equal lengths are compared in constant time. A different length returns
/// false at once, which is the same length check the Dart code uses.
pub fn bytes_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.ct_eq(b))
}

pub fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

/// A JSON value. Objects are ordered lists of pairs.
#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn object(pairs: Vec<(String, Json)>) -> Self {
        Json::Obj(pairs)
    }

    pub fn as_object(&self) -> Result<&[(String, Json)]> {
        match self {
            Json::Obj(pairs) => Ok(pairs),
            _ => Err(Error::Invalid("expected object")),
        }
    }

    pub fn as_str(&self) -> Result<&str> {
        match self {
            Json::Str(s) => Ok(s),
            _ => Err(Error::Invalid("expected string")),
        }
    }

    pub fn as_i64(&self) -> Result<i64> {
        match self {
            Json::Int(n) => Ok(*n),
            _ => Err(Error::Invalid("expected integer")),
        }
    }

    pub fn as_bool(&self) -> Result<bool> {
        match self {
            Json::Bool(b) => Ok(*b),
            _ => Err(Error::Invalid("expected bool")),
        }
    }

    pub fn as_array(&self) -> Result<&[Json]> {
        match self {
            Json::Arr(items) => Ok(items),
            _ => Err(Error::Invalid("expected array")),
        }
    }
}

impl Drop for Json {
    fn drop(&mut self) {
        // Parsed and built documents hold seeds, session state and plaintext.
        // Wipe those strings when the value is dropped. Callers still have to
        // wipe any `String` they already copied out.
        match self {
            Json::Str(text) => text.zeroize(),
            Json::Obj(pairs) => {
                for (key, _) in pairs.iter_mut() {
                    key.zeroize();
                }
            }
            Json::Null | Json::Bool(_) | Json::Int(_) | Json::Arr(_) => {}
        }
    }
}

/// Look up `key`. Missing and JSON `null` are both `None`.
pub fn obj_opt<'a>(obj: &'a [(String, Json)], key: &str) -> Option<&'a Json> {
    obj.iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| match v {
            Json::Null => None,
            other => Some(other),
        })
}

pub fn obj_get<'a>(obj: &'a [(String, Json)], key: &str) -> Result<&'a Json> {
    obj_opt(obj, key).ok_or(Error::Invalid("missing field"))
}

pub fn obj_str<'a>(obj: &'a [(String, Json)], key: &str) -> Result<&'a str> {
    obj_get(obj, key)?
        .as_str()
        .map_err(|_| Error::Invalid("expected string"))
}

pub fn obj_i64(obj: &[(String, Json)], key: &str) -> Result<i64> {
    obj_get(obj, key)?
        .as_i64()
        .map_err(|_| Error::Invalid("expected integer"))
}

pub fn obj_bool(obj: &[(String, Json)], key: &str) -> Result<bool> {
    obj_get(obj, key)?
        .as_bool()
        .map_err(|_| Error::Invalid("expected bool"))
}

/// Decode a standard-base64 field, with Dart's cheap size ceiling (`len * 2`
/// characters) applied before decoding.
pub fn b64_field(
    value: &Json,
    exact: Option<usize>,
    max: usize,
    what: &'static str,
) -> Result<Vec<u8>> {
    let text = value.as_str().map_err(|_| Error::Invalid(what))?;
    if text.len() > max.saturating_mul(2) {
        return Err(Error::Invalid(what));
    }
    let bytes = b64_decode(text).map_err(|_| Error::Invalid(what))?;
    if let Some(exact) = exact
        && bytes.len() != exact
    {
        return Err(Error::Invalid(what));
    }
    if bytes.len() > max {
        return Err(Error::Invalid(what));
    }
    Ok(bytes)
}

/// Nested arrays and objects deeper than this are rejected. Fireplace's
/// stored documents are a few levels deep. The cap is what stops a hostile
/// document from overflowing the stack: that abort cannot be caught.
const MAX_JSON_DEPTH: usize = 32;

/// Larger than a session (the ciphertext cap is 128 KiB, and at most 1,000
/// skipped keys) and large enough for the known-answer files. The check
/// happens before the parser walks the text.
const MAX_JSON_BYTES: usize = 4 * 1024 * 1024;

pub fn parse_json(input: &str) -> Result<Json> {
    if input.len() > MAX_JSON_BYTES {
        return Err(Error::Invalid("json too large"));
    }
    let mut parser = Parser {
        bytes: input.as_bytes(),
        i: 0,
    };
    parser.skip_ws();
    let value = parser.value(0)?;
    parser.skip_ws();
    if parser.i != parser.bytes.len() {
        return Err(Error::Invalid("trailing json"));
    }
    Ok(value)
}

pub fn to_json(value: &Json) -> String {
    // Reserve the exact encoded length first. A growing `String` frees each
    // earlier copy without wiping it, and those copies hold keys and session
    // state. The allocator may round the reservation up; the write must not
    // ask for more than that.
    let mut out = String::with_capacity(json_len(value));
    let reserved = out.capacity();
    write_json(&mut out, value);
    debug_assert_eq!(out.len(), json_len(value));
    debug_assert_eq!(out.capacity(), reserved);
    out
}

struct Parser<'a> {
    bytes: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if c == b' ' || c == b'\n' || c == b'\r' || c == b'\t' {
                self.i += 1;
            } else {
                break;
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.i).copied()
    }

    fn bump(&mut self) -> Result<u8> {
        let c = self.peek().ok_or(Error::Invalid("truncated json"))?;
        self.i += 1;
        Ok(c)
    }

    fn value(&mut self, depth: usize) -> Result<Json> {
        if depth > MAX_JSON_DEPTH {
            return Err(Error::Invalid("json too deep"));
        }
        self.skip_ws();
        match self.peek().ok_or(Error::Invalid("truncated json"))? {
            b'n' => self.literal(b"null", Json::Null),
            b't' => self.literal(b"true", Json::Bool(true)),
            b'f' => self.literal(b"false", Json::Bool(false)),
            b'"' => Ok(Json::Str(self.string()?)),
            b'[' => self.array(depth),
            b'{' => self.object(depth),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(Error::Invalid("json value")),
        }
    }

    fn literal(&mut self, text: &[u8], value: Json) -> Result<Json> {
        for expected in text {
            if self.bump()? != *expected {
                return Err(Error::Invalid("json literal"));
            }
        }
        Ok(value)
    }

    fn object(&mut self, depth: usize) -> Result<Json> {
        self.bump()?;
        let mut pairs: Vec<(String, Json)> = Vec::new();
        loop {
            self.skip_ws();
            match self.peek() {
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Json::Obj(pairs));
                }
                Some(b',') if !pairs.is_empty() => {
                    self.i += 1;
                    self.skip_ws();
                }
                Some(_) if pairs.is_empty() => {}
                _ => return Err(Error::Invalid("json object")),
            }
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(Error::Invalid("json key"));
            }
            let key = self.string()?;
            self.skip_ws();
            if self.bump()? != b':' {
                return Err(Error::Invalid("json colon"));
            }
            let value = self.value(depth + 1)?;
            if let Some(existing) = pairs.iter_mut().find(|(k, _)| k == &key) {
                existing.1 = value;
            } else {
                pairs.push((key, value));
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json> {
        self.bump()?;
        let mut items = Vec::new();
        loop {
            self.skip_ws();
            match self.peek() {
                Some(b']') => {
                    self.i += 1;
                    return Ok(Json::Arr(items));
                }
                Some(b',') if !items.is_empty() => {
                    self.i += 1;
                    self.skip_ws();
                }
                Some(_) if items.is_empty() => {}
                _ => return Err(Error::Invalid("json array")),
            }
            items.push(self.value(depth + 1)?);
        }
    }

    fn number(&mut self) -> Result<Json> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.i += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(Error::Invalid("json number"));
                }
            }
            Some(b'1'..=b'9') => {
                self.i += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.i += 1;
                }
            }
            _ => return Err(Error::Invalid("json number")),
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E' | b'+')) {
            return Err(Error::Invalid("json number"));
        }
        let text = core::str::from_utf8(&self.bytes[start..self.i])
            .map_err(|_| Error::Invalid("json number"))?;
        let n = text
            .parse::<i64>()
            .map_err(|_| Error::Invalid("json number"))?;
        Ok(Json::Int(n))
    }

    fn string(&mut self) -> Result<String> {
        if self.bump()? != b'"' {
            return Err(Error::Invalid("json string"));
        }
        let mut out = String::new();
        loop {
            match self.bump()? {
                b'"' => return Ok(out),
                b'\\' => {
                    let esc = self.bump()?;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let unit = self.hex4()?;
                            let ch = if (0xD800..=0xDBFF).contains(&unit) {
                                if self.bump()? != b'\\' || self.bump()? != b'u' {
                                    return Err(Error::Invalid("json surrogate"));
                                }
                                let low = self.hex4()?;
                                if !(0xDC00..=0xDFFF).contains(&low) {
                                    return Err(Error::Invalid("json surrogate"));
                                }
                                let cp = 0x10000
                                    + (((unit as u32) - 0xD800) << 10)
                                    + ((low as u32) - 0xDC00);
                                char::from_u32(cp).ok_or(Error::Invalid("json string"))?
                            } else if (0xDC00..=0xDFFF).contains(&unit) {
                                return Err(Error::Invalid("json surrogate"));
                            } else {
                                char::from_u32(u32::from(unit))
                                    .ok_or(Error::Invalid("json string"))?
                            };
                            out.push(ch);
                        }
                        _ => return Err(Error::Invalid("json escape")),
                    }
                }
                c if c < 0x20 => return Err(Error::Invalid("json control")),
                c => {
                    let width = utf8_width(c).ok_or(Error::Invalid("json string"))?;
                    if self.i + width - 1 > self.bytes.len() {
                        return Err(Error::Invalid("json string"));
                    }
                    let start = self.i - 1;
                    self.i += width - 1;
                    let text = core::str::from_utf8(&self.bytes[start..self.i])
                        .map_err(|_| Error::Invalid("json string"))?;
                    out.push_str(text);
                }
            }
        }
    }

    fn hex4(&mut self) -> Result<u16> {
        let mut n = 0u16;
        for _ in 0..4 {
            let c = self.bump()?;
            let digit = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => return Err(Error::Invalid("json unicode")),
            };
            n = (n << 4) | u16::from(digit);
        }
        Ok(n)
    }
}

fn utf8_width(first: u8) -> Option<usize> {
    if first < 0x80 {
        Some(1)
    } else if first & 0xE0 == 0xC0 {
        Some(2)
    } else if first & 0xF0 == 0xE0 {
        Some(3)
    } else if first & 0xF8 == 0xF0 {
        Some(4)
    } else {
        None
    }
}

fn json_len(value: &Json) -> usize {
    match value {
        Json::Null => 4,
        Json::Bool(true) => 4,
        Json::Bool(false) => 5,
        Json::Int(n) => int_len(*n),
        Json::Str(text) => string_len(text),
        Json::Arr(items) => {
            let commas = items.len().saturating_sub(1);
            2 + commas + items.iter().map(json_len).sum::<usize>()
        }
        Json::Obj(pairs) => {
            let commas = pairs.len().saturating_sub(1);
            let colons = pairs.len();
            2 + commas
                + colons
                + pairs
                    .iter()
                    .map(|(key, value)| string_len(key) + json_len(value))
                    .sum::<usize>()
        }
    }
}

fn int_len(n: i64) -> usize {
    if n == 0 {
        return 1;
    }
    if n == i64::MIN {
        return 20;
    }
    let negative = n < 0;
    let mut n = n.unsigned_abs();
    let mut len = usize::from(negative);
    while n > 0 {
        len += 1;
        n /= 10;
    }
    len
}

fn string_len(text: &str) -> usize {
    let mut len = 2;
    for ch in text.chars() {
        len += match ch {
            '"' | '\\' | '\u{0008}' | '\u{000c}' | '\n' | '\r' | '\t' => 2,
            c if (c as u32) < 0x20 => 6,
            c => c.len_utf8(),
        };
    }
    len
}

fn write_json(out: &mut String, value: &Json) {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Int(n) => write_int(out, *n),
        Json::Str(text) => write_string(out, text),
        Json::Arr(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(out, item);
            }
            out.push(']');
        }
        Json::Obj(pairs) => {
            out.push('{');
            for (i, (key, value)) in pairs.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, key);
                out.push(':');
                write_json(out, value);
            }
            out.push('}');
        }
    }
}

fn write_int(out: &mut String, n: i64) {
    if n == 0 {
        out.push('0');
        return;
    }
    if n == i64::MIN {
        out.push_str("-9223372036854775808");
        return;
    }
    let negative = n < 0;
    let mut n = n.unsigned_abs();
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    if negative {
        i -= 1;
        buf[i] = b'-';
    }
    out.push_str(std::str::from_utf8(&buf[i..]).expect("digits"));
}

fn write_string(out: &mut String, text: &str) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                let n = c as u32;
                out.push_str("\\u00");
                out.push(HEX[((n >> 4) & 0xf) as usize] as char);
                out.push(HEX[(n & 0xf) as usize] as char);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Require a non-empty string no longer than `max`.
pub fn bounded_str<'a>(
    obj: &'a [(String, Json)],
    key: &'static str,
    max: usize,
) -> Result<&'a str> {
    let text = obj_str(obj, key).map_err(|_| Error::Invalid(key))?;
    if text.is_empty() || text.len() > max {
        return Err(Error::Invalid(key));
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_dart_examples() {
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(&[0]), "AA==");
        assert_eq!(b64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(b64_decode("aGVsbG8=").unwrap(), b"hello");
        assert!(b64_decode("aGVsbG8").is_err());
        assert_eq!(b64url_encode(&[0xfb, 0xff, 0x00]), "-_8A");
    }

    #[test]
    fn length_prefix_roundtrip() {
        let encoded = lp(&[b"ab", b"", b"cde"]).unwrap();
        let parts = unlp(&encoded).unwrap();
        assert_eq!(
            parts,
            vec![b"ab".to_vec(), Vec::<u8>::new(), b"cde".to_vec()]
        );
        assert!(unlp(&[0, 0, 0, 2, 1]).is_err());
    }

    #[test]
    fn json_preserves_order_and_rejects_floats() {
        let value = parse_json(r#"{"b":1,"a":"x","n":null}"#).unwrap();
        assert_eq!(to_json(&value), r#"{"b":1,"a":"x","n":null}"#);
        assert!(parse_json("1.5").is_err());
        assert!(parse_json("01").is_err());
        let again = parse_json(r#"{"a":1,"a":2}"#).unwrap();
        assert_eq!(obj_i64(again.as_object().unwrap(), "a").unwrap(), 2);
        assert_eq!(to_json(&again), r#"{"a":2}"#);
    }

    #[test]
    fn to_json_writes_into_the_buffer_it_reserved() {
        let value = Json::object(vec![
            ("secret".to_string(), Json::Str("k".repeat(8_000))),
            ("n".to_string(), Json::Int(i64::MIN)),
            ("z".to_string(), Json::Int(0)),
            ("p".to_string(), Json::Int(10)),
            ("m".to_string(), Json::Int(-10)),
            ("c".to_string(), Json::Str("\u{0001}\"\\".to_string())),
            (
                "a".to_string(),
                Json::Arr(vec![Json::Bool(true), Json::Null]),
            ),
        ]);
        let mut out = String::with_capacity(json_len(&value));
        let reserved = out.capacity();
        write_json(&mut out, &value);
        assert_eq!(out.capacity(), reserved);
        assert_eq!(out.len(), json_len(&value));
        assert_eq!(out, to_json(&value));
        assert!(out.contains("-9223372036854775808"));
        assert!(out.contains("\\u0001"));
    }

    #[test]
    fn json_string_escapes_match_dart() {
        let value = Json::Str("a\"b\\c\n\u{0001}".to_string());
        assert_eq!(to_json(&value), r#""a\"b\\c\n\u0001""#);
        assert_eq!(parse_json(&to_json(&value)).unwrap(), value);
    }

    #[test]
    fn bytes_equal_checks_every_byte_and_rejects_a_different_length() {
        assert!(bytes_equal(b"abc", b"abc"));
        assert!(!bytes_equal(b"abc", b"abd"));
        assert!(!bytes_equal(b"abc", b"ab"));
    }

    #[test]
    fn json_rejects_deep_nesting_and_oversized_input() {
        let mut deep = "[".repeat(MAX_JSON_DEPTH);
        deep.push('1');
        deep.push_str(&"]".repeat(MAX_JSON_DEPTH));
        assert!(
            parse_json(&deep).is_ok(),
            "depth {MAX_JSON_DEPTH} is allowed"
        );
        deep.insert(0, '[');
        deep.push(']');
        assert!(
            parse_json(&deep).is_err(),
            "one level past the cap is refused"
        );
        let big = " ".repeat(MAX_JSON_BYTES + 1);
        assert!(parse_json(&big).is_err());
    }
}
