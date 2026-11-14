//! OCSP stapling fetch: the leaf's Authority Information Access names an OCSP responder, so a
//! listener that staples asks it for the leaf's status and serves the answer in the handshake.
//! xray's `common/ocsp` asks with `ocsp.CreateRequest` (SHA-1 over the issuer name and key, the
//! leaf's serial) and posts over plain HTTP; the answer bytes ride the handshake verbatim, so
//! this module only has to name the responder, build that request, POST it, and hand the response
//! back. A failure to fetch staples nothing: the listener serves the chain as if stapling were
//! off, which is what xray's ticker does when its fetch errors.

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::time::Duration;

/// How long one read or write may take before the listener serves without a staple.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// The most response bytes one fetch may read: an OCSP answer is a few KiB, so a responder
/// sending more is broken or hostile, and reading it all would let it decide our memory.
const FETCH_MAX_BYTES: usize = 64 * 1024;

/// The OCSP responder every certificate's Authority Information Access extension names.
const AIA_OID: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01];

/// The `AccessDescription` method for an OCSP responder.
const OCSP_ACCESS_OID: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];

/// The `AccessDescription` method for the issuer certificate itself.
const CA_ISSUERS_ACCESS_OID: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02];

/// One DER element past `at`, as its tag, the offset where its header ends and the offset where the
/// element ends.
fn element(der: &[u8], at: usize) -> Option<(u8, usize, usize)> {
    let tag = *der.get(at)?;
    let header = usize::from(*der.get(at.checked_add(1)?)?);
    let (length, body) = if header & 0x80 != 0 {
        let count = header & 0x7f;
        if !(1..=4).contains(&count) {
            return None;
        }
        let mut length = 0usize;
        for &byte in der.get(at.checked_add(2)?..at.checked_add(2 + count)?)? {
            length = length.checked_mul(256)?.checked_add(usize::from(byte))?;
        }
        (length, at.checked_add(2 + count)?)
    } else {
        (header, at.checked_add(2)?)
    };
    let end = body.checked_add(length)?;
    (end <= der.len()).then_some((tag, body, end))
}

/// The children of the `SEQUENCE` at `at`, each as the range its whole element spans.
fn children(der: &[u8], at: usize) -> Option<Vec<(usize, usize)>> {
    let (_, body, end) = element(der, at)?;
    let mut out = Vec::new();
    let mut at = body;
    while at < end {
        let (_, _, next) = element(der, at)?;
        out.push((at, next));
        at = next;
    }
    (at == end).then_some(out)
}

/// The `TBSCertificate` children of a certificate, in order.
fn tbs_children(cert: &[u8]) -> Option<Vec<(usize, usize)>> {
    let outer = children(cert, 0)?;
    children(cert, outer.first()?.0)
}

/// The Authority Information Access URIs a certificate carries, as the OCSP responder and the
/// issuer certificate the way xray reads them.
#[allow(clippy::type_complexity)]
fn aia_uris(cert: &[u8]) -> Option<(Option<Vec<u8>>, Option<Vec<u8>>)> {
    let tbs = tbs_children(cert)?;
    // The `[3]` tail anchors the extensions, because v1 certificates shift every child by one.
    let (extensions_at, _) = tbs
        .iter()
        .rev()
        .find(|&&(at, _)| cert.get(at) == Some(&0xa3))?;
    let binding = children(cert, *extensions_at)?;
    let [sequence] = binding.as_slice() else {
        return None;
    };
    let mut ocsp = None;
    let mut issuers = None;
    for (at, _) in children(cert, sequence.0)? {
        let ext = children(cert, at)?;
        if ext.len() < 2 {
            continue;
        }
        let (oid_at, oid_end) = ext[0];
        if &cert[oid_at..oid_end] != AIA_OID {
            continue;
        }
        let (value_at, _) = ext[ext.len() - 1];
        let (_, value_body, _) = element(cert, value_at)?;
        let Some(aia) = children(cert, value_body) else {
            continue;
        };
        for (description_at, _) in aia {
            let description = children(cert, description_at)?;
            if description.len() < 2 {
                continue;
            }
            let (method_at, method_end) = description[0];
            let method = &cert[method_at..method_end];
            let (uri_at, _) = description[1];
            if cert.get(uri_at) != Some(&0x86) {
                continue;
            }
            let (_, uri_body, uri_end) = element(cert, uri_at)?;
            let uri = cert.get(uri_body..uri_end)?.to_vec();
            if method == OCSP_ACCESS_OID && ocsp.is_none() {
                ocsp = Some(uri);
            } else if method == CA_ISSUERS_ACCESS_OID && issuers.is_none() {
                issuers = Some(uri);
            }
        }
    }
    Some((ocsp, issuers))
}

/// The serial number INTEGER contents of a certificate's TBS.
fn serial(cert: &[u8]) -> Option<&[u8]> {
    let tbs = tbs_children(cert)?;
    for (at, end) in tbs {
        if cert.get(at) == Some(&0x02) {
            let (_, body, _) = element(cert, at)?;
            return cert.get(body..end);
        }
    }
    None
}

/// SHA-1 over bytes the way the OCSP request's `CertID` names them.
fn digest(bytes: &[u8]) -> [u8; 20] {
    use sha1::Digest as _;
    sha1::Sha1::digest(bytes).into()
}

fn der_len(out: &mut Vec<u8>, length: usize) {
    if length < 0x80 {
        out.push(u8::try_from(length).expect("short length fits"));
    } else {
        let mut bytes = Vec::new();
        let mut rest = length;
        while rest > 0 {
            bytes.push(u8::try_from(rest & 0xff).expect("length byte fits"));
            rest >>= 8;
        }
        bytes.reverse();
        out.push(0x80 | u8::try_from(bytes.len()).expect("length count fits"));
        out.extend_from_slice(&bytes);
    }
}

fn der_tlv(out: &mut Vec<u8>, tag: u8, body: &[u8]) {
    out.push(tag);
    der_len(out, body.len());
    out.extend_from_slice(body);
}

fn sequence(out: &mut Vec<u8>, body: &[u8]) {
    der_tlv(out, 0x30, body);
}

/// The OCSP request for a leaf issued by an issuer, the `CertID` xray's `ocsp.CreateRequest`
/// builds: SHA-1 over the issuer's subject name and public key, the leaf's serial.
fn ocsp_request(leaf: &[u8], issuer: &[u8]) -> Option<Vec<u8>> {
    let serial = serial(leaf)?;
    let issuer_tbs = tbs_children(issuer)?;
    // A `[0]` version field shifts the subject index, so it is counted, not fixed.
    let versioned = usize::from(
        issuer_tbs
            .first()
            .is_some_and(|(at, _)| issuer.get(*at) == Some(&0xa0)),
    );
    let (subject_at, subject_end) = issuer_tbs.get(4 + versioned)?;
    let issuer_name = issuer.get(*subject_at..*subject_end)?;
    let spki = issuer_tbs.get(5 + versioned)?;
    let spki_children = children(issuer, spki.0)?;
    if spki_children.len() < 2 {
        return None;
    }
    let (key_at, key_end) = spki_children[1];
    let (_, key_body, _) = element(issuer, key_at)?;
    let _ = key_end;
    let issuer_key = issuer.get(key_body.checked_add(1)?..)?;
    let name_hash = digest(issuer_name);
    let key_hash = digest(issuer_key);
    let mut cert_id_body = Vec::new();
    let mut algorithm = Vec::new();
    der_tlv(&mut algorithm, 0x06, &[0x2b, 0x0e, 0x03, 0x02, 0x1a]);
    der_tlv(&mut algorithm, 0x05, &[]);
    sequence(&mut cert_id_body, &algorithm);
    der_tlv(&mut cert_id_body, 0x04, &name_hash);
    der_tlv(&mut cert_id_body, 0x04, &key_hash);
    der_tlv(&mut cert_id_body, 0x02, serial);
    let mut cert_id = Vec::new();
    sequence(&mut cert_id, &cert_id_body);
    let mut request = Vec::new();
    sequence(&mut request, &cert_id);
    let mut requests = Vec::new();
    sequence(&mut requests, &request);
    let mut tbs = Vec::new();
    sequence(&mut tbs, &requests);
    let mut outer = Vec::new();
    sequence(&mut outer, &tbs);
    Some(outer)
}

/// One plain HTTP request over TCP, answered with the body: the responder's shape and the
/// issuer fetch's shape are the same GET/POST, so the dialer is one code path. Only `http`
/// URLs are fetched; an `https` responder answers nothing here, and the staple goes without.
fn http(url: &str, method: &str, body: Option<&[u8]>) -> Option<Vec<u8>> {
    let rest = url.strip_prefix("http://")?;
    let (host, path) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    };
    let (host, port) = match host.rsplit_once(':') {
        Some((name, port)) => (name, port.parse::<u16>().ok()?),
        None => (host, 80),
    };
    // The dial resolves the way `reality`'s splice does: one path, whatever the host names.
    let mut stream = TcpStream::connect((host, port)).ok()?;
    stream.set_read_timeout(Some(FETCH_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(FETCH_TIMEOUT)).ok()?;
    let mut request = Vec::new();
    request.extend_from_slice(format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n").as_bytes());
    if method == "POST" {
        request.extend_from_slice(b"Content-Type: application/ocsp-request\r\n");
        let length = body.map_or(0, <[u8]>::len);
        request.extend_from_slice(format!("Content-Length: {length}\r\n").as_bytes());
    }
    request.extend_from_slice(b"Connection: close\r\n\r\n");
    if let Some(body) = body {
        request.extend_from_slice(body);
    }
    stream.write_all(&request).ok()?;
    let mut response = Vec::new();
    stream
        .take(u64::try_from(FETCH_MAX_BYTES).ok()?)
        .read_to_end(&mut response)
        .ok()?;
    if response.len() >= FETCH_MAX_BYTES {
        return None;
    }
    let head_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&response[..head_end]).ok()?;
    if !head.starts_with("HTTP/")
        || !head
            .split_whitespace()
            .nth(1)
            .is_some_and(|status| status.starts_with('2'))
    {
        return None;
    }
    let mut body = &response[head_end + 4..];
    let mut chunked = false;
    let mut length: Option<usize> = None;
    for line in head.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "transfer-encoding" if value.trim().eq_ignore_ascii_case("chunked") => chunked = true,
            "content-length" => length = value.trim().parse().ok(),
            _ => {}
        }
    }
    if chunked {
        let mut out = Vec::new();
        let mut at = 0usize;
        let mut terminated = false;
        while let Some(line_end) = body[at..].windows(2).position(|w| w == b"\r\n") {
            let size = usize::from_str_radix(
                std::str::from_utf8(&body[at..at + line_end])
                    .ok()?
                    .split(';')
                    .next()?
                    .trim(),
                16,
            )
            .ok()?;
            if size == 0 {
                terminated = true;
                break;
            }
            at = at.checked_add(line_end)?.checked_add(2)?;
            let end = at.checked_add(size)?;
            out.extend_from_slice(body.get(at..end)?);
            // A chunk without its trailing CRLF is a truncated stream, not a full chunk.
            if end
                .checked_add(2)
                .is_none_or(|next| body.get(end..next) != Some(b"\r\n"))
            {
                return None;
            }
            at = end.checked_add(2)?;
        }
        // A final chunk closes the body; a stream that simply stops is truncated.
        return terminated.then_some(out);
    }
    if let Some(length) = length {
        body = body.get(..length)?;
    }
    Some(body.to_vec())
}

/// The OCSP response bytes to staple for a served chain: the leaf's responder asked for the
/// leaf's status against its issuer, or `None` when the chain names neither.
pub fn staple_for(chain: &[Vec<u8>]) -> Option<Vec<u8>> {
    let leaf = chain.first()?;
    let (ocsp_url, ca_url) = aia_uris(leaf)?;
    let issuer = if chain.len() > 1 {
        chain[1].clone()
    } else {
        http(std::str::from_utf8(ca_url.as_deref()?).ok()?, "GET", None)?
    };
    let request = ocsp_request(leaf, &issuer)?;
    http(
        std::str::from_utf8(ocsp_url.as_deref()?).ok()?,
        "POST",
        Some(&request),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn element_roundtrip() {
        let mut der = Vec::new();
        der_tlv(&mut der, 0x30, &[0x02, 0x01, 0x05]);
        let (tag, body, end) = element(&der, 0).expect("element");
        assert_eq!(tag, 0x30);
        assert_eq!(&der[body..end], &[0x02, 0x01, 0x05]);
        assert_eq!(children(&der, 0).expect("children").len(), 1);
    }

    #[test]
    fn long_length_roundtrip() {
        let body = vec![0u8; 300];
        let mut der = Vec::new();
        der_tlv(&mut der, 0x30, &body);
        let (_, body_at, end) = element(&der, 0).expect("element");
        assert_eq!(end, der.len());
        assert_eq!(body_at, 4);
    }

    #[test]
    fn malformed_inputs_are_none() {
        assert!(element(&[], 0).is_none());
        assert!(element(&[0x30], 0).is_none());
        assert!(element(&[0x30, 0x81, 0xff], 0).is_none());
        assert!(aia_uris(&[]).is_none());
        assert!(serial(&[]).is_none());
        assert!(ocsp_request(&[], &[]).is_none());
        assert!(http("https://example.invalid/ocsp", "POST", Some(&[])).is_none());
    }

    #[test]
    fn fetch_refuses_a_dead_responder() {
        assert!(http("http://127.0.0.1:1/ocsp", "GET", None).is_none());
    }

    /// A one-shot responder that answers with a hand-written response body.
    fn raw_responder(answer_head: String, answer_body: Vec<u8>) -> u16 {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            socket
                .set_read_timeout(Some(FETCH_TIMEOUT))
                .expect("timeout");
            let mut buffer = [0u8; 8192];
            let _ = socket.read(&mut buffer);
            let mut answer = answer_head.into_bytes();
            answer.extend_from_slice(&answer_body);
            socket.write_all(&answer).expect("answer");
        });
        port
    }

    #[test]
    fn a_chunked_response_reads_its_hex_sizes() {
        // `2b` hex is 43: a decimal parse would fail outright on the letter.
        let payload = vec![b'a'; 43];
        let mut body = b"2b\r\n".to_vec();
        body.extend_from_slice(&payload);
        body.extend_from_slice(b"\r\n0\r\n\r\n");
        let port = raw_responder(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_owned(),
            body,
        );
        let got = http(&format!("http://127.0.0.1:{port}/ocsp"), "GET", None);
        assert_eq!(
            got.as_deref(),
            Some(payload.as_slice()),
            "the chunks decode by their hex size"
        );
    }

    #[test]
    fn a_chunk_without_its_crlf_is_not_a_full_chunk() {
        // The declared size is satisfied, but the terminator is missing: truncated, not full.
        let body = b"5\r\nabcdeXX0\r\n\r\n".to_vec();
        let port = raw_responder(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_owned(),
            body,
        );
        assert!(
            http(&format!("http://127.0.0.1:{port}/ocsp"), "GET", None).is_none(),
            "a chunk missing its CRLF answers nothing"
        );
    }

    #[test]
    fn an_oversized_response_answers_nothing() {
        let port = raw_responder(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                FETCH_MAX_BYTES + 1
            ),
            vec![0u8; FETCH_MAX_BYTES + 1],
        );
        assert!(
            http(&format!("http://127.0.0.1:{port}/ocsp"), "GET", None).is_none(),
            "past the cap there is no staple"
        );
    }

    fn name(display: &str) -> boring::x509::X509Name {
        let mut name = boring::x509::X509NameBuilder::new().expect("name");
        name.append_entry_by_nid(boring::nid::Nid::COMMONNAME, display)
            .expect("common name");
        name.build()
    }

    fn key() -> boring::pkey::PKey<boring::pkey::Private> {
        let group = boring::ec::EcGroup::from_curve_name(boring::nid::Nid::X9_62_PRIME256V1)
            .expect("group");
        let key = boring::ec::EcKey::generate(&group).expect("ec key");
        boring::pkey::PKey::from_ec_key(key).expect("pkey")
    }

    fn serial_number(value: u64) -> boring::asn1::Asn1Integer {
        let bn = boring::bn::BigNum::from_dec_str(&value.to_string()).expect("bn");
        boring::asn1::Asn1Integer::from_bn(bn.as_ref()).expect("serial")
    }

    fn issuer() -> (Vec<u8>, boring::pkey::PKey<boring::pkey::Private>) {
        let key = key();
        let name = name("Test CA");
        let mut cert = boring::x509::X509Builder::new().expect("builder");
        cert.set_version(2).expect("version");
        cert.set_subject_name(&name).expect("subject");
        cert.set_issuer_name(&name).expect("issuer");
        cert.set_pubkey(&key).expect("pubkey");
        cert.set_serial_number(&serial_number(1)).expect("serial");
        cert.set_not_before(&boring::asn1::Asn1Time::days_from_now(0).expect("from"))
            .expect("not before");
        cert.set_not_after(&boring::asn1::Asn1Time::days_from_now(30).expect("to"))
            .expect("not after");
        cert.sign(&key, boring::hash::MessageDigest::sha256())
            .expect("signs");
        (cert.build().to_der().expect("der"), key)
    }

    fn leaf(
        issuer: &[u8],
        issuer_key: &boring::pkey::PKey<boring::pkey::Private>,
        port: u16,
    ) -> Vec<u8> {
        leaf_keyed(issuer, issuer_key, port).0
    }

    fn leaf_keyed(
        issuer: &[u8],
        issuer_key: &boring::pkey::PKey<boring::pkey::Private>,
        port: u16,
    ) -> (Vec<u8>, boring::pkey::PKey<boring::pkey::Private>) {
        let key = key();
        let name = name("leaf.test");
        let mut cert = boring::x509::X509Builder::new().expect("builder");
        cert.set_version(2).expect("version");
        cert.set_subject_name(&name).expect("subject");
        let issuer = boring::x509::X509::from_der(issuer).expect("issuer der");
        cert.set_issuer_name(issuer.subject_name()).expect("issuer");
        cert.set_pubkey(&key).expect("pubkey");
        cert.set_serial_number(&serial_number(42)).expect("serial");
        cert.set_not_before(&boring::asn1::Asn1Time::days_from_now(0).expect("from"))
            .expect("not before");
        cert.set_not_after(&boring::asn1::Asn1Time::days_from_now(30).expect("to"))
            .expect("not after");
        let ocsp = format!("OCSP;URI:http://127.0.0.1:{port}/ocsp");
        let extension =
            boring::x509::X509Extension::new_nid(None, None, boring::nid::Nid::INFO_ACCESS, &ocsp)
                .expect("aia");
        cert.append_extension(&extension).expect("aia");
        cert.sign(issuer_key, boring::hash::MessageDigest::sha256())
            .expect("signs");
        (cert.build().to_der().expect("der"), key)
    }

    #[test]
    fn the_aia_names_the_responder_and_the_request_names_the_serial() {
        let (issuer, issuer_key) = issuer();
        let leaf = leaf(&issuer, &issuer_key, 8443);
        let (ocsp_url, ca_url) = aia_uris(&leaf).expect("aia");
        assert_eq!(
            ocsp_url.as_deref(),
            Some(&b"http://127.0.0.1:8443/ocsp"[..]),
            "the responder URL"
        );
        assert!(ca_url.is_none(), "this leaf names no issuer URL");
        let request = ocsp_request(&leaf, &issuer).expect("request");
        // Walk the request: outer -> tbs -> list -> request -> CertID, and read the serial.
        let tbs_level = children(&request, 0).expect("tbs");
        let [tbs] = tbs_level.as_slice() else {
            panic!("one tbs");
        };
        let list_level = children(&request, tbs.0).expect("list");
        let [list] = list_level.as_slice() else {
            panic!("one list");
        };
        let single_level = children(&request, list.0).expect("list");
        let [single] = single_level.as_slice() else {
            panic!("one request");
        };
        let cert_id_level = children(&request, single.0).expect("request");
        let [cert_id] = cert_id_level.as_slice() else {
            panic!("one cert id");
        };
        let parts = children(&request, cert_id.0).expect("cert id");
        assert_eq!(parts.len(), 4, "algorithm and two hashes and serial");
        let serial = serial(&leaf).expect("serial");
        let (_, serial_body, serial_end) = element(&request, parts[3].0).expect("serial element");
        assert_eq!(
            &request[serial_body..serial_end],
            serial,
            "the leaf's serial"
        );
    }

    #[test]
    fn a_chain_staples_from_a_loopback_responder() {
        use std::io::{Read as _, Write as _};
        let (issuer, issuer_key) = issuer();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        let port = listener.local_addr().expect("addr").port();
        let leaf = leaf(&issuer, &issuer_key, port);
        let chain = vec![leaf.clone(), issuer.clone()];
        let canned = [0x30u8, 0x03, 0x0a, 0x01, 0x00];
        let expected = ocsp_request(&leaf, &issuer).expect("request");
        let (asked, answered) = std::sync::mpsc::channel::<(String, Vec<u8>)>();
        let expected_len = expected.len();
        std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            socket
                .set_read_timeout(Some(FETCH_TIMEOUT))
                .expect("timeout");
            let mut request = Vec::new();
            let mut raw = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                let read = socket.read(&mut buffer).expect("read");
                raw.extend_from_slice(&buffer[..read]);
                if raw.windows(4).any(|window| window == b"\r\n\r\n")
                    && raw.len()
                        >= raw
                            .windows(4)
                            .position(|window| window == b"\r\n\r\n")
                            .expect("head")
                            + 4
                            + expected_len
                {
                    break;
                }
            }
            let head_end = raw
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .expect("head");
            request.extend_from_slice(&raw[head_end + 4..]);
            request.truncate(expected_len);
            let head = String::from_utf8_lossy(&raw[..head_end]).into_owned();
            asked.send((head, request)).expect("channel");
            let mut answer = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                canned.len()
            )
            .into_bytes();
            answer.extend_from_slice(&canned);
            socket.write_all(&answer).expect("answer");
        });
        let staple = staple_for(&chain).expect("staples");
        assert_eq!(staple, canned, "the responder's bytes ride verbatim");
        let (head, body) = answered.recv().expect("asked");
        assert!(head.starts_with("POST /ocsp HTTP/1.1"), "{head}");
        assert!(
            head.contains("Content-Type: application/ocsp-request"),
            "{head}"
        );
        assert_eq!(body, expected, "the request is the CertID xray builds");
    }

    #[test]
    fn an_issuer_is_fetched_when_the_chain_names_no_issuer() {
        use std::io::{Read as _, Write as _};
        let (issuer, issuer_key) = issuer();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        let port = listener.local_addr().expect("addr").port();
        let key = key();
        let name = name("solo.test");
        let mut cert = boring::x509::X509Builder::new().expect("builder");
        cert.set_version(2).expect("version");
        cert.set_subject_name(&name).expect("subject");
        let issuer_cert = boring::x509::X509::from_der(&issuer).expect("issuer der");
        cert.set_issuer_name(issuer_cert.subject_name())
            .expect("issuer");
        cert.set_pubkey(&key).expect("pubkey");
        cert.set_serial_number(&serial_number(7)).expect("serial");
        cert.set_not_before(&boring::asn1::Asn1Time::days_from_now(0).expect("from"))
            .expect("not before");
        cert.set_not_after(&boring::asn1::Asn1Time::days_from_now(30).expect("to"))
            .expect("not after");
        let aia = format!(
            "OCSP;URI:http://127.0.0.1:{port}/ocsp,caIssuers;URI:http://127.0.0.1:{port}/ca"
        );
        let extension =
            boring::x509::X509Extension::new_nid(None, None, boring::nid::Nid::INFO_ACCESS, &aia)
                .expect("aia");
        cert.append_extension(&extension).expect("aia");
        cert.sign(&issuer_key, boring::hash::MessageDigest::sha256())
            .expect("signs");
        let leaf = cert.build().to_der().expect("der");
        let (asked, answered) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().expect("accept");
                socket
                    .set_read_timeout(Some(FETCH_TIMEOUT))
                    .expect("timeout");
                let mut raw = Vec::new();
                let mut buffer = [0u8; 8192];
                // Read the head, then exactly the Content-Length body the client named.
                let head_end = loop {
                    let read = socket.read(&mut buffer).expect("read");
                    raw.extend_from_slice(&buffer[..read]);
                    if let Some(at) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&raw[..at]).into_owned();
                        if head.starts_with("GET") {
                            break at;
                        }
                        let length = head
                            .lines()
                            .map(str::to_ascii_lowercase)
                            .find_map(|line| {
                                line.strip_prefix("content-length:").map(str::to_owned)
                            })
                            .and_then(|value| value.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if raw.len() >= at + 4 + length {
                            break at;
                        }
                    }
                };
                let head = String::from_utf8_lossy(&raw[..head_end]).into_owned();
                let path = head.split_whitespace().nth(1).expect("path").to_owned();
                asked.send(path.clone()).expect("channel");
                let body = if path == "/ca" {
                    issuer.clone()
                } else {
                    [0x30u8, 0x03, 0x0a, 0x01, 0x00].to_vec()
                };
                let mut answer = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .into_bytes();
                answer.extend_from_slice(&body);
                socket.write_all(&answer).expect("answer");
            }
        });
        let staple = staple_for(&[leaf]).expect("staples");
        assert_eq!(staple, [0x30, 0x03, 0x0a, 0x01, 0x00]);
        assert_eq!(answered.recv().expect("asked"), "/ca", "the issuer first");
        assert_eq!(
            answered.recv().expect("asked"),
            "/ocsp",
            "then the responder"
        );
    }

    fn responder_serving(responses: Vec<Vec<u8>>) -> (u16, std::sync::mpsc::Receiver<()>) {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        let port = listener.local_addr().expect("addr").port();
        let (done, asked) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            let mut step = 0;
            loop {
                let Ok((mut socket, _)) = listener.accept() else {
                    return;
                };
                socket
                    .set_read_timeout(Some(FETCH_TIMEOUT))
                    .expect("timeout");
                let mut raw = Vec::new();
                let mut buffer = [0u8; 8192];
                let head_end = loop {
                    let Ok(read) = socket.read(&mut buffer) else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    raw.extend_from_slice(&buffer[..read]);
                    if let Some(at) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&raw[..at]).into_owned();
                        let length = head
                            .lines()
                            .map(str::to_ascii_lowercase)
                            .find_map(|line| {
                                line.strip_prefix("content-length:").map(str::to_owned)
                            })
                            .and_then(|value| value.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if raw.len() >= at + 4 + length {
                            break at;
                        }
                    }
                };
                let _ = String::from_utf8_lossy(&raw[..head_end]);
                let body = responses
                    .get(step)
                    .cloned()
                    .unwrap_or_else(|| responses.last().cloned().unwrap_or_default());
                step = step.saturating_add(1);
                let mut answer = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .into_bytes();
                answer.extend_from_slice(&body);
                if socket.write_all(&answer).is_err() {
                    return;
                }
                if done.send(()).is_err() {
                    return;
                }
            }
        });
        (port, asked)
    }

    #[test]
    fn a_renewed_staple_swaps_the_served_response() {
        use std::time::Duration;
        let (issuer, issuer_key) = issuer();
        let canned_a = [0x30u8, 0x03, 0x0a, 0x01, 0x00].to_vec();
        let canned_b = [0x30u8, 0x03, 0x0a, 0x02, 0x00].to_vec();
        let (port, asked) = responder_serving(vec![canned_b.clone(), canned_b.clone()]);
        let (leaf, key) = leaf_keyed(&issuer, &issuer_key, port);
        let identity = crate::tls::TlsServerConfig {
            alpn: Vec::new(),
            min_version: None,
            max_version: None,
            cipher_suites: Vec::new(),
            curves: Vec::new(),
            certs: vec![crate::tls::CertEntry {
                cert_chain: vec![leaf, issuer],
                key_der: key.private_key_to_der_pkcs8().expect("pkcs8"),
                key_kind: crate::tls::ServerKeyKind::Pkcs8,
                reload: None,
                ocsp: Some(crate::tls::OcspStaple {
                    interval: Duration::from_secs(1),
                    response: Some(canned_a),
                }),
            }],
            send_tickets: false,
            reject_unknown_sni: false,
            server_config_cache: std::sync::Arc::default(),
            ech_server_keys: None,
            master_key_log: None,
            kernel_tx: false,
            kernel_rx: false,
        };
        assert_eq!(
            identity.reload_interval(),
            Some(Duration::from_secs(1)),
            "an ocsp-only entry still ticks"
        );
        assert!(identity.renew(), "a changed staple rebuilds the listener");
        asked.recv().expect("the responder was asked");
        assert!(
            !identity.renew(),
            "a steady responder leaves the listener alone"
        );
    }
}
