//! Damaged input and refused input.
//!
//! The first half takes a valid encoding of every format the crate reads from
//! outside and damages it in a fixed, repeatable way: cut short, one bit
//! flipped, one byte replaced, and plain noise. Nothing may panic, and
//! whatever is still accepted must encode back to text that is accepted again
//! and stays the same. By default a sample of positions is damaged, to keep
//! the run short; `FP_LONG_TESTS=1` damages every position.
//!
//! The second half is one test per validation rule: input that is well formed
//! and must be refused all the same.

use fireplace_crypto::{
    AccountIdentity, DeviceBundle, DeviceKeys, Envelope, Error, HandshakeInit, PreKeyBundle,
    PreKeyRecord, PublishedPreKey, Rng, SealedIdentity, Session, link_seal, one_time, sign_prekey,
    verify_signed,
};

const NOW: i64 = 1_700_000_000_000;

/// A small fixed generator (xorshift64*), so every run damages the same bytes.
struct Noise(u64);

impl Noise {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// True when `FP_LONG_TESTS` is set: damage every position of every text.
/// That takes several minutes, so it is for a local run, not for every push.
fn long_run() -> bool {
    std::env::var_os("FP_LONG_TESTS").is_some()
}

/// The positions to damage. A long run takes all of them. Otherwise: both
/// ends, where the structure is, and evenly spaced samples in between.
fn positions(len: usize) -> Vec<usize> {
    const ENDS: usize = 48;
    const SAMPLES: usize = 96;
    if long_run() || len <= 2 * ENDS + SAMPLES {
        return (0..len).collect();
    }
    let mut out: Vec<usize> = (0..ENDS).collect();
    let middle = len - 2 * ENDS;
    out.extend((0..SAMPLES).map(|i| ENDS + i * middle / SAMPLES));
    out.extend(len - ENDS..len);
    out
}

/// `parse` returns the value encoded again, or `None` when it refuses.
fn damage(name: &str, valid: &str, parse: &dyn Fn(&str) -> Option<String>) {
    let check = |text: &str| {
        if let Some(encoded) = parse(text) {
            let again = parse(&encoded)
                .unwrap_or_else(|| panic!("{name}: accepted text did not parse again"));
            assert_eq!(again, encoded, "{name}: encoding is not stable");
        }
    };
    assert_eq!(
        parse(valid).as_deref(),
        Some(valid),
        "{name}: the valid text must round-trip"
    );
    let bytes = valid.as_bytes();
    let mut refused = 0usize;
    for cut in positions(bytes.len()) {
        if let Ok(text) = std::str::from_utf8(&bytes[..cut]) {
            assert!(parse(text).is_none(), "{name}: accepted when cut at {cut}");
            refused += 1;
        }
    }
    assert!(refused > 0);
    for pos in positions(bytes.len()) {
        for bit in [0u8, (pos % 7) as u8 + 1] {
            let mut copy = bytes.to_vec();
            copy[pos] ^= 1 << bit;
            if let Ok(text) = std::str::from_utf8(&copy) {
                check(text);
            }
        }
    }
    let mut noise = Noise(0x9E37_79B9_7F4A_7C15 ^ bytes.len() as u64);
    for _ in 0..if long_run() { 2000 } else { 120 } {
        let mut copy = bytes.to_vec();
        let pos = noise.below(copy.len());
        copy[pos] = 0x20 + noise.below(0x5f) as u8;
        check(std::str::from_utf8(&copy).unwrap());
    }
    for _ in 0..200 {
        let len = noise.below(96);
        let text: String = (0..len)
            .map(|_| char::from(0x20 + noise.below(0x5f) as u8))
            .collect();
        check(&text);
    }
    for text in [
        "",
        "{}",
        "[]",
        "null",
        "{\"pv\":4}",
        "\"\"",
        "0",
        "{\"a\":{}}",
    ] {
        assert!(parse(text).is_none(), "{name}: accepted {text:?}");
    }
}

struct World {
    alice_keys: DeviceKeys,
    alice_bundle: DeviceBundle,
    bob_id: AccountIdentity,
    bob_keys: DeviceKeys,
    bob_bundle: DeviceBundle,
    signed_record: PreKeyRecord,
    signed: PublishedPreKey,
    one_time_record: PreKeyRecord,
    alice: Session,
    bob: Session,
    handshake: HandshakeInit,
}

fn world(rng: &mut Rng) -> World {
    let alice_id = AccountIdentity::generate(rng).unwrap();
    let alice_keys = DeviceKeys::generate(rng).unwrap();
    let alice_bundle = alice_keys.certify(&alice_id, "alice", rng).unwrap();
    let bob_id = AccountIdentity::generate(rng).unwrap();
    let bob_keys = DeviceKeys::generate(rng).unwrap();
    let bob_bundle = bob_keys.certify(&bob_id, "bob", rng).unwrap();
    let signed_record = PreKeyRecord::generate(rng, NOW).unwrap();
    let signed = sign_prekey(&signed_record, &bob_id, "bob", &bob_keys.device_id, rng).unwrap();
    let one_time_record = PreKeyRecord::generate(rng, NOW).unwrap();
    let remote = PreKeyBundle {
        device: bob_bundle.clone(),
        signed: signed.clone(),
        one_time: Some(one_time(&one_time_record)),
    };
    let (alice, handshake) =
        Session::initiate(&alice_keys, &alice_bundle, &remote, rng, NOW).unwrap();
    let bob = Session::accept(
        &bob_keys,
        &bob_bundle,
        &alice_bundle,
        &handshake,
        &signed_record,
        Some(&one_time_record),
        NOW,
    )
    .unwrap();
    World {
        alice_keys,
        alice_bundle,
        bob_id,
        bob_keys,
        bob_bundle,
        signed_record,
        signed,
        one_time_record,
        alice,
        bob,
        handshake,
    }
}

fn copy(session: &Session) -> Session {
    Session::from_json(&session.to_json()).unwrap()
}

#[test]
fn damaged_encodings_never_panic_and_stay_stable() {
    let mut rng = Rng::os();
    let mut w = world(&mut rng);
    let first = w.alice.encrypt(b"hello", "chat-1", &mut rng).unwrap();
    assert!(first.handshake.is_some());
    w.bob.decrypt(&first, "chat-1", &mut rng, NOW).unwrap();
    let reply = w.bob.encrypt(b"hi", "chat-1", &mut rng).unwrap();
    // Leave a gap so the saved session holds skipped keys as well.
    let _lost = w.bob.encrypt(b"lost", "chat-1", &mut rng).unwrap();
    let later = w.bob.encrypt(b"later", "chat-1", &mut rng).unwrap();
    w.alice.decrypt(&reply, "chat-1", &mut rng, NOW).unwrap();
    w.alice.decrypt(&later, "chat-1", &mut rng, NOW).unwrap();

    damage("envelope with handshake", &first.to_json(), &|t| {
        Envelope::from_json(t).ok().map(|e| e.to_json())
    });
    damage("envelope", &reply.to_json(), &|t| {
        Envelope::from_json(t).ok().map(|e| e.to_json())
    });
    damage("handshake", &w.handshake.to_json(), &|t| {
        HandshakeInit::from_json(t).ok().map(|h| h.to_json())
    });
    damage("device bundle", &w.bob_bundle.to_json(), &|t| {
        DeviceBundle::from_json(t).ok().map(|b| b.to_json())
    });
    damage("signed prekey", &w.signed.to_json(), &|t| {
        PublishedPreKey::from_json(t).ok().map(|p| p.to_json())
    });
    damage(
        "one-time prekey",
        &one_time(&w.one_time_record).to_json(),
        &|t| PublishedPreKey::from_json(t).ok().map(|p| p.to_json()),
    );
    damage("device keys", &w.bob_keys.to_json(), &|t| {
        DeviceKeys::from_json(t).ok().map(|k| k.to_json())
    });
    damage("prekey record", &w.signed_record.to_json(), &|t| {
        PreKeyRecord::from_json(t).ok().map(|r| r.to_json())
    });
    damage("account identity", &w.bob_id.to_json(), &|t| {
        AccountIdentity::from_json(t).ok().map(|i| i.to_json())
    });
    damage("session with skipped keys", &w.alice.to_json(), &|t| {
        Session::from_json(t).ok().map(|s| s.to_json())
    });
    damage("responder session", &w.bob.to_json(), &|t| {
        Session::from_json(t).ok().map(|s| s.to_json())
    });
    let sealed = link_seal(
        &w.bob_id,
        "bob",
        &w.bob_keys.device_id,
        &w.bob_keys.x25519_pub,
        &w.bob_keys.kem_pub,
        &mut rng,
    )
    .unwrap();
    damage("sealed identity", &sealed.to_json(), &|t| {
        SealedIdentity::from_json(t).ok().map(|s| s.to_json())
    });

    // A prekey bundle has no encoder of its own: only "never panics" applies.
    let bundle = format!(
        r#"{{"device":{},"signed":{},"oneTime":{}}}"#,
        w.bob_bundle.to_json(),
        w.signed.to_json(),
        one_time(&w.one_time_record).to_json()
    );
    assert!(PreKeyBundle::from_json(&bundle).is_ok());
    let bytes = bundle.as_bytes();
    for pos in positions(bytes.len()) {
        if let Ok(text) = std::str::from_utf8(&bytes[..pos]) {
            assert!(PreKeyBundle::from_json(text).is_err());
        }
        let mut flipped = bytes.to_vec();
        flipped[pos] ^= 1 << (pos % 8);
        if let Ok(text) = std::str::from_utf8(&flipped) {
            let _ = PreKeyBundle::from_json(text);
        }
    }
}

#[test]
fn a_damaged_message_is_refused_and_leaves_the_session_as_it_was() {
    let mut rng = Rng::os();
    let mut w = world(&mut rng);
    let first = w.alice.encrypt(b"hello", "chat-1", &mut rng).unwrap();
    w.bob.decrypt(&first, "chat-1", &mut rng, NOW).unwrap();
    let reply = w.bob.encrypt(b"hi", "chat-1", &mut rng).unwrap();
    w.alice.decrypt(&reply, "chat-1", &mut rng, NOW).unwrap();
    // `same` continues Alice's current chain; `turn` starts a new chain at Bob.
    let same = w.bob.encrypt(b"same chain", "chat-1", &mut rng).unwrap();
    let turn = w.alice.encrypt(b"new chain", "chat-1", &mut rng).unwrap();

    type Edit = fn(&mut Envelope);
    let edits: [(&str, Edit); 14] = [
        ("ct first bit", |e| e.ct[0] ^= 1),
        ("ct last bit", |e| *e.ct.last_mut().unwrap() ^= 0x80),
        ("ct shorter", |e| {
            e.ct.pop();
        }),
        ("ct longer", |e| e.ct.push(0)),
        ("mac", |e| e.mac[15] ^= 1),
        ("nonce", |e| e.nonce[0] ^= 1),
        ("counter up", |e| e.n += 1),
        ("previous length", |e| e.pn += 1),
        ("ratchet key", |e| e.rx[5] ^= 1),
        ("kem key", |e| e.rk[100] ^= 1),
        ("kem ciphertext", |e| e.rc[100] ^= 1),
        ("ratchet key all zero", |e| e.rx = vec![0; 32]),
        ("session id", |e| e.sid.push('x')),
        ("counter far ahead", |e| e.n += 1001),
    ];
    for (receiver, message) in [(&w.alice, &same), (&w.bob, &turn)] {
        let saved = receiver.to_json();
        for (what, edit) in edits {
            let mut session = copy(receiver);
            let mut damaged = message.clone();
            edit(&mut damaged);
            assert!(
                session.decrypt(&damaged, "chat-1", &mut rng, NOW).is_err(),
                "{what}"
            );
            assert_eq!(session.to_json(), saved, "{what}: the session changed");
            // The untouched message still decrypts afterwards.
            assert!(
                session.decrypt(message, "chat-1", &mut rng, NOW).is_ok(),
                "{what}"
            );
        }
        // Another chat's id, and a replay, are refused too.
        let mut session = copy(receiver);
        assert!(session.decrypt(message, "chat-2", &mut rng, NOW).is_err());
        assert_eq!(session.to_json(), saved);
        session.decrypt(message, "chat-1", &mut rng, NOW).unwrap();
        let after = session.to_json();
        assert!(session.decrypt(message, "chat-1", &mut rng, NOW).is_err());
        assert_eq!(session.to_json(), after);
    }
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// The X25519 inputs whose shared secret is all zero for every private key
/// (RFC 7748, section 6.1): the points of small order and their other encodings.
fn low_order_points() -> Vec<Vec<u8>> {
    [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ]
    .iter()
    .map(|p| hex(p))
    .collect()
}

#[test]
fn low_order_x25519_keys_are_refused_wherever_they_arrive() {
    let mut rng = Rng::os();
    let w = world(&mut rng);
    for point in low_order_points() {
        // In a signed prekey, signed by the account itself.
        let mut record = PreKeyRecord::generate(&mut rng, NOW).unwrap();
        record.x25519_pub = point.clone();
        let signed =
            sign_prekey(&record, &w.bob_id, "bob", &w.bob_keys.device_id, &mut rng).unwrap();
        assert!(verify_signed(&w.bob_bundle, &signed));
        let remote = PreKeyBundle {
            device: w.bob_bundle.clone(),
            signed,
            one_time: None,
        };
        assert!(matches!(
            Session::initiate(&w.alice_keys, &w.alice_bundle, &remote, &mut rng, NOW),
            Err(Error::Crypto(_))
        ));

        // In a one-time prekey, which nobody signs.
        let mut unsigned = one_time(&w.one_time_record);
        unsigned.x25519_pub = point.clone();
        let remote = PreKeyBundle {
            device: w.bob_bundle.clone(),
            signed: w.signed.clone(),
            one_time: Some(unsigned),
        };
        assert!(matches!(
            Session::initiate(&w.alice_keys, &w.alice_bundle, &remote, &mut rng, NOW),
            Err(Error::Crypto(_))
        ));

        // As the device key of a certified bundle.
        let mut keys = DeviceKeys::generate(&mut rng).unwrap();
        keys.x25519_pub = point.clone();
        let bundle = keys.certify(&w.bob_id, "bob", &mut rng).unwrap();
        assert!(bundle.verify_cert());
        let record = PreKeyRecord::generate(&mut rng, NOW).unwrap();
        let signed = sign_prekey(&record, &w.bob_id, "bob", &keys.device_id, &mut rng).unwrap();
        let remote = PreKeyBundle {
            device: bundle,
            signed,
            one_time: None,
        };
        assert!(matches!(
            Session::initiate(&w.alice_keys, &w.alice_bundle, &remote, &mut rng, NOW),
            Err(Error::Crypto(_))
        ));

        // As the ephemeral key of a handshake.
        let mut handshake = w.handshake.clone();
        handshake.ek = point.clone();
        assert!(matches!(
            Session::accept(
                &w.bob_keys,
                &w.bob_bundle,
                &w.alice_bundle,
                &handshake,
                &w.signed_record,
                Some(&w.one_time_record),
                NOW,
            ),
            Err(Error::Crypto(_))
        ));
    }
}

#[test]
fn a_bundle_must_carry_its_post_quantum_keys() {
    let mut rng = Rng::os();
    let w = world(&mut rng);
    let device = w.bob_bundle.to_json();
    let signed = w.signed.to_json();
    let whole = |device: &str, signed: &str| format!(r#"{{"device":{device},"signed":{signed}}}"#);
    assert!(PreKeyBundle::from_json(&whole(&device, &signed)).is_ok());

    // Each ML-KEM key removed, emptied, cut short, or replaced by null.
    let kem = |text: &str| -> String {
        let start = text.find("\"kemPub\":\"").unwrap() + 10;
        let end = start + text[start..].find('"').unwrap();
        text[start..end].to_string()
    };
    for (broken_device, broken_signed) in [
        (device.replace(&kem(&device), ""), signed.clone()),
        (device.replace(&kem(&device), "AAAA"), signed.clone()),
        (device.replace("\"kemPub\"", "\"kemPubX\""), signed.clone()),
        (
            device.replace(&format!("\"{}\"", kem(&device)), "null"),
            signed.clone(),
        ),
        (device.clone(), signed.replace(&kem(&signed), "")),
        (device.clone(), signed.replace(&kem(&signed), "AAAA")),
        (device.clone(), signed.replace("\"kemPub\"", "\"kemPubX\"")),
        (
            device.clone(),
            signed.replace(&format!("\"{}\"", kem(&signed)), "null"),
        ),
    ] {
        assert!(PreKeyBundle::from_json(&whole(&broken_device, &broken_signed)).is_err());
    }

    // A handshake must carry its KEM ciphertext, and both or neither of the
    // one-time prekey fields.
    let hs = w.handshake.to_json();
    assert!(HandshakeInit::from_json(&hs).is_ok());
    assert!(HandshakeInit::from_json(&hs.replace("\"kemCt\"", "\"kemCtX\"")).is_err());
    assert!(HandshakeInit::from_json(&hs.replace("\"opkCt\"", "\"opkCtX\"")).is_err());
    assert!(HandshakeInit::from_json(&hs.replace("\"opk\"", "\"opkX\"")).is_err());

    // An envelope must carry the ratchet's KEM key and ciphertext, and only
    // the current protocol version is read.
    let mut alice = copy(&w.alice);
    let env = alice.encrypt(b"x", "chat-1", &mut rng).unwrap().to_json();
    assert!(Envelope::from_json(&env).is_ok());
    for (from, to) in [
        ("\"rk\"", "\"rkX\""),
        ("\"rc\"", "\"rcX\""),
        ("\"pv\":4", "\"pv\":3"),
        ("\"pv\":4", "\"pv\":5"),
        ("\"pv\":4", "\"pv\":\"4\""),
    ] {
        assert!(
            Envelope::from_json(&env.replace(from, to)).is_err(),
            "{from}"
        );
    }
}

#[test]
fn an_account_signature_needs_both_halves_and_its_own_purpose() {
    let mut rng = Rng::os();
    let w = world(&mut rng);
    assert!(w.bob_bundle.verify_cert());
    assert!(verify_signed(&w.bob_bundle, &w.signed));

    // A certificate is a 64-byte Ed25519 signature and a 3,309-byte ML-DSA-65
    // signature, each after a 4-byte length. Damage one half at a time.
    assert_eq!(w.bob_bundle.cert.len(), 4 + 64 + 4 + 3309);
    for offset in [4, 4 + 63, 4 + 64 + 4, 4 + 64 + 4 + 3308] {
        let mut bundle = w.bob_bundle.clone();
        bundle.cert[offset] ^= 1;
        assert!(!bundle.verify_cert(), "offset {offset}");
        let mut signed = w.signed.clone();
        signed.sig.as_mut().unwrap()[offset] ^= 1;
        assert!(!verify_signed(&w.bob_bundle, &signed), "offset {offset}");
    }
    // One half alone, a third part, or nothing.
    for cert in [
        w.bob_bundle.cert[..4 + 64].to_vec(),
        w.bob_bundle.cert[4 + 64..].to_vec(),
        [w.bob_bundle.cert.clone(), vec![0, 0, 0, 0]].concat(),
        Vec::new(),
    ] {
        let mut bundle = w.bob_bundle.clone();
        bundle.cert = cert;
        assert!(!bundle.verify_cert());
    }

    // The certificate names one account, one device and one pair of keys.
    let mut bundle = w.bob_bundle.clone();
    bundle.uid = "bobby".into();
    assert!(!bundle.verify_cert());
    let mut bundle = w.bob_bundle.clone();
    bundle.device_id = w.alice_bundle.device_id.clone();
    assert!(!bundle.verify_cert());
    let mut bundle = w.bob_bundle.clone();
    bundle.x25519_pub = w.alice_bundle.x25519_pub.clone();
    assert!(!bundle.verify_cert());
    let mut bundle = w.bob_bundle.clone();
    bundle.kem_pub = w.alice_bundle.kem_pub.clone();
    assert!(!bundle.verify_cert());
    // Another account's identity key does not verify it.
    let mut bundle = w.bob_bundle.clone();
    bundle.identity_pub = w.alice_bundle.identity_pub.clone();
    assert!(!bundle.verify_cert());

    // A signature made for one purpose is not accepted for another, even
    // over the same account, device and keys.
    let same_keys = PublishedPreKey {
        id: w.bob_bundle.device_id.clone(),
        kind: fireplace_crypto::PreKeyKind::Signed,
        x25519_pub: w.bob_bundle.x25519_pub.clone(),
        kem_pub: w.bob_bundle.kem_pub.clone(),
        sig: Some(w.bob_bundle.cert.clone()),
    };
    assert!(!verify_signed(&w.bob_bundle, &same_keys));
    let mut bundle = w.bob_bundle.clone();
    bundle.x25519_pub = w.signed.x25519_pub.clone();
    bundle.kem_pub = w.signed.kem_pub.clone();
    bundle.cert = w.signed.sig.clone().unwrap();
    assert!(!bundle.verify_cert());

    // A signed prekey is bound to its id, account and device; a one-time
    // prekey never passes as a signed one.
    let mut signed = w.signed.clone();
    signed.id.push('x');
    assert!(!verify_signed(&w.bob_bundle, &signed));
    assert!(!verify_signed(&w.alice_bundle, &w.signed));
    let mut signed = w.signed.clone();
    signed.kind = fireplace_crypto::PreKeyKind::OneTime;
    assert!(!verify_signed(&w.bob_bundle, &signed));
    let mut signed = w.signed.clone();
    signed.sig = None;
    assert!(!verify_signed(&w.bob_bundle, &signed));

    // A handshake is refused when the bundle's certificate or signed prekey
    // does not verify, and when a "one-time" prekey is of the signed kind.
    let mut bad_cert = w.bob_bundle.clone();
    bad_cert.cert[10] ^= 1;
    let mut bad_signed = w.signed.clone();
    bad_signed.sig.as_mut().unwrap()[10] ^= 1;
    for remote in [
        PreKeyBundle {
            device: bad_cert,
            signed: w.signed.clone(),
            one_time: None,
        },
        PreKeyBundle {
            device: w.bob_bundle.clone(),
            signed: bad_signed,
            one_time: None,
        },
        PreKeyBundle {
            device: w.bob_bundle.clone(),
            signed: w.signed.clone(),
            one_time: Some(w.signed.clone()),
        },
    ] {
        assert!(matches!(
            Session::initiate(&w.alice_keys, &w.alice_bundle, &remote, &mut rng, NOW),
            Err(Error::Crypto(_))
        ));
    }
}

#[test]
fn the_skipped_message_limit_holds_at_its_edge() {
    let mut rng = Rng::os();
    let mut w = world(&mut rng);
    let first = w.alice.encrypt(b"0", "chat-1", &mut rng).unwrap();
    w.bob.decrypt(&first, "chat-1", &mut rng, NOW).unwrap();
    // Bob has read message 0. Alice sends 1 to 1001 and Bob sees only the
    // last two: 1001 is 1,000 ahead, 1002 would be 1,001.
    let mut last = None;
    for _ in 0..1001 {
        last = Some(w.alice.encrypt(b"x", "chat-1", &mut rng).unwrap());
    }
    let edge = last.unwrap();
    assert_eq!(edge.n, 1001);
    let beyond = w.alice.encrypt(b"y", "chat-1", &mut rng).unwrap();

    let saved = w.bob.to_json();
    let mut bob = copy(&w.bob);
    assert!(bob.decrypt(&beyond, "chat-1", &mut rng, NOW).is_err());
    assert_eq!(bob.to_json(), saved);
    // Exactly at the limit it is read, and the 1,000 keys in between are kept.
    assert_eq!(bob.decrypt(&edge, "chat-1", &mut rng, NOW).unwrap(), b"x");
    assert!(bob.to_json().len() > saved.len() + 1000 * 44);
    assert_eq!(bob.decrypt(&beyond, "chat-1", &mut rng, NOW).unwrap(), b"y");
}
