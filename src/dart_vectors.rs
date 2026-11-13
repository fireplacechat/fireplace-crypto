//! Known answers exported by the app's `scripts/export_crypto_vectors.dart`.
//! The scripted sections replay one recorded stream. The natural section was
//! produced by the operating-system generator, so this side only decrypts it.

use crate::codec::{self, Json};
use crate::device::DeviceKeys;
use crate::fingerprint::{identity_fingerprint, safety_number};
use crate::identity::AccountIdentity;
use crate::link::{confirmation_code, request_fingerprint, seal as link_seal};
use crate::prekeys::{self, PreKeyBundle, PreKeyRecord};
use crate::recovery::{self, RecoveryKey};
use crate::rng::Rng;
use crate::session::{Envelope, Session};

fn pattern() -> Vec<u8> {
    (0..8192).map(|i| ((i * 17 + 3) & 0xff) as u8).collect()
}

fn root() -> Json {
    // Synthetic vectors, shipped with the crate so this test compiles from a
    // packaged source tree. NIST and Wycheproof files stay under tests/.
    codec::parse_json(include_str!("../vectors/dart_vectors.json")).expect("vector json")
}

fn object<'a>(value: &'a Json, key: &str) -> &'a [(String, Json)] {
    match codec::obj_get(value.as_object().unwrap(), key).unwrap() {
        Json::Obj(pairs) => pairs,
        _ => panic!("{key} is not an object"),
    }
}

fn text<'a>(obj: &'a [(String, Json)], key: &str) -> &'a str {
    codec::obj_str(obj, key).unwrap_or_else(|_| panic!("missing {key}"))
}

fn same(what: &str, got: &str, expected: &str) {
    if got == expected {
        return;
    }
    let at = got
        .bytes()
        .zip(expected.bytes())
        .position(|(a, b)| a != b)
        .unwrap_or(got.len().min(expected.len()));
    let show = |s: &str| {
        let start = (at.saturating_sub(48)..=at)
            .rev()
            .find(|i| s.is_char_boundary(*i))
            .unwrap_or(0);
        let end = (at..=(at + 48).min(s.len()))
            .find(|i| s.is_char_boundary(*i))
            .unwrap_or(s.len());
        s[start..end].to_string()
    };
    panic!(
        "{what} differs at byte {at} (got {} bytes, expected {})\ngot: {}\nexp: {}",
        got.len(),
        expected.len(),
        show(got),
        show(expected)
    );
}

fn created_at(session_json: &str) -> i64 {
    let value = codec::parse_json(session_json).unwrap();
    codec::obj_i64(value.as_object().unwrap(), "createdAt").unwrap()
}

#[test]
fn scripted_handshake_matches_dart() {
    let doc = root();
    let section = object(&doc, "handshake");
    let prekey_now = codec::obj_i64(section, "prekeyNow").unwrap();
    let mut rng = Rng::stream(pattern());

    let alice_id = AccountIdentity::generate(&mut rng).unwrap();
    same(
        "alice identity",
        &alice_id.to_json(),
        text(section, "aliceIdentity"),
    );
    let alice_keys = DeviceKeys::generate(&mut rng).unwrap();
    same(
        "alice device",
        &alice_keys.to_json(),
        text(section, "aliceDevice"),
    );
    let alice_bundle = alice_keys.certify(&alice_id, "alice", &mut rng).unwrap();
    same(
        "alice bundle",
        &alice_bundle.to_json(),
        text(section, "aliceBundle"),
    );

    let bob_id = AccountIdentity::generate(&mut rng).unwrap();
    same(
        "bob identity",
        &bob_id.to_json(),
        text(section, "bobIdentity"),
    );
    let bob_keys = DeviceKeys::generate(&mut rng).unwrap();
    same(
        "bob device",
        &bob_keys.to_json(),
        text(section, "bobDevice"),
    );
    let bob_bundle = bob_keys.certify(&bob_id, "bob", &mut rng).unwrap();
    same(
        "bob bundle",
        &bob_bundle.to_json(),
        text(section, "bobBundle"),
    );

    let signed_record = PreKeyRecord::generate(&mut rng, prekey_now).unwrap();
    same(
        "signed record",
        &signed_record.to_json(),
        text(section, "signedRecord"),
    );
    let signed = prekeys::sign(
        &signed_record,
        &bob_id,
        "bob",
        &bob_keys.device_id,
        &mut rng,
    )
    .unwrap();
    same(
        "signed prekey",
        &signed.to_json(),
        text(section, "signedPrekey"),
    );
    let one_time_record = PreKeyRecord::generate(&mut rng, prekey_now).unwrap();
    same(
        "one-time record",
        &one_time_record.to_json(),
        text(section, "oneTimeRecord"),
    );
    let one_time = prekeys::one_time(&one_time_record);
    same(
        "one-time prekey",
        &one_time.to_json(),
        text(section, "oneTimePrekey"),
    );

    let remote = PreKeyBundle {
        device: bob_bundle.clone(),
        signed,
        one_time: Some(one_time),
    };
    let alice_created = created_at(text(section, "aliceSession"));
    let (mut alice, handshake) =
        Session::initiate(&alice_keys, &alice_bundle, &remote, &mut rng, alice_created).unwrap();
    same(
        "handshake",
        &handshake.to_json(),
        text(section, "handshake"),
    );

    let bob_created = created_at(text(section, "bobSession"));
    let bob = Session::accept(
        &bob_keys,
        &bob_bundle,
        &alice_bundle,
        &handshake,
        &signed_record,
        Some(&one_time_record),
        bob_created,
    )
    .unwrap();
    same("bob session", &bob.to_json(), text(section, "bobSession"));

    let envelope = alice.encrypt(b"hello", "chat-1", &mut rng).unwrap();
    same(
        "alice session",
        &alice.to_json(),
        text(section, "aliceSession"),
    );
    same("envelope", &envelope.to_json(), text(section, "envelope"));

    let alice_pub = alice_id.public_bytes().unwrap();
    let bob_pub = bob_id.public_bytes().unwrap();
    same(
        "alice fingerprint",
        &identity_fingerprint(&alice_pub).unwrap(),
        text(section, "aliceFingerprint"),
    );
    same(
        "bob fingerprint",
        &identity_fingerprint(&bob_pub).unwrap(),
        text(section, "bobFingerprint"),
    );
    let safety = safety_number(&alice_pub, &bob_pub).unwrap();
    same("safety number", &safety, text(section, "safety"));
    same(
        "safety number swapped",
        &safety_number(&bob_pub, &alice_pub).unwrap(),
        text(section, "safetySwapped"),
    );
    same(
        "link fingerprint",
        &request_fingerprint(&bob_keys.x25519_pub, &bob_keys.kem_pub).unwrap(),
        text(section, "linkFingerprint"),
    );
    same(
        "link code",
        &confirmation_code(&alice_pub, &bob_keys.x25519_pub, &bob_keys.kem_pub).unwrap(),
        text(section, "linkCode"),
    );
}

#[test]
fn scripted_recovery_and_link_match_dart() {
    let doc = root();
    let section = object(&doc, "recovery");
    let mut rng = Rng::stream(pattern());
    let identity = AccountIdentity::generate(&mut rng).unwrap();
    same("identity", &identity.to_json(), text(section, "identity"));
    let key = RecoveryKey::generate(&mut rng).unwrap();
    same("display", &key.display().unwrap(), text(section, "display"));
    let blob = recovery::encrypt(&identity, &key, &mut rng).unwrap();
    same("blob", &blob, text(section, "blob"));
    let device = DeviceKeys::generate(&mut rng).unwrap();
    same("device", &device.to_json(), text(section, "device"));
    let sealed = link_seal(
        &identity,
        "ada",
        &device.device_id,
        &device.x25519_pub,
        &device.kem_pub,
        &mut rng,
    )
    .unwrap();
    same("sealed", &sealed.to_json(), text(section, "sealed"));
}

/// A session built here, written out for the app to decrypt with Dart.
/// Set `FP_FIXTURE` to a path to refresh `test/crypto/vectors/rust_session.json`.
fn rust_fixture() -> String {
    let pattern: Vec<u8> = (0..8192).map(|i| ((i * 13 + 5) & 0xff) as u8).collect();
    let mut rng = Rng::stream(pattern);
    const NOW: i64 = 1_700_000_000_000;
    let alice_id = AccountIdentity::generate(&mut rng).unwrap();
    let alice_keys = DeviceKeys::generate(&mut rng).unwrap();
    let alice_bundle = alice_keys.certify(&alice_id, "alice", &mut rng).unwrap();
    let bob_id = AccountIdentity::generate(&mut rng).unwrap();
    let bob_keys = DeviceKeys::generate(&mut rng).unwrap();
    let bob_bundle = bob_keys.certify(&bob_id, "bob", &mut rng).unwrap();
    let signed_record = PreKeyRecord::generate(&mut rng, NOW).unwrap();
    let signed = prekeys::sign(
        &signed_record,
        &bob_id,
        "bob",
        &bob_keys.device_id,
        &mut rng,
    )
    .unwrap();
    let one_time_record = PreKeyRecord::generate(&mut rng, NOW).unwrap();
    let remote = PreKeyBundle {
        device: bob_bundle.clone(),
        signed,
        one_time: Some(prekeys::one_time(&one_time_record)),
    };
    let (mut alice, handshake) =
        Session::initiate(&alice_keys, &alice_bundle, &remote, &mut rng, NOW).unwrap();
    let mut bob = Session::accept(
        &bob_keys,
        &bob_bundle,
        &alice_bundle,
        &handshake,
        &signed_record,
        Some(&one_time_record),
        NOW,
    )
    .unwrap();
    let envelope = alice
        .encrypt(b"hello from rust", "chat-1", &mut rng)
        .unwrap();
    let bob_before = bob.to_json();
    let alice_after_send = alice.to_json();
    let plain = bob.decrypt(&envelope, "chat-1", &mut rng, NOW).unwrap();
    assert_eq!(plain, b"hello from rust");
    let reply = bob.encrypt(b"reply from rust", "chat-1", &mut rng).unwrap();
    let opened = alice.decrypt(&reply, "chat-1", &mut rng, NOW).unwrap();
    assert_eq!(opened, b"reply from rust");
    codec::to_json(&Json::object(vec![
        ("chatId".to_string(), Json::Str("chat-1".to_string())),
        (
            "plaintext".to_string(),
            Json::Str("hello from rust".to_string()),
        ),
        (
            "replyPlaintext".to_string(),
            Json::Str("reply from rust".to_string()),
        ),
        ("bobSession".to_string(), Json::Str(bob_before)),
        ("envelope".to_string(), Json::Str(envelope.to_json())),
        ("aliceSession".to_string(), Json::Str(alice_after_send)),
        ("reply".to_string(), Json::Str(reply.to_json())),
    ]))
}

#[test]
fn rust_fixture_round_trips() {
    let doc = rust_fixture();
    if let Ok(path) = std::env::var("FP_FIXTURE") {
        std::fs::write(&path, format!("{doc}\n")).unwrap();
    }
    let _ = doc;
}

#[test]
fn scripted_transcript_matches_dart() {
    let doc = root();
    let section = object(&doc, "transcript");
    let prekey_now = codec::obj_i64(section, "prekeyNow").unwrap();
    let mut rng = Rng::stream(pattern());

    let alice_id = AccountIdentity::generate(&mut rng).unwrap();
    let alice_keys = DeviceKeys::generate(&mut rng).unwrap();
    let alice_bundle = alice_keys.certify(&alice_id, "alice", &mut rng).unwrap();
    let bob_id = AccountIdentity::generate(&mut rng).unwrap();
    let bob_keys = DeviceKeys::generate(&mut rng).unwrap();
    let bob_bundle = bob_keys.certify(&bob_id, "bob", &mut rng).unwrap();
    let signed_record = PreKeyRecord::generate(&mut rng, prekey_now).unwrap();
    let signed = prekeys::sign(
        &signed_record,
        &bob_id,
        "bob",
        &bob_keys.device_id,
        &mut rng,
    )
    .unwrap();
    let one_time_record = PreKeyRecord::generate(&mut rng, prekey_now).unwrap();
    let remote = PreKeyBundle {
        device: bob_bundle.clone(),
        signed,
        one_time: Some(prekeys::one_time(&one_time_record)),
    };
    let alice_created = created_at(text(section, "aliceFinal"));
    let (mut alice, handshake) =
        Session::initiate(&alice_keys, &alice_bundle, &remote, &mut rng, alice_created).unwrap();
    let bob_created = created_at(text(section, "bobFinal"));
    let mut bob = Session::accept(
        &bob_keys,
        &bob_bundle,
        &alice_bundle,
        &handshake,
        &signed_record,
        Some(&one_time_record),
        bob_created,
    )
    .unwrap();

    let first = alice.encrypt(b"one", "chat-1", &mut rng).unwrap();
    let second = alice.encrypt(b"two", "chat-1", &mut rng).unwrap();
    same("alice 0", &first.to_json(), text(section, "aliceToBob0"));
    same("alice 1", &second.to_json(), text(section, "aliceToBob1"));

    let late = bob
        .decrypt(&second, "chat-1", &mut rng, bob_created)
        .unwrap();
    assert_eq!(late, b"two");
    same(
        "bob after skip",
        &bob.to_json(),
        text(section, "bobAfterSkip"),
    );
    let early = bob
        .decrypt(&first, "chat-1", &mut rng, bob_created)
        .unwrap();
    assert_eq!(early, b"one");

    let reply0 = bob.encrypt(b"three", "chat-1", &mut rng).unwrap();
    let reply1 = bob.encrypt(b"four", "chat-1", &mut rng).unwrap();
    same("bob 0", &reply0.to_json(), text(section, "bobToAlice0"));
    same("bob 1", &reply1.to_json(), text(section, "bobToAlice1"));
    same("bob final", &bob.to_json(), text(section, "bobFinal"));

    let alice_late = alice
        .decrypt(&reply1, "chat-1", &mut rng, alice_created)
        .unwrap();
    assert_eq!(alice_late, b"four");
    same(
        "alice after skip",
        &alice.to_json(),
        text(section, "aliceAfterSkip"),
    );
    let alice_early = alice
        .decrypt(&reply0, "chat-1", &mut rng, alice_created)
        .unwrap();
    assert_eq!(alice_early, b"three");
    same("alice final", &alice.to_json(), text(section, "aliceFinal"));
}

#[test]
fn natural_dart_session_decrypts() {
    let doc = root();
    let section = object(&doc, "natural");
    let mut bob = Session::from_json(text(section, "bobSession")).unwrap();
    let envelope = Envelope::from_json(text(section, "envelope")).unwrap();
    let plain = bob
        .decrypt(
            &envelope,
            text(section, "chatId"),
            &mut Rng::os(),
            1_700_000_000_000,
        )
        .unwrap();
    assert_eq!(plain, text(section, "plaintext").as_bytes());
}
