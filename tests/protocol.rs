//! The two ends of a session, built with the operating-system generator,
//! agree on the session id and on every plaintext. A second run from one
//! recorded byte stream is byte-for-byte the same, which is what the Dart
//! export compares against.

use fireplace_crypto::{
    AccountIdentity, DeviceKeys, Error, PreKeyBundle, PreKeyRecord, RecoveryKey, Rng, Session,
    link_open, link_seal, one_time, recovery_decrypt, recovery_encrypt, request_fingerprint,
    safety_number, sign_prekey,
};

const NOW: i64 = 1_700_000_000_000;

#[test]
fn handshake_ratchet_skip_and_replay() {
    let mut rng = Rng::os();
    let alice_id = AccountIdentity::generate(&mut rng).unwrap();
    let alice_keys = DeviceKeys::generate(&mut rng).unwrap();
    let alice_bundle = alice_keys.certify(&alice_id, "alice", &mut rng).unwrap();
    let bob_id = AccountIdentity::generate(&mut rng).unwrap();
    let bob_keys = DeviceKeys::generate(&mut rng).unwrap();
    let bob_bundle = bob_keys.certify(&bob_id, "bob", &mut rng).unwrap();
    assert!(alice_id.consistent(&mut rng).unwrap());
    assert!(alice_keys.consistent());
    let signed_record = PreKeyRecord::generate(&mut rng, NOW).unwrap();
    let signed = sign_prekey(
        &signed_record,
        &bob_id,
        "bob",
        &bob_keys.device_id,
        &mut rng,
    )
    .unwrap();
    let one_time_record = PreKeyRecord::generate(&mut rng, NOW).unwrap();
    assert!(signed_record.consistent());
    let remote = PreKeyBundle {
        device: bob_bundle.clone(),
        signed: signed.clone(),
        one_time: Some(one_time(&one_time_record)),
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
    assert_eq!(alice.session_id, bob.session_id);
    assert!(alice.self_check());
    assert!(bob.self_check());
    assert!(!alice.acknowledged());
    assert!(!bob.can_send());

    let first = alice.encrypt(b"one", "chat-1", &mut rng).unwrap();
    let second = alice.encrypt(b"two", "chat-1", &mut rng).unwrap();
    let third = alice.encrypt(b"three", "chat-1", &mut rng).unwrap();
    assert_eq!(
        bob.decrypt(&third, "chat-1", &mut rng, NOW).unwrap(),
        b"three"
    );
    assert!(bob.acknowledged());
    assert_eq!(
        bob.decrypt(&first, "chat-1", &mut rng, NOW).unwrap(),
        b"one"
    );
    assert_eq!(
        bob.decrypt(&second, "chat-1", &mut rng, NOW).unwrap(),
        b"two"
    );
    assert!(bob.decrypt(&third, "chat-1", &mut rng, NOW).is_err());

    let reply = bob.encrypt(b"back", "chat-1", &mut rng).unwrap();
    assert_eq!(
        alice.decrypt(&reply, "chat-1", &mut rng, NOW).unwrap(),
        b"back"
    );
    assert!(alice.acknowledged());
    let mut forged = alice.encrypt(b"nope", "chat-1", &mut rng).unwrap();
    forged.mac[0] ^= 1;
    assert!(bob.decrypt(&forged, "chat-1", &mut rng, NOW).is_err());

    let stored = bob.to_json();
    let mut restored = Session::from_json(&stored).unwrap();
    let again = alice.encrypt(b"after load", "chat-1", &mut rng).unwrap();
    assert_eq!(
        restored.decrypt(&again, "chat-1", &mut rng, NOW).unwrap(),
        b"after load"
    );
    assert!(Session::try_from_json(&stored.replace("\"pv\":4", "\"pv\":3")).is_none());
}

struct Pair {
    alice: Session,
    bob: Session,
    signed_pub: Vec<u8>,
}

fn pair(rng: &mut Rng) -> Pair {
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
        signed,
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
    Pair {
        alice,
        bob,
        signed_pub: signed_record.x25519_pub.clone(),
    }
}

#[test]
fn failed_auth_does_not_commit_and_the_ninth_new_chain_is_limited() {
    let mut rng = Rng::os();
    let Pair {
        mut alice, mut bob, ..
    } = pair(&mut rng);
    let first = alice.encrypt(b"one", "chat-1", &mut rng).unwrap();
    let held = alice.encrypt(b"held", "chat-1", &mut rng).unwrap();
    assert_eq!(
        bob.decrypt(&first, "chat-1", &mut rng, NOW).unwrap(),
        b"one"
    );

    let mut forged = first.clone();
    forged.rx = vec![0x11; 32];
    forged.mac[0] ^= 0xff;
    for _ in 0..8 {
        let err = bob.decrypt(&forged, "chat-1", &mut rng, NOW).unwrap_err();
        assert!(matches!(err, Error::Crypto(_)), "{err}");
    }
    assert_eq!(
        bob.decrypt(&forged, "chat-1", &mut rng, NOW).unwrap_err(),
        Error::RateLimited
    );
    assert_eq!(
        bob.decrypt(&held, "chat-1", &mut rng, NOW).unwrap(),
        b"held"
    );
}

#[test]
fn reflected_chain_and_wrong_session_do_not_spend_the_budget() {
    let mut rng = Rng::os();
    let Pair {
        mut alice,
        mut bob,
        signed_pub,
    } = pair(&mut rng);
    let first = alice.encrypt(b"one", "chat-1", &mut rng).unwrap();
    assert_eq!(
        bob.decrypt(&first, "chat-1", &mut rng, NOW).unwrap(),
        b"one"
    );

    let mut wrong = first.clone();
    wrong.sid = "not-this-session".to_string();
    for _ in 0..20 {
        assert_eq!(
            bob.decrypt(&wrong, "chat-1", &mut rng, NOW).unwrap_err(),
            Error::Crypto("wrong session")
        );
    }

    let mut reflected = first.clone();
    reflected.rx = signed_pub;
    reflected.n = 40;
    assert_eq!(
        bob.decrypt(&reflected, "chat-1", &mut rng, NOW)
            .unwrap_err(),
        Error::Crypto("replayed or reflected chain")
    );

    let mut forged = first.clone();
    forged.rx = vec![0x22; 32];
    forged.mac[0] ^= 0xff;
    for _ in 0..7 {
        assert!(matches!(
            bob.decrypt(&forged, "chat-1", &mut rng, NOW).unwrap_err(),
            Error::Crypto(_)
        ));
    }
    assert_eq!(
        bob.decrypt(&reflected, "chat-1", &mut rng, NOW)
            .unwrap_err(),
        Error::Crypto("replayed or reflected chain")
    );
    assert!(matches!(
        bob.decrypt(&forged, "chat-1", &mut rng, NOW).unwrap_err(),
        Error::Crypto(_)
    ));
    assert_eq!(
        bob.decrypt(&forged, "chat-1", &mut rng, NOW).unwrap_err(),
        Error::RateLimited
    );
}

#[test]
fn same_stream_is_byte_for_byte() {
    let pattern: Vec<u8> = (0..8192).map(|i| (i * 17 + 3) as u8).collect();
    let first = scripted(&pattern);
    let second = scripted(&pattern);
    assert_eq!(first, second);
    assert_ne!(scripted(&pattern), scripted(&vec![9u8; pattern.len()]));
}

fn scripted(stream: &[u8]) -> String {
    let mut rng = Rng::stream(stream.to_vec());
    let identity = AccountIdentity::generate(&mut rng).unwrap();
    let keys = DeviceKeys::generate(&mut rng).unwrap();
    let bundle = keys.certify(&identity, "ada", &mut rng).unwrap();
    format!(
        "{}|{}|{}",
        identity.to_json(),
        keys.to_json(),
        bundle.to_json()
    )
}

#[test]
fn recovery_and_link_roundtrip() {
    let mut rng = Rng::os();
    let identity = AccountIdentity::generate(&mut rng).unwrap();
    let key = RecoveryKey::generate(&mut rng).unwrap();
    let shown = key.display().unwrap();
    let parsed = RecoveryKey::parse(&shown.to_lowercase().replace('-', " "))
        .unwrap()
        .unwrap();
    assert_eq!(parsed.as_bytes(), key.as_bytes());
    assert!(
        RecoveryKey::parse("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
            .unwrap()
            .is_none()
    );
    let blob = recovery_encrypt(&identity, &key, &mut rng).unwrap();
    let opened = recovery_decrypt(&blob, &parsed).unwrap();
    assert_eq!(opened.to_json(), identity.to_json());
    assert!(recovery_decrypt(&blob, &RecoveryKey::generate(&mut rng).unwrap()).is_err());

    let device = DeviceKeys::generate(&mut rng).unwrap();
    let fingerprint = request_fingerprint(&device.x25519_pub, &device.kem_pub).unwrap();
    assert_eq!(fingerprint.len(), 22);
    let sealed = link_seal(
        &identity,
        "ada",
        &device.device_id,
        &device.x25519_pub,
        &device.kem_pub,
        &mut rng,
    )
    .unwrap();
    let moved = link_open(&sealed, "ada", &device).unwrap();
    assert_eq!(moved.to_json(), identity.to_json());
}

#[test]
fn safety_number_ignores_order() {
    let mut rng = Rng::os();
    let a = AccountIdentity::generate(&mut rng)
        .unwrap()
        .public_bytes()
        .unwrap();
    let b = AccountIdentity::generate(&mut rng)
        .unwrap()
        .public_bytes()
        .unwrap();
    assert_eq!(
        safety_number(&a, &b).unwrap(),
        safety_number(&b, &a).unwrap()
    );
    assert_ne!(
        safety_number(&a, &a).unwrap(),
        safety_number(&a, &b).unwrap()
    );
}
