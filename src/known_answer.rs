//! NIST ACVP and Wycheproof known answers, the same files the Dart tests use.
//!
//! They live under `tests/vectors` and are not part of the published crate.
//! When that directory is absent, these tests return without checking. A
//! present directory with a missing file is a failure. NIST signing and
//! verification use the vector's own context string, which is not always
//! `fireplace/v1`, so those two call `ml-dsa` directly. Everything else goes
//! through this crate's primitives.

use std::path::PathBuf;

use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, ExpandedSigningKeyBytes, MlDsa65,
    Signature as DsaSignature, VerifyingKey as DsaVerifyingKey,
};
use ml_kem::kem::Key;
use ml_kem::{EncapsulationKey, MlKem768};

use crate::codec::{self, Json};
use crate::prim::{self, MLDSA_PK, MLDSA_SIG, MLDSA_SK, MLKEM_EK};
use crate::rng::Rng;

fn vectors_dir() -> Option<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors");
    dir.is_dir().then_some(dir)
}

fn fixture(name: &str) -> Option<Json> {
    let Some(dir) = vectors_dir() else {
        if std::env::var_os("FP_REQUIRE_VECTORS").is_some() {
            panic!("tests/vectors is missing; FP_REQUIRE_VECTORS is set");
        }
        return None;
    };
    let path = dir.join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "{} is missing from the vectors directory ({err})",
            path.display()
        )
    });
    Some(codec::parse_json(&text).unwrap_or_else(|err| panic!("{name} did not parse ({err})")))
}

fn rows<'a>(doc: &'a Json, key: &str) -> &'a [Json] {
    let obj = doc.as_object().expect("vector root");
    codec::obj_get(obj, key)
        .unwrap_or_else(|_| panic!("missing {key}"))
        .as_array()
        .unwrap_or_else(|_| panic!("{key} is not an array"))
}

fn field<'a>(row: &'a Json, key: &str) -> &'a Json {
    let obj = row.as_object().expect("vector row");
    codec::obj_get(obj, key).unwrap_or_else(|_| panic!("missing {key}"))
}

fn field_str<'a>(row: &'a Json, key: &str) -> &'a str {
    field(row, key)
        .as_str()
        .unwrap_or_else(|_| panic!("{key} is not a string"))
}

fn tc_id(row: &Json) -> i64 {
    field(row, "tcId")
        .as_i64()
        .unwrap_or_else(|_| panic!("tcId is not an integer"))
}

fn decode_hex(text: &str) -> Vec<u8> {
    if !text.len().is_multiple_of(2) {
        panic!("odd hex length");
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap_or_else(|_| panic!("bad hex")))
        .collect()
}

fn expect_bytes(what: &str, tc: i64, got: &[u8], expected_hex: &str) {
    let want = decode_hex(expected_hex);
    if got == want.as_slice() {
        return;
    }
    let at = got
        .iter()
        .zip(want.iter())
        .position(|(a, b)| a != b)
        .unwrap_or(got.len().min(want.len()));
    panic!(
        "{what} tcId {tc} differs at byte {at} (got {} bytes, expected {})",
        got.len(),
        want.len()
    );
}

fn array32(bytes: &[u8], what: &str) -> [u8; 32] {
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("{what} is {} bytes", bytes.len()))
}

/// NIST's encapsulation-key check. A key the crate refuses to load counts as
/// rejected, which is what the Dart test treats as an encapsulate throw.
fn encapsulation_key_accepted(bytes: &[u8]) -> bool {
    if bytes.len() != MLKEM_EK {
        return false;
    }
    let Ok(encoded) = Key::<EncapsulationKey<MlKem768>>::try_from(bytes) else {
        return false;
    };
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        EncapsulationKey::<MlKem768>::new(&encoded).is_ok()
    }))
    .unwrap_or(false)
}

fn signing_key(secret: &[u8]) -> ExpandedSigningKey<MlDsa65> {
    assert_eq!(secret.len(), MLDSA_SK, "ml-dsa secret length");
    let encoded = ExpandedSigningKeyBytes::<MlDsa65>::try_from(secret)
        .expect("ml-dsa secret does not fit the expanded encoding");
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        #[allow(deprecated)]
        ExpandedSigningKey::<MlDsa65>::from_expanded(&encoded)
    }))
    .unwrap_or_else(|_| panic!("ml-dsa from_expanded panicked"))
}

fn dsa_verify(public: &[u8], message: &[u8], signature: &[u8], ctx: &[u8]) -> bool {
    if public.len() != MLDSA_PK || signature.len() != MLDSA_SIG {
        return false;
    }
    let Ok(encoded_pk) = EncodedVerifyingKey::<MlDsa65>::try_from(public) else {
        return false;
    };
    let Ok(encoded_sig) = EncodedSignature::<MlDsa65>::try_from(signature) else {
        return false;
    };
    let Some(signature) = DsaSignature::<MlDsa65>::decode(&encoded_sig) else {
        return false;
    };
    let Ok(verifying) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        DsaVerifyingKey::<MlDsa65>::decode(&encoded_pk)
    })) else {
        return false;
    };
    verifying.verify_with_context(message, ctx, &signature)
}

#[test]
fn nist_ml_kem_768_matches() {
    let Some(doc) = fixture("nist_mlkem768.json") else {
        return;
    };
    for row in rows(&doc, "keyGen") {
        let tc = tc_id(row);
        let mut seed = [0u8; 64];
        let d = decode_hex(field_str(row, "d"));
        let z = decode_hex(field_str(row, "z"));
        seed[..32].copy_from_slice(&array32(&d, "d"));
        seed[32..].copy_from_slice(&array32(&z, "z"));
        let pair = prim::mlkem_from_seed(&seed);
        expect_bytes("ek", tc, &pair.public, field_str(row, "ek"));
        expect_bytes("dk", tc, &pair.secret, field_str(row, "dk"));
    }
    for row in rows(&doc, "encaps") {
        let tc = tc_id(row);
        let (ciphertext, shared) = prim::mlkem_encapsulate(
            &decode_hex(field_str(row, "ek")),
            &decode_hex(field_str(row, "m")),
        )
        .unwrap_or_else(|err| panic!("encaps tcId {tc}: {err}"));
        expect_bytes("ciphertext", tc, &ciphertext, field_str(row, "c"));
        expect_bytes("shared", tc, &shared, field_str(row, "k"));
    }
    for row in rows(&doc, "decaps") {
        let tc = tc_id(row);
        let shared = prim::mlkem_decapsulate(
            &decode_hex(field_str(row, "dk")),
            &decode_hex(field_str(row, "c")),
        )
        .unwrap_or_else(|err| panic!("decaps tcId {tc}: {err}"));
        expect_bytes("decaps", tc, &shared, field_str(row, "k"));
    }
    for row in rows(&doc, "ekCheck") {
        let tc = tc_id(row);
        let accepted = encapsulation_key_accepted(&decode_hex(field_str(row, "ek")));
        let passed = field(row, "testPassed").as_bool().expect("testPassed");
        assert_eq!(accepted, passed, "ekCheck tcId {tc}");
    }
}

#[test]
fn nist_ml_dsa_65_matches() {
    let Some(doc) = fixture("nist_mldsa65.json") else {
        return;
    };
    for row in rows(&doc, "keyGen") {
        let tc = tc_id(row);
        let pair = prim::mldsa_from_seed(&array32(&decode_hex(field_str(row, "seed")), "seed"));
        expect_bytes("pk", tc, &pair.public, field_str(row, "pk"));
        expect_bytes("sk", tc, &pair.secret, field_str(row, "sk"));
    }
    for row in rows(&doc, "sigGen") {
        let tc = tc_id(row);
        let key = signing_key(&decode_hex(field_str(row, "sk")));
        let message = decode_hex(field_str(row, "message"));
        let ctx = decode_hex(field_str(row, "context"));
        let deterministic = matches!(field(row, "deterministic"), Json::Bool(true));
        let signature = if deterministic {
            key.sign_deterministic(&message, &ctx)
                .unwrap_or_else(|_| panic!("sigGen tcId {tc}"))
        } else {
            let rnd = decode_hex(field_str(row, "rnd"));
            let mut rng = Rng::stream(rnd);
            key.sign_randomized(&message, &ctx, &mut rng)
                .unwrap_or_else(|_| panic!("sigGen tcId {tc}"))
        };
        let encoded = signature.encode().to_vec();
        expect_bytes("signature", tc, &encoded, field_str(row, "signature"));
    }
    let mut rejected = 0;
    for row in rows(&doc, "sigVer") {
        let tc = tc_id(row);
        let ok = dsa_verify(
            &decode_hex(field_str(row, "pk")),
            &decode_hex(field_str(row, "message")),
            &decode_hex(field_str(row, "signature")),
            &decode_hex(field_str(row, "context")),
        );
        let passed = field(row, "testPassed").as_bool().expect("testPassed");
        assert_eq!(ok, passed, "sigVer tcId {tc}");
        if !passed {
            rejected += 1;
        }
    }
    assert!(rejected > 0, "the set must include invalid signatures");
}

#[test]
fn wycheproof_classical_matches() {
    let Some(doc) = fixture("wycheproof_classical.json") else {
        return;
    };

    let mut checked = 0;
    for row in rows(&doc, "x25519") {
        let tc = tc_id(row);
        let result = field_str(row, "result");
        match prim::x25519_shared(
            &decode_hex(field_str(row, "private")),
            &decode_hex(field_str(row, "public")),
        ) {
            Ok(shared) => {
                if result == "valid" {
                    expect_bytes("x25519", tc, &shared, field_str(row, "shared"));
                    checked += 1;
                }
            }
            Err(_) => assert_eq!(result, "acceptable", "x25519 refused tcId {tc}"),
        }
    }
    assert!(checked > 200, "checked {checked} valid X25519 vectors");

    let mut invalid_seen = 0;
    for row in rows(&doc, "ed25519") {
        let tc = tc_id(row);
        let result = field_str(row, "result");
        let ok = prim::ed25519_verify(
            &decode_hex(field_str(row, "pk")),
            &decode_hex(field_str(row, "msg")),
            &decode_hex(field_str(row, "sig")),
        );
        assert_eq!(ok, result == "valid", "ed25519 tcId {tc}");
        if result == "invalid" {
            invalid_seen += 1;
        }
    }
    assert!(invalid_seen > 50, "saw {invalid_seen} invalid signatures");

    for row in rows(&doc, "aesgcm") {
        let tc = tc_id(row);
        let key = decode_hex(field_str(row, "key"));
        let nonce = decode_hex(field_str(row, "iv"));
        let aad = decode_hex(field_str(row, "aad"));
        let ciphertext = decode_hex(field_str(row, "ct"));
        let tag = decode_hex(field_str(row, "tag"));
        let message = decode_hex(field_str(row, "msg"));
        if field_str(row, "result") == "valid" {
            let opened = crate::aead::open(&key, &nonce, &aad, &ciphertext, &tag)
                .unwrap_or_else(|err| panic!("aes decrypt tcId {tc}: {err}"));
            assert_eq!(opened, message, "aes decrypt tcId {tc}");
            let (sealed, mac) = crate::aead::seal(&key, &nonce, &aad, &message)
                .unwrap_or_else(|err| panic!("aes encrypt tcId {tc}: {err}"));
            expect_bytes("aes ciphertext", tc, &sealed, field_str(row, "ct"));
            expect_bytes("aes tag", tc, &mac, field_str(row, "tag"));
        } else {
            assert!(
                crate::aead::open(&key, &nonce, &aad, &ciphertext, &tag).is_err(),
                "invalid aes case was accepted, tcId {tc}"
            );
        }
    }

    for row in rows(&doc, "hkdf") {
        if field_str(row, "result") != "valid" {
            continue;
        }
        let tc = tc_id(row);
        let size = field(row, "size").as_i64().expect("hkdf size");
        assert!(size > 0, "hkdf size tcId {tc}");
        let mut out = vec![0u8; usize::try_from(size).expect("hkdf size")];
        crate::kdf::hkdf_sha256(
            &decode_hex(field_str(row, "ikm")),
            &decode_hex(field_str(row, "salt")),
            &decode_hex(field_str(row, "info")),
            &mut out,
        )
        .unwrap_or_else(|err| panic!("hkdf tcId {tc}: {err}"));
        expect_bytes("hkdf", tc, &out, field_str(row, "okm"));
    }
}
