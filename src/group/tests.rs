use std::collections::HashMap;

use super::*;
use crate::codec::{b64_decode, b64_encode, b64url_encode, parse_json, to_json};

/// One device of one account, with its store and account identity.
struct Phone {
    store: GroupStore,
    uid: String,
    device: String,
}

fn identity() -> AccountIdentity {
    AccountIdentity::generate(&mut Rng::os()).unwrap()
}

fn phone(id: &AccountIdentity, uid: &str, device: &str) -> Phone {
    let mut p = Phone {
        store: GroupStore::open(HashMap::new()),
        uid: uid.into(),
        device: device.into(),
    };
    p.change(&format!(
        r#"{{"op":"device","identity":{},"uid":"{uid}","device":"{device}","deviceCertHash":"{}","generation":1}}"#,
        to_json(&Json::Str(id.to_json())),
        b64_encode(&[7u8; 32]),
    ));
    p
}

const GID: &str = "AAECAwQFBgcICQoLDA0ODw"; // 16 bytes, base64url

impl Phone {
    fn raw(&mut self, request: &str) -> Result<Json> {
        self.store.call(request).map(|s| parse_json(&s).unwrap())
    }
    /// A change that the app accepts at once.
    fn change(&mut self, request: &str) -> Json {
        let out = self.raw(request).unwrap();
        self.store.accept().unwrap();
        out
    }
    fn packages(&mut self, n: usize) -> Vec<String> {
        let out = self.change(&format!(r#"{{"op":"key_packages","count":{n}}}"#));
        field(&out, "packages")
            .as_array()
            .unwrap()
            .iter()
            .map(|p| field(p, "keyPackage").as_str().unwrap().to_owned())
            .collect()
    }
    /// Adds one account, merges at once (the server took it) and returns
    /// (commit, welcome).
    fn add(&mut self, packages: &[String]) -> (String, String) {
        let list: Vec<String> = packages.iter().map(|p| format!("\"{p}\"")).collect();
        let out = self.change(&format!(
            r#"{{"op":"commit_add","gid":"{GID}","keyPackages":[{}]}}"#,
            list.join(",")
        ));
        self.change(&format!(r#"{{"op":"merge_pending","gid":"{GID}"}}"#));
        (s(&out, "commit"), s(&out, "welcome"))
    }
    fn join(&mut self, welcome: &str) -> Json {
        self.change(&format!(r#"{{"op":"join","welcome":"{welcome}"}}"#))
    }
    fn send(&mut self, text: &str) -> String {
        let out = self.change(&format!(
            r#"{{"op":"encrypt","gid":"{GID}","plain":"{}","aad":"{}"}}"#,
            b64_encode(text.as_bytes()),
            b64_encode(b"op-1"),
        ));
        s(&out, "ciphertext")
    }
    fn receive(&mut self, message: &str) -> Json {
        self.change(&format!(
            r#"{{"op":"process","gid":"{GID}","message":"{message}"}}"#
        ))
    }
    fn info(&mut self) -> Json {
        self.raw(&format!(r#"{{"op":"info","gid":"{GID}"}}"#))
            .unwrap()
    }
}

fn field<'a>(json: &'a Json, key: &str) -> &'a Json {
    obj_get(json.as_object().unwrap(), key).unwrap()
}
fn s(json: &Json, key: &str) -> String {
    field(json, key).as_str().unwrap().to_owned()
}
fn epoch(json: &Json) -> i64 {
    field(json, "epoch").as_i64().unwrap()
}
fn text(json: &Json) -> String {
    String::from_utf8(b64_decode(&s(json, "plain")).unwrap()).unwrap()
}

/// Alice creates "Book club" and adds Bob's two devices.
fn book_club() -> (Phone, Phone, Phone) {
    let (a, b) = (identity(), identity());
    let mut alice = phone(&a, "alice", "alice-phone");
    let mut bob1 = phone(&b, "bob", "bob-phone");
    let mut bob2 = phone(&b, "bob", "bob-tablet");
    alice.change(&format!(
        r#"{{"op":"create","gid":"{GID}","name":"Book club"}}"#
    ));
    let packages = [bob1.packages(1), bob2.packages(1)].concat();
    let (_, welcome) = alice.add(&packages);
    bob1.join(&welcome);
    bob2.join(&welcome);
    (alice, bob1, bob2)
}

#[test]
fn create_join_and_exchange_messages() {
    let (mut alice, mut bob1, mut bob2) = book_club();
    let info = bob1.info();
    assert_eq!(s(&info, "name"), "Book club");
    assert_eq!(
        field(&info, "admins").as_array().unwrap(),
        &[Json::Str("alice".into())]
    );
    let uids: Vec<String> = field(&info, "members")
        .as_array()
        .unwrap()
        .iter()
        .map(|m| s(m, "uid"))
        .collect();
    assert_eq!(uids, ["alice", "bob", "bob"]);
    assert_eq!(epoch(&info), epoch(&alice.info()));

    let ct = alice.send("Anyone bringing snacks?");
    for bob in [&mut bob1, &mut bob2] {
        let got = bob.receive(&ct);
        assert_eq!(s(&got, "kind"), "application");
        assert_eq!(text(&got), "Anyone bringing snacks?");
        assert_eq!(s(field(&got, "sender"), "uid"), "alice");
        assert_eq!(b64_decode(&s(&got, "aad")).unwrap(), b"op-1");
    }
    // Bob's other devices read Bob's own messages too.
    let reply = bob1.send("I can do chips");
    assert_eq!(text(&bob2.receive(&reply)), "I can do chips");
    assert_eq!(text(&alice.receive(&reply)), "I can do chips");
}

#[test]
fn self_update_rename_and_remove_reach_every_member() {
    let (mut alice, mut bob1, mut bob2) = book_club();
    let start = epoch(&alice.info());

    let update = bob1.change(&format!(r#"{{"op":"commit_update","gid":"{GID}"}}"#));
    bob1.change(&format!(r#"{{"op":"merge_pending","gid":"{GID}"}}"#));
    for p in [&mut alice, &mut bob2] {
        let got = p.receive(&s(&update, "commit"));
        assert_eq!(s(&got, "kind"), "commit");
        assert_eq!(s(field(&got, "committer"), "uid"), "bob");
        assert_eq!(epoch(&got), start + 1);
    }

    let rename = alice.change(&format!(
        r#"{{"op":"commit_meta","gid":"{GID}","name":"Tea club"}}"#
    ));
    alice.change(&format!(r#"{{"op":"merge_pending","gid":"{GID}"}}"#));
    let got = bob1.receive(&s(&rename, "commit"));
    assert_eq!(s(&got, "name"), "Tea club");
    bob2.receive(&s(&rename, "commit"));

    // Remove Bob's tablet (leaf 2).
    let remove = alice.change(&format!(
        r#"{{"op":"commit_remove","gid":"{GID}","leaves":[2]}}"#
    ));
    alice.change(&format!(r#"{{"op":"merge_pending","gid":"{GID}"}}"#));
    let got = bob1.receive(&s(&remove, "commit"));
    let removed = field(&got, "removed").as_array().unwrap();
    assert_eq!(removed.len(), 1);
    assert_eq!(s(&removed[0], "device"), "bob-tablet");
    let gone = bob2.receive(&s(&remove, "commit"));
    assert_eq!(field(&gone, "active"), &Json::Bool(false));
    // The tablet cannot read what comes after.
    let later = alice.send("after the tablet left");
    assert!(
        bob2.raw(&format!(
            r#"{{"op":"process","gid":"{GID}","message":"{later}"}}"#
        ))
        .is_err()
    );
    assert_eq!(text(&bob1.receive(&later)), "after the tablet left");
}

#[test]
fn a_forged_credential_cannot_be_added() {
    let (a, mallory_id) = (identity(), identity());
    let mut alice = phone(&a, "alice", "alice-phone");
    alice.change(&format!(
        r#"{{"op":"create","gid":"{GID}","name":"Book club"}}"#
    ));
    // Mallory's credential claims to be Bob but is not signed by Bob's identity:
    // build Bob's credential, then swap in Mallory's signature key.
    let mut mallory = phone(&mallory_id, "bob", "bob-phone");
    let mut record =
        FireplaceCredential::decode(&mallory.store.provider.get(REC_CREDENTIAL).unwrap()).unwrap();
    record.signature_key[0] ^= 1;
    mallory
        .store
        .provider
        .put(REC_CREDENTIAL, record.encode().unwrap());
    let packages = mallory.packages(1);
    let list = format!("\"{}\"", packages[0]);
    let before = alice.info();
    assert!(
        alice
            .raw(&format!(
                r#"{{"op":"commit_add","gid":"{GID}","keyPackages":[{list}]}}"#
            ))
            .is_err()
    );
    // A failed change leaves nothing behind and nothing open.
    assert_eq!(alice.info(), before);
    assert!(alice.store.accept().is_err());
}

#[test]
fn an_add_names_the_account_and_can_be_held_to_an_expected_one() {
    let (a, b, other) = (identity(), identity(), identity());
    let mut alice = phone(&a, "alice", "alice-phone");
    alice.change(&format!(
        r#"{{"op":"create","gid":"{GID}","name":"Book club"}}"#
    ));
    let mut bob1 = phone(&b, "bob", "bob-phone");
    let mut bob2 = phone(&b, "bob", "bob-tablet");
    let packages = [bob1.packages(1), bob2.packages(1)].concat();
    let list = format!("\"{}\",\"{}\"", packages[0], packages[1]);
    let bob_identity = b64_encode(&b.public_bytes().unwrap());

    // The result names each device before anything is merged or sent.
    let out = alice
        .raw(&format!(
            r#"{{"op":"commit_add","gid":"{GID}","keyPackages":[{list}],"uid":"bob","identity":"{bob_identity}"}}"#
        ))
        .unwrap();
    let added = field(&out, "added").as_array().unwrap();
    assert_eq!(added.len(), 2);
    assert_eq!(s(&added[0], "uid"), "bob");
    assert_eq!(s(&added[0], "device"), "bob-phone");
    assert_eq!(s(&added[1], "device"), "bob-tablet");
    assert_eq!(s(&added[0], "identity"), bob_identity);
    alice.store.rollback().unwrap();

    // A different expected account, or the right account under another
    // identity key, is refused and changes nothing.
    let before = alice.info();
    let other_identity = b64_encode(&other.public_bytes().unwrap());
    for expected in [
        format!(r#""uid":"carol","identity":"{bob_identity}""#),
        format!(r#""uid":"bob","identity":"{other_identity}""#),
        r#""uid":"carol""#.to_string(),
        format!(r#""identity":"{other_identity}""#),
    ] {
        assert!(
            alice
                .raw(&format!(
                    r#"{{"op":"commit_add","gid":"{GID}","keyPackages":[{list}],{expected}}}"#
                ))
                .is_err(),
            "{expected}"
        );
        assert_eq!(alice.info(), before);
        assert!(alice.store.accept().is_err());
    }
}

#[test]
fn one_add_is_one_account() {
    let (a, b, c) = (identity(), identity(), identity());
    let mut alice = phone(&a, "alice", "alice-phone");
    alice.change(&format!(
        r#"{{"op":"create","gid":"{GID}","name":"Book club"}}"#
    ));
    let mut bob = phone(&b, "bob", "bob-phone");
    let mut carol = phone(&c, "carol", "carol-phone");
    // The same account id under a second identity key is a second account.
    let mut bob_again = phone(&c, "bob", "bob-tablet");
    let bob_kp = bob.packages(1).remove(0);
    for second in [carol.packages(1).remove(0), bob_again.packages(1).remove(0)] {
        assert!(
            alice
                .raw(&format!(
                    r#"{{"op":"commit_add","gid":"{GID}","keyPackages":["{bob_kp}","{second}"]}}"#
                ))
                .is_err()
        );
        assert!(alice.store.accept().is_err());
    }
}

#[test]
fn rollback_restores_the_store_and_a_change_must_finish_first() {
    let (mut alice, mut bob1, _) = book_club();
    let ct = alice.send("hello");
    let saved = bob1.store.records();
    let first = bob1
        .raw(&format!(
            r#"{{"op":"process","gid":"{GID}","message":"{ct}"}}"#
        ))
        .unwrap();
    assert!(!field(&first, "changes").as_array().unwrap().is_empty());
    // Nothing else may start while this change is open.
    assert!(
        bob1.raw(&format!(
            r#"{{"op":"encrypt","gid":"{GID}","plain":"aGk="}}"#
        ))
        .is_err()
    );
    bob1.store.rollback().unwrap();
    assert_eq!(bob1.store.records(), saved);
    // The same message decrypts again, because nothing was kept.
    assert_eq!(text(&bob1.receive(&ct)), "hello");
}

/// A Commit by `phone` that sets the metadata extension to exactly `raw`,
/// as a modified app could, without the checks `commit_meta` applies.
fn raw_meta_commit(phone: &mut Phone, raw: Vec<u8>) -> String {
    let gid = GroupId::from_slice(&crate::codec::b64url_decode(GID).unwrap());
    let mut group = phone.store.load(&gid).unwrap();
    let (signer, _) = phone.store.signer().unwrap();
    let extensions = Extensions::from_vec(vec![
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::Unknown(META_EXTENSION)],
            &[],
            &[CredentialType::Basic],
        )),
        Extension::Unknown(META_EXTENSION, UnknownExtension(raw)),
    ])
    .unwrap();
    let (commit, _, _) = group
        .update_group_context_extensions(&phone.store.provider, extensions, &signer)
        .unwrap();
    b64_encode(&tls(&commit).unwrap())
}

fn raw_meta(name: &str, admins: &[&str]) -> Vec<u8> {
    let mut parts: Vec<&[u8]> = vec![b"fireplace-group-meta-v1", name.as_bytes()];
    parts.extend(admins.iter().map(|a| a.as_bytes()));
    crate::codec::lp(&parts).unwrap()
}

#[test]
fn received_metadata_is_held_to_the_rules_for_sent_metadata() {
    let long = "x".repeat(41);
    let many: Vec<String> = (0..65).map(|i| format!("account-{i}")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    let cases: Vec<(&str, Vec<&str>)> = vec![
        (long.as_str(), vec!["alice"]),
        ("", vec!["alice"]),
        (" padded ", vec!["alice"]),
        ("Book club", vec!["alice", "alice"]),
        ("Book club", vec!["alice", ""]),
        ("Book club", vec!["a/b"]),
        ("Book club", many),
    ];
    for (name, admins) in cases {
        let (mut alice, mut bob1, _) = book_club();
        let commit = raw_meta_commit(&mut bob1, raw_meta(name, &admins));
        let before = alice.info();
        assert!(
            alice
                .raw(&format!(
                    r#"{{"op":"process","gid":"{GID}","message":"{commit}"}}"#
                ))
                .is_err(),
            "{name:?} {admins:?}"
        );
        // Refused, and nothing changed or left open.
        assert_eq!(alice.info(), before);
        assert!(alice.store.accept().is_err());
    }
    // Metadata within the rules, sent the same raw way, is accepted.
    let (mut alice, mut bob1, _) = book_club();
    let commit = raw_meta_commit(&mut bob1, raw_meta("Tea club", &["alice", "bob"]));
    let got = alice.receive(&commit);
    assert_eq!(s(&got, "name"), "Tea club");
    assert_eq!(field(&got, "admins").as_array().unwrap().len(), 2);
}

#[test]
fn this_device_cannot_send_metadata_others_would_refuse() {
    let (mut alice, _, _) = book_club();
    for admins in [r#"["alice","alice"]"#, r#"["alice",""]"#, r#"["a:b"]"#] {
        assert!(
            alice
                .raw(&format!(
                    r#"{{"op":"commit_meta","gid":"{GID}","admins":{admins}}}"#
                ))
                .is_err(),
            "{admins}"
        );
        assert!(alice.store.accept().is_err());
    }
    // An empty list and a normal list are still allowed.
    for admins in ["[]", r#"["alice","bob"]"#] {
        alice.change(&format!(
            r#"{{"op":"commit_meta","gid":"{GID}","admins":{admins}}}"#
        ));
        alice.change(&format!(r#"{{"op":"discard_pending","gid":"{GID}"}}"#));
    }
}

#[test]
fn only_one_commit_wins_an_epoch() {
    let (mut alice, mut bob1, mut bob2) = book_club();
    let a = alice.change(&format!(r#"{{"op":"commit_update","gid":"{GID}"}}"#));
    let b = bob1.change(&format!(r#"{{"op":"commit_update","gid":"{GID}"}}"#));
    // The server took Alice's. Bob's device discards its own and applies hers.
    alice.change(&format!(r#"{{"op":"merge_pending","gid":"{GID}"}}"#));
    bob1.change(&format!(r#"{{"op":"discard_pending","gid":"{GID}"}}"#));
    bob1.receive(&s(&a, "commit"));
    bob2.receive(&s(&a, "commit"));
    // Bob's losing Commit is for an old epoch and is refused everywhere.
    assert!(
        bob2.raw(&format!(
            r#"{{"op":"process","gid":"{GID}","message":"{}"}}"#,
            s(&b, "commit")
        ))
        .is_err()
    );
    let ct = bob1.send("still in step");
    assert_eq!(text(&alice.receive(&ct)), "still in step");
}

fn device_request(id: &AccountIdentity, uid: &str, device: &str) -> String {
    format!(
        r#"{{"op":"device","identity":{},"uid":"{uid}","device":"{device}","deviceCertHash":"{}","generation":2}}"#,
        to_json(&Json::Str(id.to_json())),
        b64_encode(&[7u8; 32]),
    )
}

#[test]
fn the_device_is_not_replaced_while_it_is_in_a_group() {
    let (mut alice, mut bob1, _) = book_club();
    let b = identity();
    let before = bob1.store.records();
    assert!(bob1.raw(&device_request(&b, "bob", "bob-phone")).is_err());
    assert_eq!(bob1.store.records(), before);
    assert!(bob1.store.accept().is_err());
    // So what it sends is still signed with the key its leaf has.
    let ct = bob1.send("still me");
    assert_eq!(text(&alice.receive(&ct)), "still me");

    // Before any group, and after the last one is forgotten, it may be replaced.
    let mut fresh = phone(&b, "bob", "bob-watch");
    fresh.change(&device_request(&b, "bob", "bob-watch"));
    bob1.change(&format!(r#"{{"op":"forget","gid":"{GID}"}}"#));
    bob1.change(&device_request(&b, "bob", "bob-phone"));
}

#[test]
fn a_store_reloaded_from_saved_records_carries_on() {
    let (mut alice, bob1, _) = book_club();
    let mut reloaded = Phone {
        store: GroupStore::open(bob1.store.records()),
        uid: bob1.uid.clone(),
        device: bob1.device.clone(),
    };
    let ct = alice.send("after a restart");
    assert_eq!(text(&reloaded.receive(&ct)), "after a restart");
    let groups = reloaded.raw(r#"{"op":"groups"}"#).unwrap();
    assert_eq!(
        field(&groups, "groups").as_array().unwrap(),
        &[Json::Str(GID.into())]
    );
}

#[test]
fn members_are_reported_with_certificate_hash_and_generation() {
    let (mut alice, mut bob1, _) = book_club();
    let hash = b64_encode(&[7u8; 32]);
    let info = bob1.info();
    let members = field(&info, "members").as_array().unwrap();
    assert_eq!(members.len(), 3);
    for m in members {
        assert_eq!(s(m, "certHash"), hash);
        assert_eq!(field(m, "generation").as_i64().unwrap(), 1);
    }
    // The sender of a message and the committer of a Commit carry them too.
    let got = bob1.receive(&alice.send("hello"));
    assert_eq!(s(field(&got, "sender"), "certHash"), hash);
    let update = alice.change(&format!(r#"{{"op":"commit_update","gid":"{GID}"}}"#));
    alice.change(&format!(r#"{{"op":"merge_pending","gid":"{GID}"}}"#));
    let got = bob1.receive(&s(&update, "commit"));
    assert_eq!(
        field(field(&got, "committer"), "generation")
            .as_i64()
            .unwrap(),
        1
    );
}

#[test]
fn a_credential_with_a_malformed_hash_or_generation_is_refused() {
    let a = identity();
    let mut alice = phone(&a, "alice", "alice-phone");
    alice.change(&format!(
        r#"{{"op":"create","gid":"{GID}","name":"Book club"}}"#
    ));
    // A negative generation cannot be issued.
    let b = identity();
    let mut store = GroupStore::open(HashMap::new());
    assert!(
        store
            .call(&format!(
                r#"{{"op":"device","identity":{},"uid":"bob","device":"bob-phone","deviceCertHash":"{}","generation":-1}}"#,
                to_json(&Json::Str(b.to_json())),
                b64_encode(&[7u8; 32]),
            ))
            .is_err()
    );
    // Credentials signed by the account itself, with a short hash and with a
    // generation too large to report: both are refused when added.
    for (hash_len, generation) in [(31usize, 1u64), (32, u64::MAX)] {
        let mut bob = phone(&b, "bob", "bob-phone");
        let key = bob.store.provider.get(REC_SIGNATURE_KEY).unwrap();
        let mut rng = Rng::os();
        let mut forged = FireplaceCredential::issue(
            &b,
            "bob",
            "bob-phone",
            &[7u8; 32],
            &key,
            generation,
            &mut rng,
        )
        .unwrap();
        if hash_len != 32 {
            // `issue` refuses a short hash, so sign one by hand.
            forged = FireplaceCredential::issue_unchecked(
                &b,
                "bob",
                "bob-phone",
                &vec![7u8; hash_len],
                &key,
                generation,
                &mut rng,
            )
            .unwrap();
        }
        bob.store
            .provider
            .put(REC_CREDENTIAL, forged.encode().unwrap());
        let kp = bob.packages(1).remove(0);
        assert!(
            alice
                .raw(&format!(
                    r#"{{"op":"commit_add","gid":"{GID}","keyPackages":["{kp}"]}}"#
                ))
                .is_err(),
            "hash {hash_len} generation {generation}"
        );
        assert!(alice.store.accept().is_err());
    }
}

#[test]
fn applying_the_changes_reproduces_the_store() {
    let (mut alice, mut bob1, _) = book_club();
    let mut copy = bob1.store.records();
    let ct = alice.send("delta");
    let out = bob1
        .raw(&format!(
            r#"{{"op":"process","gid":"{GID}","message":"{ct}"}}"#
        ))
        .unwrap();
    for c in field(&out, "changes").as_array().unwrap() {
        let k = b64_decode(&s(c, "k")).unwrap();
        match field(c, "v") {
            Json::Null => {
                copy.remove(&k);
            }
            v => {
                copy.insert(k, b64_decode(v.as_str().unwrap()).unwrap());
            }
        }
    }
    bob1.store.accept().unwrap();
    assert_eq!(copy, bob1.store.records());
}

#[test]
fn joining_reports_the_inviter_and_can_be_held_to_one_group() {
    let (a, b, c) = (identity(), identity(), identity());
    let mut alice = phone(&a, "alice", "alice-phone");
    alice.change(&format!(
        r#"{{"op":"create","gid":"{GID}","name":"Book club"}}"#
    ));
    let mut bob = phone(&b, "bob", "bob-phone");
    let (commit, welcome) = alice.add(&bob.packages(1));
    let _ = commit;

    // A Welcome for a group other than the one named is refused, and the key
    // package it was for is still there afterwards.
    let other = b64url_encode(&[9u8; 16]);
    let before = bob.store.records();
    assert!(
        bob.raw(&format!(
            r#"{{"op":"join","welcome":"{welcome}","gid":"{other}"}}"#
        ))
        .is_err()
    );
    assert_eq!(bob.store.records(), before);
    assert!(bob.store.accept().is_err());

    let joined = bob.change(&format!(
        r#"{{"op":"join","welcome":"{welcome}","gid":"{GID}"}}"#
    ));
    assert_eq!(s(&joined, "gid"), GID);
    let inviter = field(&joined, "inviter");
    assert_eq!(s(inviter, "uid"), "alice");
    assert_eq!(s(inviter, "device"), "alice-phone");
    assert_eq!(
        s(inviter, "identity"),
        b64_encode(&a.public_bytes().unwrap())
    );

    // The inviter is whoever made the Welcome, not the group's first member:
    // Bob invites Carol.
    let mut carol = phone(&c, "carol", "carol-phone");
    let list = format!("\"{}\"", carol.packages(1)[0]);
    let out = bob.change(&format!(
        r#"{{"op":"commit_add","gid":"{GID}","keyPackages":[{list}]}}"#
    ));
    bob.change(&format!(r#"{{"op":"merge_pending","gid":"{GID}"}}"#));
    let joined = carol.join(&s(&out, "welcome"));
    assert_eq!(s(field(&joined, "inviter"), "uid"), "bob");
}

#[test]
fn bad_requests_are_refused() {
    let (mut alice, _, _) = book_club();
    for bad in [
        r#"{"op":"nope"}"#.to_string(),
        r#"{"op":"create","gid":"short","name":"x"}"#.into(),
        format!(
            r#"{{"op":"create","gid":"{}","name":""}}"#,
            b64url_encode(&[9; 16])
        ),
        format!(
            r#"{{"op":"create","gid":"{}","name":"{}"}}"#,
            b64url_encode(&[9; 16]),
            "x".repeat(41)
        ),
        r#"{"op":"key_packages","count":11}"#.to_string(),
        format!(r#"{{"op":"process","gid":"{GID}","message":"AAAA"}}"#),
    ] {
        assert!(alice.raw(&bad).is_err(), "{bad}");
        assert!(alice.store.accept().is_err());
    }
}
