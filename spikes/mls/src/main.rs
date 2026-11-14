//! MLS measurement spike (mobile decision 0050). Not shipped and not linked into
//! the Fireplace library. It answers: with OpenMLS 0.9.2 and the RustCrypto
//! provider 0.6.0, how big and how slow are the operations Fireplace's group
//! chats would perform, for the chosen suite and for a classical baseline?
//!
//! The group grows the way the product would: one account (four devices) per
//! Commit, Welcomes carrying the ratchet tree (they are stored as Firestore
//! documents), and handshake messages encrypted.
//!
//! Run: cargo run --release

use std::time::{Duration, Instant};

use openmls::prelude::{tls_codec::Serialize as _, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

const DEVICES_PER_ACCOUNT: usize = 4;

struct Device {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    group: Option<MlsGroup>,
}

impl Device {
    fn new(cs: Ciphersuite, uid: usize, dev: usize) -> (Self, KeyPackage, usize) {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(cs.signature_algorithm()).unwrap();
        signer.store(provider.storage()).unwrap();
        // The real credential binds uid, device id and an account-signed
        // endorsement; a fixed-size stand-in keeps the sizes honest.
        let mut identity = format!("uid-{uid:028}:dev-{dev:032}").into_bytes();
        identity.resize(64 + 64 + 3309 + 32, 0); // Ed25519 + ML-DSA-65 endorsement + hash
        let cwk = CredentialWithKey {
            credential: BasicCredential::new(identity).into(),
            signature_key: signer.to_public_vec().into(),
        };
        let kp = KeyPackage::builder().build(cs, &provider, &signer, cwk).unwrap();
        let kp_size = kp.key_package().tls_serialized_len();
        (Self { provider, signer, group: None }, kp.key_package().clone(), kp_size)
    }

    fn storage_bytes(&self) -> usize {
        let values = self.provider.storage().values.read().unwrap();
        values.iter().map(|(k, v)| k.len() + v.len()).sum()
    }
}

fn wire(msg: &MlsMessageOut) -> Vec<u8> {
    msg.tls_serialize_detached().unwrap()
}

fn incoming(bytes: &[u8]) -> ProtocolMessage {
    use openmls::prelude::tls_codec::Deserialize as _;
    MlsMessageIn::tls_deserialize_exact(bytes)
        .unwrap()
        .try_into_protocol_message()
        .unwrap()
}

/// Applies a Commit on one member and returns how long that took.
fn apply_commit(d: &mut Device, bytes: &[u8]) -> Duration {
    let t = Instant::now();
    let group = d.group.as_mut().unwrap();
    let processed = group.process_message(&d.provider, incoming(bytes)).unwrap();
    match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            group.merge_staged_commit(&d.provider, *staged).unwrap()
        }
        _ => panic!("expected a commit"),
    }
    t.elapsed()
}

fn ms(d: Duration) -> String {
    format!("{:.1} ms", d.as_secs_f64() * 1000.0)
}
fn kib(n: usize) -> String {
    format!("{:.1} KiB", n as f64 / 1024.0)
}

#[derive(Default)]
struct Row {
    leaves: usize,
    key_package: usize,
    add_commit: usize,
    welcome: usize,
    add_create: Duration,
    add_process: Duration,
    join: Duration,
    update_commit: usize,
    update_create: Duration,
    update_process: Duration,
    remove_commit: usize,
    remove_process: Duration,
    msg_short: usize,
    msg_long: usize,
    encrypt_long: Duration,
    decrypt_long: Duration,
    state: usize,
}

fn run(cs: Ciphersuite, accounts: usize) -> Row {
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(cs)
        .use_ratchet_tree_extension(true)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .build();
    let mut row = Row { leaves: accounts * DEVICES_PER_ACCOUNT, ..Default::default() };

    // Account 0, device 0 creates the group and adds its own other devices.
    let mut devices: Vec<Device> = Vec::new();
    for account in 0..accounts {
        let mut joining = Vec::new();
        let mut packages = Vec::new();
        for dev in 0..DEVICES_PER_ACCOUNT {
            let (d, kp, kp_size) = Device::new(cs, account, dev);
            row.key_package = kp_size;
            joining.push(d);
            packages.push(kp);
        }
        if account == 0 {
            let mut creator = joining.remove(0);
            packages.remove(0);
            let cwk = CredentialWithKey {
                credential: BasicCredential::new(vec![0; 64]).into(),
                signature_key: creator.signer.to_public_vec().into(),
            };
            creator.group =
                Some(MlsGroup::new(&creator.provider, &creator.signer, &config, cwk).unwrap());
            devices.push(creator);
        }
        // The committer is always the first device (an administrator).
        let t = Instant::now();
        let (commit, welcome, _) = {
            let c = &mut devices[0];
            let g = c.group.as_mut().unwrap();
            let out = g.add_members(&c.provider, &c.signer, &packages).unwrap();
            g.merge_pending_commit(&c.provider).unwrap();
            out
        };
        let add_create = t.elapsed();
        let (commit, welcome) = (wire(&commit), wire(&welcome));
        let mut add_process = Duration::ZERO;
        for d in devices.iter_mut().skip(1) {
            add_process = apply_commit(d, &commit);
        }
        let mut join = Duration::ZERO;
        for mut d in joining {
            use openmls::prelude::tls_codec::Deserialize as _;
            let t = Instant::now();
            let w = MlsMessageIn::tls_deserialize_exact(&welcome[..]).unwrap();
            let w = match w.extract() {
                MlsMessageBodyIn::Welcome(w) => w,
                _ => panic!("expected a welcome"),
            };
            d.group = Some(
                StagedWelcome::new_from_welcome(&d.provider, config.join_config(), w, None)
                    .unwrap()
                    .into_group(&d.provider)
                    .unwrap(),
            );
            join = t.elapsed();
            devices.push(d);
        }
        // Record the last (largest) add: the group was already nearly full.
        row.add_commit = commit.len();
        row.welcome = welcome.len();
        row.add_create = add_create;
        row.add_process = add_process;
        row.join = join;
    }

    // A device refreshes its own leaf (post-compromise security).
    let last = devices.len() - 1;
    let t = Instant::now();
    let update = {
        let d = &mut devices[last];
        let g = d.group.as_mut().unwrap();
        let b = g.self_update(&d.provider, &d.signer, LeafNodeParameters::default()).unwrap();
        g.merge_pending_commit(&d.provider).unwrap();
        wire(b.commit())
    };
    row.update_create = t.elapsed();
    row.update_commit = update.len();
    for d in devices.iter_mut().take(last) {
        row.update_process = apply_commit(d, &update);
    }

    // Messages: a short text and the longest allowed (16,384 four-byte characters).
    let short = "a".repeat(100);
    let long = "😀".repeat(16_384);
    let enc = |devices: &mut Vec<Device>, text: &str| {
        let d = &mut devices[0];
        let g = d.group.as_mut().unwrap();
        wire(&g.create_message(&d.provider, &d.signer, text.as_bytes()).unwrap())
    };
    row.msg_short = enc(&mut devices, &short).len();
    let again = enc(&mut devices, &short);
    let _ = incoming_message(&mut devices[1], &again); // keep in step
    let t = Instant::now();
    let long_bytes = enc(&mut devices, &long);
    row.encrypt_long = t.elapsed();
    row.msg_long = long_bytes.len();
    let t = Instant::now();
    let plain = incoming_message(&mut devices[1], &long_bytes);
    row.decrypt_long = t.elapsed();
    assert_eq!(plain, long.as_bytes());

    // Remove one whole account (all its leaves), as the product requires.
    if accounts > 1 {
        let targets: Vec<LeafNodeIndex> = (0..DEVICES_PER_ACCOUNT)
            .map(|i| LeafNodeIndex::new(((accounts - 1) * DEVICES_PER_ACCOUNT + i) as u32))
            .collect();
        let remove = {
            let d = &mut devices[0];
            let g = d.group.as_mut().unwrap();
            let (c, _, _) = g.remove_members(&d.provider, &d.signer, &targets).unwrap();
            g.merge_pending_commit(&d.provider).unwrap();
            wire(&c)
        };
        row.remove_commit = remove.len();
        row.remove_process = apply_commit(&mut devices[1], &remove);
    }

    row.state = devices[1].storage_bytes();
    row
}

fn incoming_message(d: &mut Device, bytes: &[u8]) -> Vec<u8> {
    let g = d.group.as_mut().unwrap();
    match g.process_message(&d.provider, incoming(bytes)).unwrap().into_content() {
        ProcessedMessageContent::ApplicationMessage(m) => m.into_bytes(),
        _ => panic!("expected an application message"),
    }
}

fn main() {
    let suites = [
        ("0x0011 hybrid KEM + Ed25519 (chosen)", Ciphersuite::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519),
        ("0x0001 classical baseline", Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519),
    ];
    for (name, cs) in suites {
        println!("\n## {name}  (openmls 0.9.2 wire id {:#06x})\n", u16::from(cs));
        println!("| leaves | key package | add commit | welcome | add: create / member applies / join | self-update commit | update: create / apply | remove-account commit | remove apply | msg 100 ch | msg 16,384 emoji | long: encrypt / decrypt | member state |");
        println!("|---|---|---|---|---|---|---|---|---|---|---|---|---|");
        for accounts in [1, 4, 16] {
            let r = run(cs, accounts);
            println!(
                "| {} | {} | {} | {} | {} / {} / {} | {} | {} / {} | {} | {} | {} B | {} | {} / {} | {} |",
                r.leaves, kib(r.key_package), kib(r.add_commit), kib(r.welcome),
                ms(r.add_create), ms(r.add_process), ms(r.join),
                kib(r.update_commit), ms(r.update_create), ms(r.update_process),
                kib(r.remove_commit), ms(r.remove_process),
                r.msg_short, kib(r.msg_long), ms(r.encrypt_long), ms(r.decrypt_long), kib(r.state),
            );
        }
    }
}
