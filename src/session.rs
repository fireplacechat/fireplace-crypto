//! Handshake v2 and the hybrid double ratchet.
//!
//! The Dart file `session.dart` is the reference. Labels, the order of the
//! transcript, and the point at which a failed decrypt is thrown away are
//! copied from there. State changes only after the message authenticates.
//!
//! Domain-separation strings keep their original version numbers on purpose.
//! Changing a label changes every derived key.

use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroize;

use crate::aead;
use crate::codec::{self, Json, b64_encode, b64url_encode, bytes_equal, concat, lp, u64_bytes};
use crate::device::{DeviceBundle, DeviceKeys};
use crate::error::{Error, Result};
use crate::kdf::{hkdf_sha256, hmac_sha256, sha256};
use crate::prekeys::{self, PreKeyBundle, PreKeyKind, PreKeyRecord};
use crate::prim::{self, MLKEM_CT, MLKEM_DK, MLKEM_EK};
use crate::rng::Rng;

pub const PROTOCOL_VERSION: i64 = 4;
pub const MAX_SKIP: i64 = 1000;
const MAX_RETIRED: usize = 64;
const MAX_FAILED: usize = 8;
const FAILURE_WINDOW_MS: i64 = 60_000;
const MAX_CIPHERTEXT: usize = 128 * 1024;
const COUNTER_MAX: i64 = 0x7fff_ffff;
const CREATED_MAX: i64 = 8_640_000_000_000_000;

const LABEL_HANDSHAKE: &[u8] = b"fireplace/v2/handshake";
const LABEL_ROOT: &[u8] = b"fireplace/v3/root";
const LABEL_RATCHET: &[u8] = b"fireplace/v3/ratchet";
const LABEL_MSG: &[u8] = b"fireplace/v3/msg";
const LABEL_SID: &[u8] = b"fireplace/v4/sid";
const LABEL_AAD: &[u8] = b"fireplace/v4/aad";

pub fn system_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[derive(Clone, Debug)]
pub struct HandshakeInit {
    pub ek: Vec<u8>,
    pub kem_ct: Vec<u8>,
    pub spk_id: String,
    pub opk_id: Option<String>,
    pub opk_kem_ct: Option<Vec<u8>>,
}

impl HandshakeInit {
    pub fn to_json(&self) -> String {
        codec::to_json(&self.to_value())
    }

    fn to_value(&self) -> Json {
        let mut pairs = vec![
            ("ek".to_string(), Json::Str(b64_encode(&self.ek))),
            ("kemCt".to_string(), Json::Str(b64_encode(&self.kem_ct))),
            ("spk".to_string(), Json::Str(self.spk_id.clone())),
        ];
        if let Some(opk) = &self.opk_id {
            pairs.push(("opk".to_string(), Json::Str(opk.clone())));
        }
        if let Some(ct) = &self.opk_kem_ct {
            pairs.push(("opkCt".to_string(), Json::Str(b64_encode(ct))));
        }
        Json::object(pairs)
    }

    pub fn from_json(text: &str) -> Result<Self> {
        Self::from_fields(codec::parse_json(text)?.as_object()?)
    }

    fn from_fields(obj: &[(String, Json)]) -> Result<Self> {
        let spk = codec::obj_str(obj, "spk").map_err(|_| Error::Invalid("bad spk id"))?;
        if spk.is_empty() || spk.len() > 32 {
            return Err(Error::Invalid("bad spk id"));
        }
        let opk = match codec::obj_opt(obj, "opk") {
            None => None,
            Some(value) => {
                let text = value.as_str().map_err(|_| Error::Invalid("bad opk id"))?;
                if text.is_empty() || text.len() > 32 {
                    return Err(Error::Invalid("bad opk id"));
                }
                Some(text.to_string())
            }
        };
        let opk_ct = codec::obj_opt(obj, "opkCt");
        if opk.is_none() != opk_ct.is_none() {
            return Err(Error::Invalid("inconsistent one-time prekey fields"));
        }
        Ok(Self {
            ek: codec::b64_field(codec::obj_get(obj, "ek")?, Some(32), 32, "ek")?,
            kem_ct: codec::b64_field(
                codec::obj_get(obj, "kemCt")?,
                Some(MLKEM_CT),
                MLKEM_CT,
                "kemCt",
            )?,
            spk_id: spk.to_string(),
            opk_id: opk,
            opk_kem_ct: match opk_ct {
                None => None,
                Some(value) => Some(codec::b64_field(value, Some(MLKEM_CT), MLKEM_CT, "opkCt")?),
            },
        })
    }
}

#[derive(Clone, Debug)]
pub struct Envelope {
    pub n: i64,
    pub pn: i64,
    pub sid: String,
    pub rx: Vec<u8>,
    pub rk: Vec<u8>,
    pub rc: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ct: Vec<u8>,
    pub mac: Vec<u8>,
    pub handshake: Option<HandshakeInit>,
}

impl Envelope {
    pub fn to_json(&self) -> String {
        codec::to_json(&self.to_value())
    }

    fn to_value(&self) -> Json {
        let mut pairs = vec![
            ("pv".to_string(), Json::Int(PROTOCOL_VERSION)),
            ("n".to_string(), Json::Int(self.n)),
            ("pn".to_string(), Json::Int(self.pn)),
            ("sid".to_string(), Json::Str(self.sid.clone())),
            ("rx".to_string(), Json::Str(b64_encode(&self.rx))),
            ("rk".to_string(), Json::Str(b64_encode(&self.rk))),
            ("rc".to_string(), Json::Str(b64_encode(&self.rc))),
            ("nonce".to_string(), Json::Str(b64_encode(&self.nonce))),
            ("ct".to_string(), Json::Str(b64_encode(&self.ct))),
            ("mac".to_string(), Json::Str(b64_encode(&self.mac))),
        ];
        if let Some(handshake) = &self.handshake {
            pairs.push(("hs".to_string(), handshake.to_value()));
        }
        Json::object(pairs)
    }

    pub fn from_json(text: &str) -> Result<Self> {
        Self::from_fields(codec::parse_json(text)?.as_object()?)
    }

    fn from_fields(obj: &[(String, Json)]) -> Result<Self> {
        let pv = codec::obj_i64(obj, "pv")
            .map_err(|_| Error::Invalid("unsupported protocol version"))?;
        if pv != PROTOCOL_VERSION {
            return Err(Error::Invalid("unsupported protocol version"));
        }
        let n = counter(obj, "n", "bad counter")?;
        let pn = counter(obj, "pn", "bad previous-chain length")?;
        let sid = codec::obj_str(obj, "sid").map_err(|_| Error::Invalid("bad session id"))?;
        if sid.is_empty() || sid.len() > 32 {
            return Err(Error::Invalid("bad session id"));
        }
        let handshake = match codec::obj_opt(obj, "hs") {
            None => None,
            Some(Json::Obj(pairs)) => Some(HandshakeInit::from_fields(pairs)?),
            Some(_) => return Err(Error::Invalid("bad handshake")),
        };
        Ok(Self {
            n,
            pn,
            sid: sid.to_string(),
            rx: codec::b64_field(codec::obj_get(obj, "rx")?, Some(32), 32, "rx")?,
            rk: codec::b64_field(codec::obj_get(obj, "rk")?, Some(MLKEM_EK), MLKEM_EK, "rk")?,
            rc: codec::b64_field(codec::obj_get(obj, "rc")?, Some(MLKEM_CT), MLKEM_CT, "rc")?,
            nonce: codec::b64_field(codec::obj_get(obj, "nonce")?, Some(12), 12, "nonce")?,
            ct: codec::b64_field(codec::obj_get(obj, "ct")?, None, MAX_CIPHERTEXT, "ct")?,
            mac: codec::b64_field(codec::obj_get(obj, "mac")?, Some(16), 16, "mac")?,
            handshake,
        })
    }
}

#[derive(Clone)]
struct State {
    rk: Vec<u8>,
    cks: Option<Vec<u8>>,
    ckr: Option<Vec<u8>>,
    ns: i64,
    nr: i64,
    pn: i64,
    dhs_seed: Vec<u8>,
    dhs_pub: Vec<u8>,
    kem_secret: Vec<u8>,
    kem_pub: Vec<u8>,
    dhr_pub: Option<Vec<u8>>,
    pending_ct: Option<Vec<u8>>,
    skipped: Vec<(String, Vec<u8>)>,
    retired: Vec<String>,
}

impl Drop for State {
    fn drop(&mut self) {
        self.rk.zeroize();
        if let Some(v) = &mut self.cks {
            v.zeroize();
        }
        if let Some(v) = &mut self.ckr {
            v.zeroize();
        }
        self.dhs_seed.zeroize();
        self.kem_secret.zeroize();
        if let Some(v) = &mut self.pending_ct {
            v.zeroize();
        }
        for (_, key) in &mut self.skipped {
            key.zeroize();
        }
    }
}

impl State {
    fn fresh(rk: Vec<u8>) -> Self {
        Self {
            rk,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            dhs_seed: Vec::new(),
            dhs_pub: Vec::new(),
            kem_secret: Vec::new(),
            kem_pub: Vec::new(),
            dhr_pub: None,
            pending_ct: None,
            skipped: Vec::new(),
            retired: Vec::new(),
        }
    }

    fn retire(&mut self, key: &[u8]) {
        if key.len() != 32 {
            return;
        }
        let id = b64_encode(key);
        if self.retired.iter().any(|item| item == &id) {
            return;
        }
        self.retired.push(id);
        while self.retired.len() > MAX_RETIRED {
            self.retired.remove(0);
        }
    }

    fn cannot_start_chain(&self, key: &[u8]) -> bool {
        bytes_equal(key, &self.dhs_pub) || self.retired.iter().any(|item| item == &b64_encode(key))
    }

    fn to_value(&self) -> Json {
        let mut pairs = vec![("rk".to_string(), Json::Str(b64_encode(&self.rk)))];
        if let Some(cks) = &self.cks {
            pairs.push(("cks".to_string(), Json::Str(b64_encode(cks))));
        }
        if let Some(ckr) = &self.ckr {
            pairs.push(("ckr".to_string(), Json::Str(b64_encode(ckr))));
        }
        pairs.extend([
            ("ns".to_string(), Json::Int(self.ns)),
            ("nr".to_string(), Json::Int(self.nr)),
            ("pn".to_string(), Json::Int(self.pn)),
            ("dhsSeed".to_string(), Json::Str(b64_encode(&self.dhs_seed))),
            ("dhsPub".to_string(), Json::Str(b64_encode(&self.dhs_pub))),
            (
                "kemSecret".to_string(),
                Json::Str(b64_encode(&self.kem_secret)),
            ),
            ("kemPub".to_string(), Json::Str(b64_encode(&self.kem_pub))),
        ]);
        if let Some(dhr) = &self.dhr_pub {
            pairs.push(("dhrPub".to_string(), Json::Str(b64_encode(dhr))));
        }
        if let Some(ct) = &self.pending_ct {
            pairs.push(("pendingCt".to_string(), Json::Str(b64_encode(ct))));
        }
        let skipped = self
            .skipped
            .iter()
            .map(|(k, v)| (k.clone(), Json::Str(b64_encode(v))))
            .collect();
        pairs.push(("skipped".to_string(), Json::Obj(skipped)));
        if !self.retired.is_empty() {
            pairs.push((
                "retired".to_string(),
                Json::Arr(self.retired.iter().cloned().map(Json::Str).collect()),
            ));
        }
        Json::Obj(pairs)
    }

    fn from_fields(obj: &[(String, Json)]) -> Result<Self> {
        let mut state = Self {
            rk: exact(obj, "rk", 32)?,
            cks: optional(obj, "cks", 32)?,
            ckr: optional(obj, "ckr", 32)?,
            ns: counter(obj, "ns", "bad ns")?,
            nr: counter(obj, "nr", "bad nr")?,
            pn: counter(obj, "pn", "bad pn")?,
            dhs_seed: exact(obj, "dhsSeed", 32)?,
            dhs_pub: exact(obj, "dhsPub", 32)?,
            kem_secret: exact(obj, "kemSecret", MLKEM_DK)?,
            kem_pub: exact(obj, "kemPub", MLKEM_EK)?,
            dhr_pub: optional(obj, "dhrPub", 32)?,
            pending_ct: optional(obj, "pendingCt", MLKEM_CT)?,
            skipped: Vec::new(),
            retired: Vec::new(),
        };
        if state.cks.is_none() != state.pending_ct.is_none() {
            return Err(Error::Invalid("inconsistent sending state"));
        }
        if state.ckr.is_some() && state.dhr_pub.is_none() {
            return Err(Error::Invalid("receiving chain without a remote key"));
        }
        let skipped =
            codec::obj_get(obj, "skipped").map_err(|_| Error::Invalid("bad skipped keys"))?;
        let Json::Obj(pairs) = skipped else {
            return Err(Error::Invalid("bad skipped keys"));
        };
        if pairs.len() > MAX_SKIP as usize {
            return Err(Error::Invalid("bad skipped keys"));
        }
        for (key, value) in pairs {
            if !skipped_key_ok(key) {
                return Err(Error::Invalid("bad skipped key id"));
            }
            state.skipped.push((
                key.clone(),
                codec::b64_field(value, Some(32), 32, "skipped key")?,
            ));
        }
        if let Some(retired) = codec::obj_opt(obj, "retired") {
            let Json::Arr(items) = retired else {
                return Err(Error::Invalid("bad retired keys"));
            };
            if items.len() > MAX_RETIRED {
                return Err(Error::Invalid("bad retired keys"));
            }
            for item in items {
                let text = item.as_str().map_err(|_| Error::Invalid("retired key"))?;
                let _ = codec::b64_field(item, Some(32), 32, "retired key")?;
                state.retired.push(text.to_string());
            }
        }
        Ok(state)
    }
}

fn skipped_key_ok(key: &str) -> bool {
    let Some((head, tail)) = key.split_once(':') else {
        return false;
    };
    let head = head.as_bytes();
    head.len() == 44
        && head[..43]
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'+' || *c == b'/')
        && head[43] == b'='
        && !tail.is_empty()
        && tail.len() <= 10
        && tail.bytes().all(|c| c.is_ascii_digit())
}

pub struct Session {
    pub local_uid: String,
    pub local_device: String,
    pub remote_uid: String,
    pub remote_device: String,
    pub is_initiator: bool,
    pub session_id: String,
    pub created_at: i64,
    state: State,
    handshake: Option<HandshakeInit>,
    failures: Vec<i64>,
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Session({})", self.session_id)
    }
}

impl Session {
    pub fn acknowledged(&self) -> bool {
        self.handshake.is_none()
    }

    pub fn can_send(&self) -> bool {
        self.state.cks.is_some()
    }

    pub fn send_counter(&self) -> i64 {
        self.state.ns
    }

    pub fn self_check(&self) -> bool {
        prim::x25519_matches(&self.state.dhs_seed, &self.state.dhs_pub)
            && prim::mlkem_matches(&self.state.kem_secret, &self.state.kem_pub)
    }

    pub fn initiate(
        local: &DeviceKeys,
        local_bundle: &DeviceBundle,
        remote: &PreKeyBundle,
        rng: &mut Rng,
        now_ms: i64,
    ) -> Result<(Self, HandshakeInit)> {
        check_created(now_ms)?;
        check_local(local, local_bundle)?;
        let dev = &remote.device;
        if !dev.verify_cert() {
            return Err(Error::Crypto("remote device certificate invalid"));
        }
        if !prekeys::verify_signed(dev, &remote.signed) {
            return Err(Error::Crypto("remote signed prekey invalid"));
        }
        let spk = &remote.signed;
        let opk = remote.one_time.as_ref();
        if opk.is_some_and(|opk| opk.kind != PreKeyKind::OneTime) {
            return Err(Error::Crypto("one-time prekey has the wrong kind"));
        }

        let mut ek_seed = rng.array::<32>()?;
        let ek_pub = prim::x25519_public(&ek_seed)?.to_vec();
        let dh1 = prim::x25519_dh(&local.x25519_seed, &spk.x25519_pub)?;
        let dh2 = prim::x25519_dh(&ek_seed, &dev.x25519_pub)?;
        let dh3 = prim::x25519_dh(&ek_seed, &spk.x25519_pub)?;
        let dh4 = match opk {
            Some(opk) => Some(prim::x25519_dh(&ek_seed, &opk.x25519_pub)?),
            None => None,
        };
        ek_seed.zeroize();
        let coins = rng.array::<32>()?;
        let (ct1, ss1) = prim::mlkem_encapsulate(&spk.kem_pub, &coins)?;
        let (ct2, ss2) = match opk {
            Some(opk) => {
                let coins = rng.array::<32>()?;
                let (ct, ss) = prim::mlkem_encapsulate(&opk.kem_pub, &coins)?;
                (Some(ct), Some(ss))
            }
            None => (None, None),
        };
        let handshake = HandshakeInit {
            ek: ek_pub,
            kem_ct: ct1,
            spk_id: spk.id.clone(),
            opk_id: opk.map(|opk| opk.id.clone()),
            opk_kem_ct: ct2,
        };
        let (rk0, sid) = derive_root(
            local_bundle,
            dev,
            (&spk.id, &spk.x25519_pub, &spk.kem_pub),
            opk.map(|opk| {
                (
                    opk.id.as_str(),
                    opk.x25519_pub.as_slice(),
                    opk.kem_pub.as_slice(),
                )
            }),
            &handshake,
            &[
                Some(&dh1),
                Some(&dh2),
                Some(&dh3),
                dh4.as_ref().map(|b| b.as_slice()),
                Some(&ss1),
                ss2.as_ref().map(|b| b.as_slice()),
            ],
        )?;
        let mut state = State::fresh(rk0);
        send_step(&mut state, &spk.x25519_pub, &spk.kem_pub, rng)?;
        let session = Self {
            local_uid: local_bundle.uid.clone(),
            local_device: local_bundle.device_id.clone(),
            remote_uid: dev.uid.clone(),
            remote_device: dev.device_id.clone(),
            is_initiator: true,
            session_id: sid,
            created_at: now_ms,
            state,
            handshake: Some(handshake.clone()),
            failures: Vec::new(),
        };
        Ok((session, handshake))
    }

    pub fn accept(
        local: &DeviceKeys,
        local_bundle: &DeviceBundle,
        remote: &DeviceBundle,
        handshake: &HandshakeInit,
        signed_prekey: &PreKeyRecord,
        one_time: Option<&PreKeyRecord>,
        now_ms: i64,
    ) -> Result<Self> {
        check_created(now_ms)?;
        check_local(local, local_bundle)?;
        if !remote.verify_cert() {
            return Err(Error::Crypto("remote device certificate invalid"));
        }
        if handshake.spk_id != signed_prekey.id {
            return Err(Error::Crypto("signed prekey id mismatch"));
        }
        if one_time.is_none() != handshake.opk_id.is_none()
            || one_time.is_some_and(|opk| handshake.opk_id.as_deref() != Some(opk.id.as_str()))
        {
            return Err(Error::Crypto("one-time prekey mismatch"));
        }
        let dh1 = prim::x25519_dh(&signed_prekey.x25519_seed, &remote.x25519_pub)?;
        let dh2 = prim::x25519_dh(&local.x25519_seed, &handshake.ek)?;
        let dh3 = prim::x25519_dh(&signed_prekey.x25519_seed, &handshake.ek)?;
        let (dh4, ss2) = match one_time {
            Some(opk) => {
                let dh4 = prim::x25519_dh(&opk.x25519_seed, &handshake.ek)?;
                let ct = handshake
                    .opk_kem_ct
                    .as_deref()
                    .ok_or(Error::Crypto("one-time prekey mismatch"))?;
                let ss2 = prim::mlkem_decapsulate(&opk.kem_secret, ct)?;
                (Some(dh4), Some(ss2))
            }
            None => (None, None),
        };
        let ss1 = prim::mlkem_decapsulate(&signed_prekey.kem_secret, &handshake.kem_ct)?;
        let (rk0, sid) = derive_root(
            remote,
            local_bundle,
            (
                &signed_prekey.id,
                &signed_prekey.x25519_pub,
                &signed_prekey.kem_pub,
            ),
            one_time.map(|opk| {
                (
                    opk.id.as_str(),
                    opk.x25519_pub.as_slice(),
                    opk.kem_pub.as_slice(),
                )
            }),
            handshake,
            &[
                Some(&dh1),
                Some(&dh2),
                Some(&dh3),
                dh4.as_ref().map(|b| b.as_slice()),
                Some(&ss1),
                ss2.as_ref().map(|b| b.as_slice()),
            ],
        )?;
        let state = State {
            rk: rk0,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            dhs_seed: signed_prekey.x25519_seed.clone(),
            dhs_pub: signed_prekey.x25519_pub.clone(),
            kem_secret: signed_prekey.kem_secret.clone(),
            kem_pub: signed_prekey.kem_pub.clone(),
            dhr_pub: None,
            pending_ct: None,
            skipped: Vec::new(),
            retired: Vec::new(),
        };
        Ok(Self {
            local_uid: local_bundle.uid.clone(),
            local_device: local_bundle.device_id.clone(),
            remote_uid: remote.uid.clone(),
            remote_device: remote.device_id.clone(),
            is_initiator: false,
            session_id: sid,
            created_at: now_ms,
            state,
            handshake: None,
            failures: Vec::new(),
        })
    }

    /// A 12-byte nonce is the only randomness an encryption draws.
    pub fn encrypt(&mut self, plaintext: &[u8], chat_id: &str, rng: &mut Rng) -> Result<Envelope> {
        let state = &mut self.state;
        let cks = state
            .cks
            .as_deref()
            .ok_or(Error::Crypto("this session cannot send yet"))?;
        let n = state.ns;
        let mk = hmac_sha256(cks, &[1]);
        let next = hmac_sha256(cks, &[2]);
        let rx = state.dhs_pub.clone();
        let rk = state.kem_pub.clone();
        let rc = state
            .pending_ct
            .clone()
            .ok_or(Error::Crypto("this session cannot send yet"))?;
        let aad = message_aad(
            &self.session_id,
            chat_id,
            &self.local_uid,
            &self.local_device,
            &self.remote_uid,
            &self.remote_device,
            n,
            state.pn,
            &rx,
            &rk,
            &rc,
        )?;
        let nonce = rng.array::<12>()?;
        let (ct, mac) = aead::seal(&message_key(&mk)?, &nonce, &aad, plaintext)?;
        state.cks = Some(next.to_vec());
        state.ns = n + 1;
        Ok(Envelope {
            n,
            pn: state.pn,
            sid: self.session_id.clone(),
            rx,
            rk,
            rc,
            nonce: nonce.to_vec(),
            ct,
            mac: mac.to_vec(),
            handshake: self.handshake.clone(),
        })
    }

    /// `rng` is consumed only when the message starts a new receiving chain:
    /// the reply ratchet draws a fresh X25519 seed, an ML-KEM seed and
    /// encapsulation coins, in that order. `now_ms` is the clock for the
    /// failed-chain budget.
    pub fn decrypt(
        &mut self,
        env: &Envelope,
        chat_id: &str,
        rng: &mut Rng,
        now_ms: i64,
    ) -> Result<Vec<u8>> {
        if env.sid != self.session_id {
            return Err(Error::Crypto("wrong session"));
        }
        self.failures
            .retain(|t| now_ms.saturating_sub(*t) <= FAILURE_WINDOW_MS);
        let mut new_chain = false;
        match self.decrypt_inner(env, chat_id, rng, &mut new_chain) {
            Err(Error::RateLimited) => Err(Error::RateLimited),
            Err(error) => {
                if new_chain && !matches!(error, Error::Rng) {
                    self.failures.push(now_ms);
                }
                Err(error)
            }
            ok => ok,
        }
    }

    fn decrypt_inner(
        &mut self,
        env: &Envelope,
        chat_id: &str,
        rng: &mut Rng,
        new_chain: &mut bool,
    ) -> Result<Vec<u8>> {
        let mut state = self.state.clone();
        let key = (|| -> Result<[u8; 32]> {
            let skipped_id = format!("{}:{}", b64_encode(&env.rx), env.n);
            if let Some(pos) = state.skipped.iter().position(|(id, _)| id == &skipped_id) {
                let mk = state.skipped.remove(pos).1;
                return message_key(&mk);
            }
            let same = state
                .dhr_pub
                .as_ref()
                .is_some_and(|dhr| bytes_equal(dhr, &env.rx));
            if !same {
                if state.cannot_start_chain(&env.rx) {
                    return Err(Error::Crypto("replayed or reflected chain"));
                }
                if env.n > MAX_SKIP {
                    return Err(Error::Crypto("too many skipped messages"));
                }
                if state.ckr.is_some() && env.pn - state.nr > MAX_SKIP {
                    return Err(Error::Crypto("too many skipped messages"));
                }
                if self.failures.len() >= MAX_FAILED {
                    return Err(Error::RateLimited);
                }
                if state.ckr.is_some() {
                    let chain = state
                        .dhr_pub
                        .clone()
                        .ok_or(Error::Crypto("malformed ratchet header"))?;
                    skip_to(&mut state, &chain, env.pn)?;
                }
                *new_chain = true;
                recv_step(&mut state, &env.rx, &env.rk, &env.rc, rng)?;
            } else if env.n < state.nr {
                return Err(Error::Crypto("replayed or unknown counter"));
            }
            skip_to(&mut state, &env.rx, env.n)?;
            let ckr = state
                .ckr
                .as_deref()
                .ok_or(Error::Crypto("no receiving chain"))?;
            let mk = hmac_sha256(ckr, &[1]);
            let next = hmac_sha256(ckr, &[2]);
            state.ckr = Some(next.to_vec());
            state.nr = env.n + 1;
            message_key(&mk)
        })()
        .map_err(map_chain_error)?;

        let aad = message_aad(
            &self.session_id,
            chat_id,
            &self.remote_uid,
            &self.remote_device,
            &self.local_uid,
            &self.local_device,
            env.n,
            env.pn,
            &env.rx,
            &env.rk,
            &env.rc,
        )?;
        let plain = aead::open(&key, &env.nonce, &aad, &env.ct, &env.mac)
            .map_err(|_| Error::Crypto("authentication failed"))?;
        self.state = state;
        self.handshake = None;
        Ok(plain)
    }

    pub fn to_json(&self) -> String {
        codec::to_json(&self.to_value())
    }

    fn to_value(&self) -> Json {
        let mut pairs = vec![
            ("pv".to_string(), Json::Int(PROTOCOL_VERSION)),
            ("localUid".to_string(), Json::Str(self.local_uid.clone())),
            (
                "localDevice".to_string(),
                Json::Str(self.local_device.clone()),
            ),
            ("remoteUid".to_string(), Json::Str(self.remote_uid.clone())),
            (
                "remoteDevice".to_string(),
                Json::Str(self.remote_device.clone()),
            ),
            ("isInitiator".to_string(), Json::Bool(self.is_initiator)),
            ("sid".to_string(), Json::Str(self.session_id.clone())),
            ("createdAt".to_string(), Json::Int(self.created_at)),
            ("st".to_string(), self.state.to_value()),
        ];
        if let Some(handshake) = &self.handshake {
            pairs.push(("hs".to_string(), handshake.to_value()));
        }
        Json::Obj(pairs)
    }

    pub fn from_json(text: &str) -> Result<Self> {
        Self::from_fields(codec::parse_json(text)?.as_object()?)
    }

    /// `None` for an older protocol version or for state that fails validation.
    pub fn try_from_json(text: &str) -> Option<Self> {
        let value = codec::parse_json(text).ok()?;
        let obj = value.as_object().ok()?;
        if codec::obj_i64(obj, "pv").ok()? != PROTOCOL_VERSION {
            return None;
        }
        Self::from_fields(obj).ok()
    }

    fn from_fields(obj: &[(String, Json)]) -> Result<Self> {
        let created =
            codec::obj_i64(obj, "createdAt").map_err(|_| Error::Invalid("bad createdAt"))?;
        check_created(created)?;
        let is_initiator =
            codec::obj_bool(obj, "isInitiator").map_err(|_| Error::Invalid("bad role"))?;
        let state = match codec::obj_get(obj, "st").map_err(|_| Error::Invalid("bad state"))? {
            Json::Obj(pairs) => State::from_fields(pairs)?,
            _ => return Err(Error::Invalid("bad state")),
        };
        let handshake = match codec::obj_opt(obj, "hs") {
            None => None,
            Some(Json::Obj(pairs)) => Some(HandshakeInit::from_fields(pairs)?),
            Some(_) => return Err(Error::Invalid("bad handshake")),
        };
        if is_initiator && state.cks.is_none() {
            return Err(Error::Invalid("initiator without chain"));
        }
        if handshake.is_some() && !is_initiator {
            return Err(Error::Invalid("responder with handshake"));
        }
        Ok(Self {
            local_uid: required_str(obj, "localUid", 128)?,
            local_device: required_str(obj, "localDevice", 128)?,
            remote_uid: required_str(obj, "remoteUid", 128)?,
            remote_device: required_str(obj, "remoteDevice", 128)?,
            is_initiator,
            session_id: required_str(obj, "sid", 32)?,
            created_at: created,
            state,
            handshake,
            failures: Vec::new(),
        })
    }
}

fn map_chain_error(error: Error) -> Error {
    match error {
        Error::Crypto(_) | Error::RateLimited | Error::Rng => error,
        _ => Error::Crypto("malformed ratchet header"),
    }
}

fn check_local(local: &DeviceKeys, bundle: &DeviceBundle) -> Result<()> {
    let public = prim::x25519_public(&local.x25519_seed)?;
    if !bytes_equal(&public, &bundle.x25519_pub)
        || !bytes_equal(&local.kem_pub, &bundle.kem_pub)
        || bundle.device_id != local.device_id
    {
        return Err(Error::Crypto(
            "local keys do not match the local device bundle",
        ));
    }
    Ok(())
}

fn derive_root(
    initiator: &DeviceBundle,
    responder: &DeviceBundle,
    spk: (&str, &[u8], &[u8]),
    opk: Option<(&str, &[u8], &[u8])>,
    handshake: &HandshakeInit,
    secrets: &[Option<&[u8]>],
) -> Result<(Vec<u8>, String)> {
    let empty = Vec::new();
    let (opk_id, opk_x, opk_k) = match opk {
        Some((id, x, k)) => (id.as_bytes(), x, k),
        None => (&b""[..], empty.as_slice(), empty.as_slice()),
    };
    let opk_ct = handshake.opk_kem_ct.as_deref().unwrap_or(&[]);
    let transcript = lp(&[
        LABEL_HANDSHAKE,
        initiator.uid.as_bytes(),
        initiator.device_id.as_bytes(),
        &initiator.identity_pub,
        &initiator.x25519_pub,
        &initiator.kem_pub,
        responder.uid.as_bytes(),
        responder.device_id.as_bytes(),
        &responder.identity_pub,
        &responder.x25519_pub,
        &responder.kem_pub,
        spk.0.as_bytes(),
        spk.1,
        spk.2,
        opk_id,
        opk_x,
        opk_k,
        &handshake.ek,
        &handshake.kem_ct,
        opk_ct,
    ])?;
    let secret_parts: Vec<Vec<u8>> = secrets.iter().map(|s| s.unwrap_or(&[]).to_vec()).collect();
    let secret_refs: Vec<&[u8]> = secret_parts.iter().map(Vec::as_slice).collect();
    let ikm = lp(&secret_refs)?;
    let info = concat(&[LABEL_ROOT, &transcript]);
    let mut root = [0u8; 32];
    hkdf_sha256(&ikm, b"", &info, &mut root)?;
    let sid_hash = sha256(&lp(&[LABEL_SID, &transcript])?);
    let sid = b64url_encode(&sid_hash[..16]);
    Ok((root.to_vec(), sid))
}

fn kdf_rk(rk: &[u8], dh: &[u8], ss: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    let mut out = [0u8; 64];
    hkdf_sha256(&lp(&[dh, ss])?, rk, LABEL_RATCHET, &mut out)?;
    let mut root = [0u8; 32];
    let mut chain = [0u8; 32];
    root.copy_from_slice(&out[..32]);
    chain.copy_from_slice(&out[32..]);
    out.zeroize();
    Ok((root, chain))
}

fn send_step(state: &mut State, remote_x: &[u8], remote_kem: &[u8], rng: &mut Rng) -> Result<()> {
    let mut seed = rng.array::<32>()?;
    let public = prim::x25519_public(&seed)?.to_vec();
    let kem = prim::mlkem_generate(rng)?;
    let dh = prim::x25519_dh(&seed, remote_x)?;
    let coins = rng.array::<32>()?;
    let (ct, ss) = prim::mlkem_encapsulate(remote_kem, &coins)?;
    let (rk, ck) = kdf_rk(&state.rk, &dh, &ss)?;
    state.pn = state.ns;
    state.ns = 0;
    state.rk = rk.to_vec();
    state.cks = Some(ck.to_vec());
    state.retire(&state.dhs_pub.clone());
    state.dhs_seed = seed.to_vec();
    state.dhs_pub = public;
    state.kem_pub = kem.public;
    state.kem_secret = kem.secret;
    state.pending_ct = Some(ct);
    seed.zeroize();
    Ok(())
}

fn recv_step(
    state: &mut State,
    rx: &[u8],
    peer_kem: &[u8],
    rc: &[u8],
    rng: &mut Rng,
) -> Result<()> {
    let dh = prim::x25519_dh(&state.dhs_seed, rx)?;
    let ss = prim::mlkem_decapsulate(&state.kem_secret, rc)
        .map_err(|_| Error::Crypto("bad ratchet KEM ciphertext"))?;
    let (rk, ck) = kdf_rk(&state.rk, &dh, &ss)?;
    state.rk = rk.to_vec();
    state.ckr = Some(ck.to_vec());
    state.nr = 0;
    if let Some(previous) = state.dhr_pub.clone() {
        state.retire(&previous);
    }
    state.dhr_pub = Some(rx.to_vec());
    send_step(state, rx, peer_kem, rng)
}

fn message_key(mk: &[u8]) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    hkdf_sha256(mk, b"", LABEL_MSG, &mut out)?;
    Ok(out)
}

fn skip_to(state: &mut State, chain_pub: &[u8], until: i64) -> Result<()> {
    if state.ckr.is_none() || until <= state.nr {
        return Ok(());
    }
    if until - state.nr > MAX_SKIP {
        return Err(Error::Crypto("too many skipped messages"));
    }
    while state.nr < until {
        let ckr = state
            .ckr
            .as_deref()
            .ok_or(Error::Crypto("no receiving chain"))?;
        let mk = hmac_sha256(ckr, &[1]);
        let next = hmac_sha256(ckr, &[2]);
        state.skipped.push((
            format!("{}:{}", b64_encode(chain_pub), state.nr),
            mk.to_vec(),
        ));
        state.ckr = Some(next.to_vec());
        state.nr += 1;
    }
    while state.skipped.len() > MAX_SKIP as usize {
        state.skipped.remove(0);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn message_aad(
    sid: &str,
    chat_id: &str,
    sender_uid: &str,
    sender_dev: &str,
    recipient_uid: &str,
    recipient_dev: &str,
    n: i64,
    pn: i64,
    rx: &[u8],
    rk: &[u8],
    rc: &[u8],
) -> Result<Vec<u8>> {
    let header = sha256(&lp(&[rk, rc])?);
    lp(&[
        LABEL_AAD,
        sid.as_bytes(),
        chat_id.as_bytes(),
        sender_uid.as_bytes(),
        sender_dev.as_bytes(),
        recipient_uid.as_bytes(),
        recipient_dev.as_bytes(),
        &u64_bytes(u64::try_from(n).map_err(|_| Error::Invalid("bad counter"))?),
        &u64_bytes(u64::try_from(pn).map_err(|_| Error::Invalid("bad counter"))?),
        rx,
        &header,
    ])
}

fn counter(obj: &[(String, Json)], key: &str, what: &'static str) -> Result<i64> {
    let n = codec::obj_i64(obj, key).map_err(|_| Error::Invalid(what))?;
    if !(0..=COUNTER_MAX).contains(&n) {
        return Err(Error::Invalid(what));
    }
    Ok(n)
}

fn exact(obj: &[(String, Json)], key: &'static str, len: usize) -> Result<Vec<u8>> {
    codec::b64_field(codec::obj_get(obj, key)?, Some(len), len, key)
}

fn optional(obj: &[(String, Json)], key: &'static str, len: usize) -> Result<Option<Vec<u8>>> {
    match codec::obj_opt(obj, key) {
        None => Ok(None),
        Some(value) => Ok(Some(codec::b64_field(value, Some(len), len, key)?)),
    }
}

fn required_str(obj: &[(String, Json)], key: &'static str, max: usize) -> Result<String> {
    codec::bounded_str(obj, key, max).map(str::to_string)
}

fn check_created(created: i64) -> Result<()> {
    if !(0..=CREATED_MAX).contains(&created) {
        Err(Error::Invalid("bad createdAt"))
    } else {
        Ok(())
    }
}
