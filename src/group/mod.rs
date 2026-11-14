//! Group chats over MLS (RFC 9420), mobile decision 0050 and the specification in
//! `docs/protocol/group-chats-v1.md` of the app repository.
//!
//! One [`GroupStore`] holds everything one device needs: its MLS signing key, its
//! Fireplace credential, its key packages and the state of every group it is in.
//! The store never touches files. It starts from records the app saved and, after
//! each change, reports the records that changed so the app can save them.
//!
//! Every change is a small transaction. The call applies it and returns the result
//! and the changed records; the app checks the result (for example, that a Commit
//! came from an administrator), saves the records, and calls [`GroupStore::accept`].
//! Or it calls [`GroupStore::rollback`], which restores the store exactly. A call
//! that fails rolls back on its own. No other change can start while one is open.

mod credential;
mod provider;

use std::collections::HashMap;

use openmls::prelude::{tls_codec::Deserialize as _, *};
use openmls_basic_credential::SignatureKeyPair;

pub use credential::{Credential as FireplaceCredential, VerifiedMember};
use provider::Provider;

use crate::codec::{Json, b64_decode, b64_encode, obj_get, obj_opt, obj_str};
use crate::{AccountIdentity, Error, Result, Rng};

/// The only suite version 1 uses (draft-ietf-mls-pq-ciphersuites-07 `0x0011`;
/// OpenMLS 0.9.2 still uses the provisional identifier `0x004e`).
pub const SUITE: Ciphersuite = Ciphersuite::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519;
/// Group-context extension carrying the encrypted name and administrators.
const META_EXTENSION: u16 = 0xF0F1;
const MAX_NAME_CHARS: usize = 40;
const MAX_KEY_PACKAGES: i64 = 10;
/// Longest input the store accepts in one call.
pub const MAX_INPUT: usize = 4 << 20;

const REC_CREDENTIAL: &[u8] = b"fp:credential";
const REC_SIGNATURE_KEY: &[u8] = b"fp:signature-key";
const REC_GROUPS: &[u8] = b"fp:groups";

type Records = HashMap<Vec<u8>, Vec<u8>>;

/// Name and administrators, authenticated by MLS and seen only by members.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Meta {
    pub name: String,
    pub admins: Vec<String>,
}

pub struct GroupStore {
    provider: Provider,
    /// The records as they were when the open transaction started.
    open: Option<Records>,
}

impl GroupStore {
    /// Loads a store from the records the app saved (empty for a new device).
    pub fn open(records: Records) -> Self {
        Self {
            provider: Provider::new(records),
            open: None,
        }
    }

    /// All records, for a first save or a check.
    pub fn records(&self) -> Records {
        self.provider.records()
    }

    pub fn accept(&mut self) -> Result<()> {
        self.open
            .take()
            .map(|_| ())
            .ok_or(Error::Invalid("no open change"))
    }

    pub fn rollback(&mut self) -> Result<()> {
        let before = self.open.take().ok_or(Error::Invalid("no open change"))?;
        self.provider.replace(before);
        Ok(())
    }

    /// Runs one request (JSON) and returns its result (JSON). Changing requests
    /// include `changes`: the records to save before calling `accept`.
    pub fn call(&mut self, request: &str) -> Result<String> {
        if request.len() > MAX_INPUT {
            return Err(Error::Invalid("request too large"));
        }
        let json = crate::codec::parse_json(request)?;
        let obj = json.as_object()?;
        let op = obj_str(obj, "op")?;
        let result = match op {
            "accept" => self.accept().map(|_| Json::object(vec![])),
            "rollback" => self.rollback().map(|_| Json::object(vec![])),
            "info" => self.info(&gid(obj)?),
            "groups" => self.groups(),
            _ => self.change(op, obj),
        }?;
        Ok(crate::codec::to_json(&result))
    }

    fn change(&mut self, op: &str, obj: &[(String, Json)]) -> Result<Json> {
        if self.open.is_some() {
            return Err(Error::Invalid("a change is still open"));
        }
        let before = self.provider.records();
        let outcome = match op {
            "device" => self.device(obj),
            "key_packages" => self.key_packages(obj),
            "create" => self.create(obj),
            "join" => self.join(obj),
            "encrypt" => self.encrypt(obj),
            "process" => self.process(obj),
            "commit_update" => self.commit(obj, Commit::Update),
            "commit_add" => self.commit(obj, Commit::Add),
            "commit_remove" => self.commit(obj, Commit::Remove),
            "commit_meta" => self.commit(obj, Commit::Meta),
            "merge_pending" => self.merge_pending(obj),
            "discard_pending" => self.discard_pending(obj),
            "forget" => self.forget(obj),
            _ => Err(Error::Invalid("unknown operation")),
        };
        match outcome {
            Ok(mut result) => {
                let after = self.provider.records();
                if let Json::Obj(pairs) = &mut result {
                    pairs.push(("changes".into(), changes(&before, &after)));
                }
                self.open = Some(before);
                Ok(result)
            }
            Err(e) => {
                self.provider.replace(before);
                Err(e)
            }
        }
    }

    // ---- the device

    /// Creates (or replaces) this device's MLS signing key and Fireplace credential.
    fn device(&mut self, obj: &[(String, Json)]) -> Result<Json> {
        let identity = AccountIdentity::from_json(obj_str(obj, "identity")?)?;
        let uid = obj_str(obj, "uid")?;
        let device = obj_str(obj, "device")?;
        let cert_hash = b64_decode(obj_str(obj, "deviceCertHash")?)?;
        let generation = crate::codec::obj_i64(obj, "generation")?;
        let signer = SignatureKeyPair::new(SUITE.signature_algorithm())
            .map_err(|_| Error::Crypto("signature key"))?;
        let mut rng = Rng::os();
        let credential = FireplaceCredential::issue(
            &identity,
            uid,
            device,
            &cert_hash,
            signer.public(),
            generation as u64,
            &mut rng,
        )?;
        signer
            .store(self.provider.storage())
            .map_err(|_| Error::Crypto("store"))?;
        self.provider.put(REC_CREDENTIAL, credential.encode()?);
        self.provider
            .put(REC_SIGNATURE_KEY, signer.public().to_vec());
        Ok(Json::object(vec![(
            "signatureKey".into(),
            Json::Str(b64_encode(signer.public())),
        )]))
    }

    fn signer(&self) -> Result<(SignatureKeyPair, CredentialWithKey)> {
        let public = self
            .provider
            .get(REC_SIGNATURE_KEY)
            .ok_or(Error::Invalid("no device"))?;
        let credential = self
            .provider
            .get(REC_CREDENTIAL)
            .ok_or(Error::Invalid("no device"))?;
        let signer = SignatureKeyPair::read(
            self.provider.storage(),
            &public,
            SUITE.signature_algorithm(),
        )
        .ok_or(Error::Invalid("no signing key"))?;
        let cwk = CredentialWithKey {
            credential: BasicCredential::new(credential).into(),
            signature_key: public.into(),
        };
        Ok((signer, cwk))
    }

    fn capabilities() -> Capabilities {
        Capabilities::new(
            None,
            Some(&[SUITE]),
            Some(&[ExtensionType::Unknown(META_EXTENSION)]),
            None,
            Some(&[CredentialType::Basic]),
        )
    }

    fn key_packages(&mut self, obj: &[(String, Json)]) -> Result<Json> {
        let count = crate::codec::obj_i64(obj, "count")?;
        if !(1..=MAX_KEY_PACKAGES).contains(&count) {
            return Err(Error::Invalid("key package count"));
        }
        let (signer, cwk) = self.signer()?;
        let mut out = Vec::new();
        for _ in 0..count {
            let bundle = KeyPackage::builder()
                .leaf_node_capabilities(Self::capabilities())
                .build(SUITE, &self.provider, &signer, cwk.clone())
                .map_err(|_| Error::Crypto("key package"))?;
            let kp = bundle.key_package();
            let reference = kp
                .hash_ref(self.provider.crypto())
                .map_err(|_| Error::Crypto("key package ref"))?;
            out.push(Json::object(vec![
                ("ref".into(), Json::Str(hex(reference.as_slice()))),
                ("keyPackage".into(), Json::Str(b64_encode(&tls(kp)?))),
            ]));
        }
        Ok(Json::object(vec![("packages".into(), Json::Arr(out))]))
    }

    // ---- groups

    fn config() -> MlsGroupCreateConfig {
        MlsGroupCreateConfig::builder()
            .ciphersuite(SUITE)
            .use_ratchet_tree_extension(true)
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .max_past_epochs(1)
            .capabilities(Self::capabilities())
            .build()
    }

    fn load(&self, gid: &GroupId) -> Result<MlsGroup> {
        MlsGroup::load(self.provider.storage(), gid)
            .map_err(|_| Error::Crypto("storage"))?
            .ok_or(Error::Invalid("unknown group"))
    }

    fn create(&mut self, obj: &[(String, Json)]) -> Result<Json> {
        let gid = gid(obj)?;
        if self.load(&gid).is_ok() {
            return Err(Error::Invalid("group exists"));
        }
        let meta = Meta {
            name: name(obj)?,
            admins: vec![self.own()?.uid],
        };
        let (signer, cwk) = self.signer()?;
        let mut group =
            MlsGroup::new_with_group_id(&self.provider, &signer, &Self::config(), gid.clone(), cwk)
                .map_err(|_| Error::Crypto("create"))?;
        // The name and administrators go in with the group's first Commit, which
        // only this device sees; nobody else is in the group yet.
        group
            .update_group_context_extensions(&self.provider, meta_extensions(&meta)?, &signer)
            .map_err(|_| Error::Crypto("meta"))?;
        group
            .merge_pending_commit(&self.provider)
            .map_err(|_| Error::Crypto("merge"))?;
        self.remember(&gid, true)?;
        self.describe(&group)
    }

    fn join(&mut self, obj: &[(String, Json)]) -> Result<Json> {
        let bytes = b64_decode(obj_str(obj, "welcome")?)?;
        let message = MlsMessageIn::tls_deserialize_exact(&bytes[..])
            .map_err(|_| Error::Invalid("welcome"))?;
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return Err(Error::Invalid("welcome"));
        };
        let group = StagedWelcome::new_from_welcome(
            &self.provider,
            Self::config().join_config(),
            welcome,
            None,
        )
        .map_err(|_| Error::Crypto("welcome"))?
        .into_group(&self.provider)
        .map_err(|_| Error::Crypto("welcome"))?;
        if group.ciphersuite() != SUITE {
            return Err(Error::Crypto("suite"));
        }
        // Every member must carry a valid Fireplace credential for its leaf key.
        roster(&group)?;
        self.remember(group.group_id(), true)?;
        self.describe(&group)
    }

    fn encrypt(&mut self, obj: &[(String, Json)]) -> Result<Json> {
        let mut group = self.load(&gid(obj)?)?;
        let (signer, _) = self.signer()?;
        let plain = b64_decode(obj_str(obj, "plain")?)?;
        if let Some(aad) = obj_opt(obj, "aad") {
            group.set_aad(b64_decode(aad.as_str()?)?);
        }
        let message = group
            .create_message(&self.provider, &signer, &plain)
            .map_err(|_| Error::Crypto("encrypt"))?;
        Ok(Json::object(vec![
            ("epoch".into(), Json::Int(group.epoch().as_u64() as i64)),
            ("ciphertext".into(), Json::Str(b64_encode(&tls(&message)?))),
        ]))
    }

    /// Decrypts an application message, or applies a Commit and reports what it
    /// changed. The app checks a Commit against its rules before `accept`.
    fn process(&mut self, obj: &[(String, Json)]) -> Result<Json> {
        let mut group = self.load(&gid(obj)?)?;
        let bytes = b64_decode(obj_str(obj, "message")?)?;
        let message = MlsMessageIn::tls_deserialize_exact(&bytes[..])
            .map_err(|_| Error::Invalid("message"))?
            .try_into_protocol_message()
            .map_err(|_| Error::Invalid("message"))?;
        let before = roster(&group)?;
        let processed = group
            .process_message(&self.provider, message)
            .map_err(|_| Error::Crypto("process"))?;
        let sender = match processed.sender() {
            Sender::Member(leaf) => before
                .iter()
                .find(|m| m.leaf == leaf.u32())
                .cloned()
                .ok_or(Error::Crypto("unknown sender"))?,
            _ => return Err(Error::Crypto("sender")),
        };
        let aad = processed.aad().to_vec();
        let epoch = processed.epoch().as_u64();
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(m) => Ok(Json::object(vec![
                ("kind".into(), Json::Str("application".into())),
                ("epoch".into(), Json::Int(epoch as i64)),
                ("sender".into(), sender.to_json()),
                ("aad".into(), Json::Str(b64_encode(&aad))),
                ("plain".into(), Json::Str(b64_encode(&m.into_bytes()))),
            ])),
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                group
                    .merge_staged_commit(&self.provider, *staged)
                    .map_err(|_| Error::Crypto("merge"))?;
                let mut result = self.changed(&group, &before)?;
                if let Json::Obj(pairs) = &mut result {
                    pairs.push(("kind".into(), Json::Str("commit".into())));
                    pairs.push(("committer".into(), sender.to_json()));
                }
                Ok(result)
            }
            // Proposals by reference are not used: every change is a full Commit.
            _ => Err(Error::Crypto("unexpected message")),
        }
    }

    /// A Commit by this device. It stays pending until the app knows whether the
    /// server took it (`merge_pending`) or another Commit won (`discard_pending`).
    fn commit(&mut self, obj: &[(String, Json)], kind: Commit) -> Result<Json> {
        let mut group = self.load(&gid(obj)?)?;
        let (signer, _) = self.signer()?;
        let mut welcome = None;
        let commit = match kind {
            Commit::Update => group
                .self_update(&self.provider, &signer, LeafNodeParameters::default())
                .map_err(|_| Error::Crypto("update"))?
                .into_commit(),
            Commit::Add => {
                let mut packages = Vec::new();
                for p in obj_get(obj, "keyPackages")?.as_array()? {
                    let bytes = b64_decode(p.as_str()?)?;
                    let kp = KeyPackageIn::tls_deserialize_exact(&bytes[..])
                        .map_err(|_| Error::Invalid("key package"))?
                        .validate(self.provider.crypto(), ProtocolVersion::Mls10)
                        .map_err(|_| Error::Crypto("key package"))?;
                    // Check the Fireplace credential before adding anybody.
                    VerifiedMember::check(
                        kp.leaf_node().credential(),
                        kp.leaf_node().signature_key().as_slice(),
                        0,
                    )?;
                    packages.push(kp);
                }
                if packages.is_empty() || packages.len() > 4 {
                    return Err(Error::Invalid("add one account (1-4 devices) at a time"));
                }
                let (c, w, _) = group
                    .add_members(&self.provider, &signer, &packages)
                    .map_err(|_| Error::Crypto("add"))?;
                welcome = Some(w);
                c
            }
            Commit::Remove => {
                let mut leaves = Vec::new();
                for l in obj_get(obj, "leaves")?.as_array()? {
                    leaves.push(LeafNodeIndex::new(
                        u32::try_from(l.as_i64()?).map_err(|_| Error::Invalid("leaf"))?,
                    ));
                }
                group
                    .remove_members(&self.provider, &signer, &leaves)
                    .map_err(|_| Error::Crypto("remove"))?
                    .0
            }
            Commit::Meta => {
                let mut meta = meta(&group)?;
                if obj_opt(obj, "name").is_some() {
                    meta.name = name(obj)?;
                }
                if let Some(admins) = obj_opt(obj, "admins") {
                    meta.admins = admins
                        .as_array()?
                        .iter()
                        .map(|a| a.as_str().map(str::to_owned))
                        .collect::<Result<_>>()?;
                }
                group
                    .update_group_context_extensions(
                        &self.provider,
                        meta_extensions(&meta)?,
                        &signer,
                    )
                    .map_err(|_| Error::Crypto("meta"))?
                    .0
            }
        };
        let mut pairs = vec![
            ("epoch".into(), Json::Int(group.epoch().as_u64() as i64)),
            ("commit".into(), Json::Str(b64_encode(&tls(&commit)?))),
        ];
        if let Some(w) = welcome {
            pairs.push(("welcome".into(), Json::Str(b64_encode(&tls(&w)?))));
        }
        Ok(Json::object(pairs))
    }

    fn merge_pending(&mut self, obj: &[(String, Json)]) -> Result<Json> {
        let mut group = self.load(&gid(obj)?)?;
        let before = roster(&group)?;
        group
            .merge_pending_commit(&self.provider)
            .map_err(|_| Error::Crypto("merge"))?;
        self.changed(&group, &before)
    }

    fn discard_pending(&mut self, obj: &[(String, Json)]) -> Result<Json> {
        let mut group = self.load(&gid(obj)?)?;
        group
            .clear_pending_commit(self.provider.storage())
            .map_err(|_| Error::Crypto("discard"))?;
        self.describe(&group)
    }

    /// Deletes a group's state after leaving it or being removed from it.
    fn forget(&mut self, obj: &[(String, Json)]) -> Result<Json> {
        let gid = gid(obj)?;
        if let Ok(mut group) = self.load(&gid) {
            group
                .delete(self.provider.storage())
                .map_err(|_| Error::Crypto("forget"))?;
        }
        self.remember(&gid, false)?;
        Ok(Json::object(vec![]))
    }

    // ---- reading

    fn info(&self, gid: &GroupId) -> Result<Json> {
        self.describe(&self.load(gid)?)
    }

    fn groups(&self) -> Result<Json> {
        Ok(Json::object(vec![(
            "groups".into(),
            Json::Arr(self.known()?.into_iter().map(Json::Str).collect()),
        )]))
    }

    fn describe(&self, group: &MlsGroup) -> Result<Json> {
        let meta = meta(group)?;
        Ok(Json::object(vec![
            (
                "gid".into(),
                Json::Str(crate::codec::b64url_encode(group.group_id().as_slice())),
            ),
            ("epoch".into(), Json::Int(group.epoch().as_u64() as i64)),
            ("active".into(), Json::Bool(group.is_active())),
            ("name".into(), Json::Str(meta.name)),
            (
                "admins".into(),
                Json::Arr(meta.admins.into_iter().map(Json::Str).collect()),
            ),
            (
                "members".into(),
                Json::Arr(roster(group)?.iter().map(VerifiedMember::to_json).collect()),
            ),
            (
                "pending".into(),
                Json::Bool(group.pending_commit().is_some()),
            ),
        ]))
    }

    /// The group after a Commit, and which leaves it added and removed.
    fn changed(&self, group: &MlsGroup, before: &[VerifiedMember]) -> Result<Json> {
        let after = roster(group)?;
        let added: Vec<Json> = after
            .iter()
            .filter(|m| !before.iter().any(|b| b.same_leaf(m)))
            .map(VerifiedMember::to_json)
            .collect();
        let removed: Vec<Json> = before
            .iter()
            .filter(|b| !after.iter().any(|m| m.same_leaf(b)))
            .map(VerifiedMember::to_json)
            .collect();
        let mut result = self.describe(group)?;
        if let Json::Obj(pairs) = &mut result {
            pairs.push(("added".into(), Json::Arr(added)));
            pairs.push(("removed".into(), Json::Arr(removed)));
        }
        Ok(result)
    }

    fn own(&self) -> Result<FireplaceCredential> {
        FireplaceCredential::decode(
            &self
                .provider
                .get(REC_CREDENTIAL)
                .ok_or(Error::Invalid("no device"))?,
        )
    }

    fn known(&self) -> Result<Vec<String>> {
        match self.provider.get(REC_GROUPS) {
            None => Ok(Vec::new()),
            Some(bytes) => crate::codec::unlp(&bytes)?
                .into_iter()
                .map(|g| String::from_utf8(g).map_err(|_| Error::Invalid("groups")))
                .collect(),
        }
    }

    fn remember(&mut self, gid: &GroupId, present: bool) -> Result<()> {
        let id = crate::codec::b64url_encode(gid.as_slice());
        let mut all = self.known()?;
        all.retain(|g| g != &id);
        if present {
            all.push(id);
        }
        let parts: Vec<&[u8]> = all.iter().map(|g| g.as_bytes()).collect();
        self.provider.put(REC_GROUPS, crate::codec::lp(&parts)?);
        Ok(())
    }
}

enum Commit {
    Update,
    Add,
    Remove,
    Meta,
}

/// Every member of the group, each with a verified Fireplace credential.
fn roster(group: &MlsGroup) -> Result<Vec<VerifiedMember>> {
    group
        .members()
        .map(|m| VerifiedMember::check(&m.credential, &m.signature_key, m.index.u32()))
        .collect()
}

fn meta(group: &MlsGroup) -> Result<Meta> {
    for ext in group.extensions().iter() {
        if let Extension::Unknown(t, UnknownExtension(bytes)) = ext
            && *t == META_EXTENSION
        {
            return decode_meta(bytes);
        }
    }
    Ok(Meta::default())
}

/// The group context's extensions: the name and administrators, and the
/// requirement that every member supports that extension and Basic credentials.
/// A change replaces both together.
fn meta_extensions(meta: &Meta) -> Result<Extensions<GroupContext>> {
    Extensions::from_vec(vec![
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::Unknown(META_EXTENSION)],
            &[],
            &[CredentialType::Basic],
        )),
        Extension::Unknown(META_EXTENSION, UnknownExtension(encode_meta(meta)?)),
    ])
    .map_err(|_| Error::Invalid("meta"))
}

fn encode_meta(meta: &Meta) -> Result<Vec<u8>> {
    let mut parts: Vec<&[u8]> = vec![b"fireplace-group-meta-v1", meta.name.as_bytes()];
    for a in &meta.admins {
        parts.push(a.as_bytes());
    }
    crate::codec::lp(&parts)
}

fn decode_meta(bytes: &[u8]) -> Result<Meta> {
    let parts = crate::codec::unlp(bytes)?;
    if parts.len() < 2 || parts[0] != b"fireplace-group-meta-v1" {
        return Err(Error::Invalid("meta"));
    }
    let text = |b: &Vec<u8>| String::from_utf8(b.clone()).map_err(|_| Error::Invalid("meta"));
    Ok(Meta {
        name: text(&parts[1])?,
        admins: parts[2..].iter().map(text).collect::<Result<_>>()?,
    })
}

fn gid(obj: &[(String, Json)]) -> Result<GroupId> {
    let text = obj_str(obj, "gid")?;
    let bytes = crate::codec::b64url_decode(text)?;
    if bytes.len() != 16 {
        return Err(Error::Invalid("group id"));
    }
    Ok(GroupId::from_slice(&bytes))
}

fn name(obj: &[(String, Json)]) -> Result<String> {
    let name = obj_str(obj, "name")?.trim().to_owned();
    if name.is_empty() || name.chars().count() > MAX_NAME_CHARS {
        return Err(Error::Invalid("group name"));
    }
    Ok(name)
}

fn tls(value: &impl openmls::prelude::tls_codec::Serialize) -> Result<Vec<u8>> {
    value
        .tls_serialize_detached()
        .map_err(|_| Error::Invalid("encode"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn changes(before: &Records, after: &Records) -> Json {
    let mut out = Vec::new();
    for (k, v) in after {
        if before.get(k) != Some(v) {
            out.push(Json::object(vec![
                ("k".into(), Json::Str(b64_encode(k))),
                ("v".into(), Json::Str(b64_encode(v))),
            ]));
        }
    }
    for k in before.keys() {
        if !after.contains_key(k) {
            out.push(Json::object(vec![
                ("k".into(), Json::Str(b64_encode(k))),
                ("v".into(), Json::Null),
            ]));
        }
    }
    Json::Arr(out)
}

#[cfg(test)]
mod tests;
