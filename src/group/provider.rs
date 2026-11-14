//! OpenMLS's RustCrypto provider over an in-memory record store that the app
//! saves and reloads. Records are opaque to the app.

use std::collections::HashMap;

use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;

pub struct Provider {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

impl Provider {
    pub fn new(records: HashMap<Vec<u8>, Vec<u8>>) -> Self {
        let storage = MemoryStorage::default();
        *storage.values.write().expect("store lock") = records;
        Self {
            crypto: RustCrypto::default(),
            storage,
        }
    }

    pub fn records(&self) -> HashMap<Vec<u8>, Vec<u8>> {
        self.storage.values.read().expect("store lock").clone()
    }

    pub fn replace(&self, records: HashMap<Vec<u8>, Vec<u8>>) {
        *self.storage.values.write().expect("store lock") = records;
    }

    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.storage
            .values
            .read()
            .expect("store lock")
            .get(key)
            .cloned()
    }

    pub fn put(&self, key: &[u8], value: Vec<u8>) {
        self.storage
            .values
            .write()
            .expect("store lock")
            .insert(key.to_vec(), value);
    }
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }
    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }
    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}
