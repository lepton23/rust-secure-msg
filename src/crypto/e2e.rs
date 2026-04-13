use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use hkdf::Hkdf;
use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem768, MlKem768Params};
use ml_kem::array::Array;
use ml_kem::kem::{DecapsulationKey, EncapsulationKey, Decapsulate, Encapsulate};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

// Wire-format size of an ML-KEM-768 ciphertext (always exactly 1088 bytes, just how lattice encryption works)
const MLKEM_CT_BYTES: usize = 1088;

pub struct E2EKeys {
    x25519_secret: StaticSecret,
    pub x25519_public: PublicKey,
    // ML-KEM private key
    mlkem_dk: DecapsulationKey<MlKem768Params>,
    // ML-KEM-768 public key 
    pub mlkem_ek_bytes: Vec<u8>,
}

impl E2EKeys {
    pub fn generate() -> Self {
        let x25519_secret = StaticSecret::random_from_rng(OsRng);
        let x25519_public = PublicKey::from(&x25519_secret);
        let (mlkem_dk, mlkem_ek) = MlKem768::generate(&mut OsRng);
        let mlkem_ek_bytes = mlkem_ek.as_bytes().as_slice().to_vec();
        Self { x25519_secret, x25519_public, mlkem_dk, mlkem_ek_bytes }
    }

    fn x25519_shared(&self, their_public: &[u8; 32]) -> [u8; 32] {
        let their_pub = PublicKey::from(*their_public);
        *self.x25519_secret.diffie_hellman(&their_pub).as_bytes()
    }

    // Derive initial chain key from hybrid shared secrets
    fn init_chain_key(x25519_ss: &[u8; 32], mlkem_ss: &[u8]) -> [u8; 32] {
        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(x25519_ss);
        ikm[32..].copy_from_slice(mlkem_ss);
        let hk = Hkdf::<Sha256>::new(None, &ikm);
        let mut chain_key = [0u8; 32];
        hk.expand(b"ratchet-init", &mut chain_key)
            .expect("HKDF expand failed");
        chain_key
    }

    // Advance the chain key with new mlkem ss
    fn advance_chain_key(prev_chain: &[u8; 32], mlkem_ss: &[u8]) -> [u8; 32] {
        let mut ikm = Vec::with_capacity(32 + mlkem_ss.len());
        ikm.extend_from_slice(prev_chain);
        ikm.extend_from_slice(mlkem_ss);
        let hk = Hkdf::<Sha256>::new(None, &ikm);
        let mut chain_key = [0u8; 32];
        hk.expand(b"chain-advance", &mut chain_key)
            .expect("HKDF expand failed");
        chain_key
    }

    // Ratchet step: split the current chain key into a one-time message key and next chain key 
    fn ratchet_step(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let hk = Hkdf::<Sha256>::new(None, chain_key);
        let mut out = [0u8; 64];
        hk.expand(b"ratchet-step", &mut out)
            .expect("HKDF expand failed");
        let mut msg_key = [0u8; 32];
        let mut next_chain = [0u8; 32];
        msg_key.copy_from_slice(&out[..32]);
        next_chain.copy_from_slice(&out[32..]);
        (msg_key, next_chain)
    }

    // Encrypt plaintext.
    // `chain_key` is None for the first message (initial handshake)
    // `Some(ck)` for every subsequent message - returns new chain key for next ratchet step
    //
    // Wire format: `[ML-KEM ciphertext (1088 B)][nonce (12 B)][AEAD ciphertext]`
    pub fn encrypt(
        &self,
        their_x25519: &[u8; 32],
        their_mlkem_ek: &[u8],
        plaintext: &str,
        chain_key: Option<[u8; 32]>,
    ) -> (Vec<u8>, [u8; 32]) {
        // Classical leg: X25519 DH
        let x25519_ss = self.x25519_shared(their_x25519);

        // Post-quantum leg: new ML-KEM-768 encapsulation each message
        type EkEncoded = ml_kem::Encoded<EncapsulationKey<MlKem768Params>>;
        let ek_arr: EkEncoded = Array::try_from(their_mlkem_ek)
            .expect("ML-KEM-768 encapsulation key must be 1184 bytes");
        let ek = EncapsulationKey::<MlKem768Params>::from_bytes(&ek_arr);
        let (mlkem_ct, mlkem_ss) = ek.encapsulate(&mut OsRng)
            .expect("ML-KEM-768 encapsulation failed");

        // Derive or advance the chain key with nnew ML-KEM SS
        let current_chain = match chain_key {
            None => Self::init_chain_key(&x25519_ss, mlkem_ss.as_slice()),
            Some(prev) => Self::advance_chain_key(&prev, mlkem_ss.as_slice()),
        };

        // Ratchet: one-time message key + next chain key
        let (msg_key, next_chain) = Self::ratchet_step(&current_chain);

        // ChaCha20-Poly1305 AEAD using msg_key
        let key = Key::from(msg_key);
        let nonce = ChaCha20Poly1305::generate_nonce(OsRng);
        let ct = ChaCha20Poly1305::new(&key)
            .encrypt(&nonce, plaintext.as_bytes())
            .expect("AEAD encryption failed");

        // Wire format: [mlkem_ct (1088) || nonce (12) || aead_ct]
        let mut out = mlkem_ct.as_slice().to_vec();
        out.extend_from_slice(nonce.as_slice());
        out.extend(ct);

        (out, next_chain)
    }

    // Decrypt ciphertext, advancing ratchet
    pub fn decrypt(
        &self,
        their_x25519: &[u8; 32],
        data: &[u8],
        chain_key: Option<[u8; 32]>,
    ) -> Option<(String, [u8; 32])> {
        if data.len() < MLKEM_CT_BYTES + 12 {
            return None;
        }
        let (mlkem_ct_bytes, rest) = data.split_at(MLKEM_CT_BYTES);
        let (nonce_bytes, aead_ct) = rest.split_at(12);

        // Classical leg: X25519 DH
        let x25519_ss = self.x25519_shared(their_x25519);

        // Post-quantum leg: decapsulate per-message ML-KEM ciphertext
        let mlkem_ct: Ciphertext<MlKem768> = Array::try_from(mlkem_ct_bytes).ok()?;
        let mlkem_ss = self.mlkem_dk.decapsulate(&mlkem_ct).ok()?;

        // Mirror sender's chain-key derivation
        let current_chain = match chain_key {
            None => Self::init_chain_key(&x25519_ss, mlkem_ss.as_slice()),
            Some(prev) => Self::advance_chain_key(&prev, mlkem_ss.as_slice()),
        };

        // Ratchet: recover one-time message key 
        let (msg_key, next_chain) = Self::ratchet_step(&current_chain);

        let key = Key::from(msg_key);
        let plaintext = ChaCha20Poly1305::new(&key)
            .decrypt(Nonce::from_slice(nonce_bytes), aead_ct)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())?;

        Some((plaintext, next_chain))
    }
}
