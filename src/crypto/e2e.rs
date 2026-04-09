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

// Wire-format size of an ML-KEM-768 ciphertext (always exactly 1088 bytes).
const MLKEM_CT_BYTES: usize = 1088;

pub struct E2EKeys {
    x25519_secret: StaticSecret,
    pub x25519_public: PublicKey,
    // ML-KEM ptivate key — never leaves this process.
    mlkem_dk: DecapsulationKey<MlKem768Params>,
    // ML-KEM-768 publick ey — sent to peers via AnnounceKey.
    pub mlkem_ek_bytes: Vec<u8>,
}

impl E2EKeys {
    pub fn generate() -> Self {
        let x25519_secret = StaticSecret::random_from_rng(OsRng);
        let x25519_public = PublicKey::from(&x25519_secret);
        // generate() returns (DecapsulationKey<P>, EncapsulationKey<P>)
        let (mlkem_dk, mlkem_ek) = MlKem768::generate(&mut OsRng);
        let mlkem_ek_bytes = mlkem_ek.as_bytes().as_slice().to_vec();
        E2EKeys { x25519_secret, x25519_public, mlkem_dk, mlkem_ek_bytes }
    }

    fn x25519_shared(&self, their_public: &[u8; 32]) -> [u8; 32] {
        let their_pub = PublicKey::from(*their_public);
        *self.x25519_secret.diffie_hellman(&their_pub).as_bytes()
    }

    // Bind both shared secrets into a single ChaCha20-Poly1305 key via HKDF-SHA256.
    // Security holds as long as either X25519 (classical) or ML-KEM-768 (PQ) is secure.
    fn derive_key(x25519_ss: &[u8], mlkem_ss: &[u8]) -> Key {
        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(x25519_ss);
        ikm[32..].copy_from_slice(mlkem_ss);
        let hk = Hkdf::<Sha256>::new(None, &ikm);
        let mut k = [0u8; 32];
        hk.expand(b"p2-message-e2e-hybrid-v1", &mut k).expect("HKDF expand failed");
        Key::from(k)
    }

    // Encrypt plaintext
    // Wire format: `[ML-KEM ciphertext (1088 B)][nonce (12 B)][AEAD ciphertext]`
    pub fn encrypt(&self, their_x25519: &[u8; 32], their_mlkem_ek: &[u8], plaintext: &str) -> Vec<u8> {
        // Classical leg: X25519 Diffie-Hellman with Dalek curve
        let x25519_ss = self.x25519_shared(their_x25519);

        // Post-quantum leg: ML-KEM-768 encapsulation using target client's public key
        type EkEncoded = ml_kem::Encoded<EncapsulationKey<MlKem768Params>>;
        let ek_arr: EkEncoded = Array::try_from(their_mlkem_ek)
            .expect("ML-KEM-768 encapsulation key must be 1184 bytes");
        let ek = EncapsulationKey::<MlKem768Params>::from_bytes(&ek_arr);
        let (mlkem_ct, mlkem_ss) = ek.encapsulate(&mut OsRng)
            .expect("ML-KEM-768 encapsulation failed");

        // Hybrid key with hkdf
        let key = Self::derive_key(&x25519_ss, mlkem_ss.as_slice());

        // ChaCha20-Poly1305 AEAD
        let nonce = ChaCha20Poly1305::generate_nonce(OsRng);
        let ct = ChaCha20Poly1305::new(&key)
            .encrypt(&nonce, plaintext.as_bytes())
            .expect("AEAD encryption failed");

        // Final bytestream [mlkem_ct (1088) || nonce (12) || aead_ct]
        let mut out = mlkem_ct.as_slice().to_vec();
        out.extend_from_slice(nonce.as_slice());
        out.extend(ct);
        out
    }

    // Decrypt ct received from a peer.
    pub fn decrypt(&self, their_x25519: &[u8; 32], data: &[u8]) -> Option<String> {
        if data.len() < MLKEM_CT_BYTES + 12 {
            return None;
        }
        let (mlkem_ct_bytes, rest) = data.split_at(MLKEM_CT_BYTES);
        let (nonce_bytes, aead_ct) = rest.split_at(12);

        // Classical leg: X25519 DH 
        let x25519_ss = self.x25519_shared(their_x25519);

        // Post-quantum leg
        let mlkem_ct: Ciphertext<MlKem768> = Array::try_from(mlkem_ct_bytes).ok()?;
        let mlkem_ss = self.mlkem_dk.decapsulate(&mlkem_ct).ok()?;

        let key = Self::derive_key(&x25519_ss, mlkem_ss.as_slice());

        ChaCha20Poly1305::new(&key)
            .decrypt(Nonce::from_slice(nonce_bytes), aead_ct)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
    }
}
