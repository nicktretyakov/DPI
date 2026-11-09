use ring::aead::{self, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM};
use ring::error::Unspecified;
use ring::rand::{SecureRandom, SystemRandom};

struct OneTimeNonce(Option<[u8; 12]>);

impl NonceSequence for OneTimeNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.0
            .take()
            .map(|arr| Nonce::assume_unique_for_key(arr))
            .ok_or(Unspecified)
    }
}

pub struct CryptoEngine {
    key_bytes: [u8; 32],
}

impl CryptoEngine {
    pub fn new() -> Self {
        let rng = SystemRandom::new();
        let mut key_bytes = [0u8; 32];
        rng.fill(&mut key_bytes).expect("Failed to generate random key");
        Self { key_bytes }
    }

    pub fn encrypt(&self, plaintext: &[u8], nonce_raw: [u8; 12]) -> Result<Vec<u8>, Unspecified> {
        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.key_bytes)?;
        let nonce_seq = OneTimeNonce(Some(nonce_raw));
        let mut sealing_key = SealingKey::new(unbound_key, nonce_seq);

        let mut in_out = plaintext.to_vec();
        sealing_key.seal_in_place_append_tag(aead::Aad::empty(), &mut in_out)?;
        Ok(in_out)
    }

    pub fn decrypt(&self, mut ciphertext: Vec<u8>, nonce_raw: [u8; 12]) -> Result<Vec<u8>, Unspecified> {
        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.key_bytes)?;
        let nonce_seq = OneTimeNonce(Some(nonce_raw));
        let mut opening_key = OpeningKey::new(unbound_key, nonce_seq);

        let decrypted_data = opening_key.open_in_place(aead::Aad::empty(), &mut ciphertext)?;
        Ok(decrypted_data.to_vec())
    }
}
