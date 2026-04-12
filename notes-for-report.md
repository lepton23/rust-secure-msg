 ---
Security Goals

  - Message confidentiality — message content must be readable only by the intended recipient, not by the server or any network observer
  - Mutual authentication — both communicating parties must prove their identity before any message exchange occurs; unauthenticated or unknown parties must be rejected
  - E2E key authenticity (MITM resistance) — a client must be able to verify that the E2E public keys it receives truly belong to the claimed peer, even if the server is compromised or malicious
  - Message integrity — any tampering with a message in transit must be detectable and cause the message to be discarded
  - Replay attack resistance — an attacker who captures a valid ciphertext must not be able to re-submit it and have it accepted as a fresh message
  - Forward secrecy — compromise of long-term private keys must not retroactively expose previously recorded sessions
  - Harvest-now-decrypt-later (HNDL) resistance — messages must remain confidential even against an adversary recording traffic today and decrypting later using a future quantum computer

  ---
Technical Choices and Traceability

                Confidentiality from network observers → mTLS transport (TLS 1.3, tokio-rustls / aws-lc-rs)

  - All traffic between client and server is encrypted at the transport layer via TLS 1.3, meaning no plaintext crosses the wire even before E2E encryption is considered
  - The build_crypto_provider function (src/crypto/crypto_provider.rs) configures the cipher suite explicitly with aws-lc-rs, a FIPS-validated cryptographic backend


                Confidentiality from the server → hybrid E2E encryption (ChaCha20-Poly1305 + HKDF-SHA256)

  - Messages are encrypted client-side before being sent to the server (src/crypto/e2e.rs); the server only ever handles ciphertext (wire format: [ML-KEM-768 ct (1088 B) || nonce (12 B) || AEAD ct])
  - ChaCha20-Poly1305 provides authenticated encryption: the AEAD tag simultaneously enforces confidentiality and integrity, so a single mechanism addresses two goals
  - The symmetric key is derived via HKDF-SHA256 over the concatenation of both shared secrets, producing a single 256-bit key; HKDF's key separation via the info string "p2-message-e2e-hybrid-v1" prevents cross-context key reuse

                Mutual authentication → mTLS with WebPkiClientVerifier

  - The server uses WebPkiClientVerifier (src/crypto/config_builder.rs:30) which rejects any connection that does not present a certificate signed by the trusted CA; there is no anonymous or password-based fallback
  - The client likewise verifies the server certificate against the same CA, so both sides are authenticated before a single application message is sent
  - Client identity is extracted from the TLS certificate CN (src/processes/server.rs:302–320) and used as the canonical client ID throughout the session; duplicate IDs are rejected (server.rs:100–104), preventing session hijacking or
  impersonation via race

                E2E key authenticity / MITM resistance → ECDSA-P256 signatures over the key bundle

  - Upon connection, each client signs the concatenation of its X25519 public key and ML-KEM-768 encapsulation key using its TLS private key (src/crypto/peer_auth.rs:sign_e2e_keys), then includes its DER-encoded TLS certificate alongside
  the signature in AnnounceKey (src/protocol/message.rs:17–27)
  - The server forwards the certificate and signature opaquely to any requesting peer (src/processes/server.rs:238–242), ensuring it cannot substitute its own keys without the signature check failing
  - The receiving client performs a three-step chain of trust (src/crypto/peer_auth.rs:verify_peer_e2e_keys): (1) the peer certificate is verified against the CA, (2) the certificate CN is checked to match the expected client ID, (3) the
  ECDSA signature over the exact key bytes received is verified against the certificate public key — binding the E2E keys cryptographically to the authenticated identity
  - If any step fails the keys are discarded and all pending messages to that peer are dropped (src/processes/app.rs:292–305)

                Message integrity → ChaCha20-Poly1305 AEAD authentication tag

  - The AEAD construction used for E2E encryption produces a MAC over the ciphertext; any bit-flip or substitution causes decryption to return None and the message is silently dropped — integrity is inseparable from confidentiality with
  this construction

                Replay attack resistance → per-peer monotonic sequence numbers inside the AEAD plaintext

  - A 64-bit sequence counter per peer pair is prepended to the plaintext before encryption ({:016x}:content, src/processes/app.rs:210–212); because it is inside the AEAD, it cannot be stripped or forged
  - The receiver tracks the last accepted sequence number per sender (inbound_seq); any message with a sequence number ≤ the last seen is rejected with an explicit error (app.rs:262–266)
  - Embedding the counter inside the authenticated plaintext ties replay protection directly to the AEAD, so both concerns are addressed atomically

                Forward secrecy → ephemeral TLS key exchange

  - Rustls defaults to TLS 1.2 and 1.3, both of which mandate ephemeral key exchange; no static key material can be used to decrypt past sessions
  - The preferred key-exchange group is X25519MLKEM768 (src/crypto/crypto_provider.rs:9), meaning even the TLS session keys are hybrid post-quantum, extending forward-secrecy guarantees into the PQ threat model

                HNDL / post-quantum resistance → hybrid key encapsulation (ML-KEM-768 + X25519)

  - ML-KEM-768 (NIST FIPS 203 standardised, formerly Kyber-768) provides IND-CCA2 security against quantum adversaries; X25519 provides the classical leg
  - The two shared secrets are combined via HKDF rather than concatenated directly, so the derived key is secure as long as either primitive remains unbroken — the hybrid design provides a security floor even if one algorithm is later
  found to be weak
  - The same hybrid principle is applied at the TLS layer via X25519MLKEM768 key exchange, so both the transport and the application-layer encryption are independently quantum-resistant

                PKI and trust hierarchy → single CA, rcgen-generated ECDSA certificates

  - All certificates (server and per-client) are signed by a single CA; the CA certificate is distributed out-of-band and loaded at startup, giving all parties a common root of trust
  - Client certificates encode the client's human-readable ID as the CN, which is the binding point that links the TLS identity to the E2E key verification chain

  ---
  The central design tension the system resolves is that the server must route messages without being trusted with their content. The mTLS layer handles authentication and transport confidentiality, but the E2E layer plus the signed key
  bundle protocol are what make the server architecturally incapable of reading messages or impersonating a peer — even if fully compromised.
