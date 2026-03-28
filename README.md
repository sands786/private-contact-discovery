# 🔒 Private Contact Discovery — Arcium RTG Submission

> **Find friends without uploading your address book.**  
> Private Set Intersection (PSI) powered by Arcium MXE on Solana.

[![Solana](https://img.shields.io/badge/Solana-Devnet-9945FF?logo=solana)](https://solana.com)
[![Arcium](https://img.shields.io/badge/Arcium-MXE-00D4FF)](https://arcium.com)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## 🎯 What This Builds

**Private Contact Discovery** lets two Solana users discover mutual contacts without either party ever seeing the other's full contact list. Only the intersection — contacts both users share — is revealed. All non-matching contacts remain mathematically hidden.

**The problem it solves:** Traditional friend-discovery (WhatsApp, Telegram, etc.) requires uploading your entire address book to a server. That server learns every contact you have — friends, doctors, lawyers, family. This is a massive privacy violation that most users accept unknowingly.

**Arcium fixes this.**

---

## 🛡️ How Arcium Is Used & Privacy Benefits

### Architecture: Private Set Intersection via Arcium MXE

```
┌─────────────────────────────────────────────────────────────┐
│                     PRIVACY FLOW                            │
│                                                             │
│  Party A                    Arcium MXE              Party B │
│  ───────                    ──────────              ─────── │
│  contacts_A                 ┌────────┐              contacts_B
│  → SHA256(salt||contact)    │Secure  │  SHA256(salt||contact)│
│  → encrypt(hashes_A)  ───► │Enclave │ ◄─── encrypt(hashes_B)│
│                             │        │                      │
│                             │  PSI   │                      │
│                             │compute │                      │
│                             └───┬────┘                      │
│                                 │ intersection only         │
│                                 ▼                           │
│                        Solana Program (CPI)                 │
│                        post_psi_result(matches)             │
│                                                             │
│  ✓ Party A learns: which of THEIR contacts match            │
│  ✗ Party A NEVER learns: Party B's non-matching contacts    │
│  ✗ Party B NEVER learns: Party A's non-matching contacts    │
│  ✗ Arcium nodes NEVER see: plaintext contacts               │
└─────────────────────────────────────────────────────────────┘
```

### Why Arcium Specifically?

| Requirement | How Arcium Provides It |
|---|---|
| Compute on encrypted data | MXE (Multi-Party Execution) decrypts inside TEE boundary |
| No single point of trust | Threshold decryption — n-of-m MXE nodes must cooperate |
| Verifiable computation | TEE attestation proof posted on-chain |
| Solana-native | Direct CPI from MXE verifier back to our Anchor program |
| No trusted third party | Even Arcium cannot reconstruct individual contact lists |

### Privacy Guarantees

1. **Client-side hashing**: `SHA-256(salt || contact_identifier)` — raw contacts never leave the browser
2. **Salted hashes**: each user's salt prevents rainbow table attacks and cross-user hash correlation
3. **Session blinding**: all hashes are further blinded with `SHA-256(hash || job_id)` before PSI, preventing cross-session correlation
4. **Zero-knowledge intersection**: PSI reveals _only_ the count and hashes of mutual contacts — nothing about non-matches
5. **On-chain commitment**: Merkle root of hashes is stored in the Solana session account so computation integrity is verifiable

---

## 🏗️ Project Structure

```
private-contact-discovery/
├── programs/
│   └── contact-discovery/
│       └── src/lib.rs          # Anchor Solana program
├── arcium-mxe/
│   └── src/main.rs             # Arcium MXE PSI computation (Rust)
├── app/
│   └── index.html              # Frontend (Phantom wallet + full UI)
├── tests/
│   └── contact-discovery.ts    # Anchor integration tests
├── Anchor.toml
├── Cargo.toml
├── package.json
└── README.md
```

---

## 🔧 Technical Implementation

### 1. Solana Program (`programs/contact-discovery/src/lib.rs`)

Four instructions:

| Instruction | Purpose |
|---|---|
| `register_identity` | Store salted identity hash on-chain (PDA per wallet) |
| `init_session` | Commit hashed contact list + Merkle root to a session PDA |
| `submit_psi_result` | Arcium MXE verifier CPI: post intersection result |
| `close_session` | Reclaim rent after discovery is complete |

**On-chain state:**
- `DiscoverySession`: stores Merkle commitment, MXE job ID, match results, status
- `UserIdentity`: stores salted identity hash for peer lookup

**Privacy design:** Raw contacts are never stored. Only SHA-256 hashes + a Merkle root commitment reach the chain, enabling integrity verification without data exposure.

### 2. Arcium MXE Program (`arcium-mxe/src/main.rs`)

The `mxe_execute` function runs inside Arcium's secure enclave:

```rust
pub fn mxe_execute(job: &PsiJobInput, set_a: &[ContactHash], set_b: &[ContactHash]) -> PsiJobOutput {
    // 1. Blind all hashes with job_id to prevent cross-session correlation
    let blinded_a = set_a.iter().map(|h| session_blind(h, &job.job_id)).collect();
    let blinded_b = set_b.iter().map(|h| session_blind(h, &job.job_id)).collect();

    // 2. Compute intersection — constant-time, no data leakage
    let intersection = compute_psi(&blinded_a, &blinded_b);

    // 3. Generate attestation proof (TEE quote)
    // 4. Return via Solana CPI callback
}
```

**PSI Algorithm:** Hash-set intersection — `O(n)` time, constant-time per lookup to prevent timing side-channels.

**Session blinding:** `H_blinded = SHA-256(H_contact || job_id)` — ensures hashes observed in one session cannot be linked to hashes in another session, even by an adversary monitoring Solana transactions.

### 3. Frontend (`app/index.html`)

- **Phantom wallet integration** — connects and signs Solana transactions
- **Client-side hashing** — `crypto.subtle.digest('SHA-256', salt || contact)` in browser
- **4-step guided UI** — Register → Hash → MXE Compute → Results
- **Real-time MXE visualization** — shows encryption, computation, and result flow
- **Privacy proof display** — shows job ID, attestation, Solana TX, match count

---

## 🚀 Getting Started

### Prerequisites

```bash
# Rust + Solana CLI
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
sh -c "$(curl -sSfL https://release.solana.com/stable/install)"

# Anchor CLI
cargo install --git https://github.com/coral-xyz/anchor avm --locked --force
avm install latest && avm use latest

# Node.js dependencies
npm install
```

### Build & Test

```bash
# Build the Solana program
anchor build

# Run tests against localnet
anchor test

# Or test on devnet
solana config set --url devnet
anchor test --provider.cluster devnet
```

### Run the Frontend

```bash
# Serve locally
npx serve app -l 3000
# Open http://localhost:3000
```

### Run the Arcium MXE (locally for testing)

```bash
cd arcium-mxe
cargo test          # unit tests
cargo run           # demo CLI output
```

### Deploy to Devnet

```bash
solana config set --url devnet
solana airdrop 2
anchor deploy
```

Update `declare_id!()` in `lib.rs` and `Anchor.toml` with the deployed program ID.

---

## 🧪 Test Results

```
private-contact-discovery
  ✓ registers a user identity
  ✓ initializes a discovery session with hashed contacts
  ✓ rejects invalid merkle root
  ✓ rejects empty contact list
  ✓ submits PSI result (simulating Arcium MXE callback)
  ✓ closes session and reclaims rent
  ✓ verifies PSI logic off-chain

7 passing (3.2s)
```

---

## 📐 Judging Criteria Response

### Innovation
Private Set Intersection for social contact discovery is a well-known research problem but has never been deployed on Solana with Arcium's MXE. The combination of client-side hashing + session blinding + on-chain Merkle commitment + MXE-computed PSI is a novel full-stack privacy architecture for decentralized social applications.

### Technical Implementation
- Full Anchor program with proper PDA design, rent reclamation, and event emission
- Arcium MXE program with PSI, session blinding, and attestation
- Comprehensive test suite (7 tests) covering happy paths and error cases
- Production-ready error handling, proper Merkle root verification

### User Experience
- 4-step guided flow — register, add contacts, compute, see results
- Real-time progress visualization of MXE computation
- Privacy proof displayed inline so users understand what was and wasn't revealed
- Works in demo mode without wallet for evaluation

### Impact
Every social app that does friend discovery uploads address books. Arcium PSI makes private friend discovery practical at scale on Solana. This could be integrated into any Solana-based social protocol (Dialect, Squads, DRiP, etc.) to eliminate address book uploads entirely.

### Clarity
The frontend includes an inline explanation of how Arcium is used at every step. The README and code comments explain the PSI protocol, privacy guarantees, and Arcium's role in detail.

---

## 🔗 Related Work & Resources

- [Arcium Documentation](https://docs.arcium.com)
- [Anchor Framework](https://anchor-lang.com)
- [Private Set Intersection (PSI) — Wikipedia](https://en.wikipedia.org/wiki/Private_set_intersection)
- [Solana Developer Resources](https://solana.com/developers)

---

## 📄 License

MIT — see [LICENSE](LICENSE)

---

*Built for the Arcium RTG — Private Contact Discovery track. All code is open-source.*
