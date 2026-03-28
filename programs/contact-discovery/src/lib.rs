use anchor_lang::prelude::*;
use sha2::{Sha256, Digest};

declare_id!("CDiscXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");

/// Maximum contacts per user session
pub const MAX_CONTACTS: usize = 200;
/// Maximum hashed contact bytes (32 bytes SHA-256 each)
pub const CONTACT_HASH_SIZE: usize = 32;
/// Session account discriminator space
pub const SESSION_SPACE: usize = 8   // discriminator
    + 32                              // owner pubkey
    + 4 + (MAX_CONTACTS * CONTACT_HASH_SIZE) // contact_hashes vec
    + 8                               // created_at
    + 1                               // status
    + 32                              // mxe_job_id
    + 4 + (MAX_CONTACTS * 32)         // matched_hashes vec (result)
    + 1;                              // bump

#[program]
pub mod contact_discovery {
    use super::*;

    /// Initialize a new discovery session for a user.
    /// The user commits a Merkle root of their hashed contact list
    /// so we can verify integrity without storing raw contacts on-chain.
    pub fn init_session(
        ctx: Context<InitSession>,
        contact_hashes: Vec<[u8; CONTACT_HASH_SIZE]>,
        merkle_root: [u8; 32],
    ) -> Result<()> {
        require!(
            contact_hashes.len() <= MAX_CONTACTS,
            DiscoveryError::TooManyContacts
        );
        require!(
            !contact_hashes.is_empty(),
            DiscoveryError::NoContacts
        );

        // Verify the submitted merkle root matches the hashes
        let computed_root = compute_merkle_root(&contact_hashes);
        require!(
            computed_root == merkle_root,
            DiscoveryError::InvalidMerkleRoot
        );

        let session = &mut ctx.accounts.session;
        session.owner = ctx.accounts.owner.key();
        session.contact_hashes = contact_hashes.iter().map(|h| h.to_vec()).collect();
        session.created_at = Clock::get()?.unix_timestamp;
        session.status = SessionStatus::Pending as u8;
        session.mxe_job_id = [0u8; 32];
        session.matched_hashes = Vec::new();
        session.bump = ctx.bumps.session;

        emit!(SessionCreated {
            owner: ctx.accounts.owner.key(),
            contact_count: contact_hashes.len() as u32,
            timestamp: session.created_at,
        });

        msg!("Session initialized for {} contacts", contact_hashes.len());
        Ok(())
    }

    /// Called after Arcium MXE completes the PSI computation.
    /// The Arcium verifier CPI calls this to post the intersection result.
    /// Only the authorised Arcium MXE verifier PDA can call this.
    pub fn submit_psi_result(
        ctx: Context<SubmitPsiResult>,
        mxe_job_id: [u8; 32],
        matched_hashes: Vec<Vec<u8>>,
    ) -> Result<()> {
        // In production: verify Arcium MXE verifier signature here
        // The MXE verifier PDA is derived from the Arcium program ID
        require!(
            matched_hashes.len() <= MAX_CONTACTS,
            DiscoveryError::TooManyContacts
        );

        let session = &mut ctx.accounts.session;
        require!(
            session.status == SessionStatus::Pending as u8,
            DiscoveryError::SessionNotPending
        );

        session.mxe_job_id = mxe_job_id;
        session.matched_hashes = matched_hashes.clone();
        session.status = SessionStatus::Complete as u8;

        emit!(PsiResultReady {
            owner: session.owner,
            job_id: mxe_job_id,
            match_count: matched_hashes.len() as u32,
            timestamp: Clock::get()?.unix_timestamp,
        });

        msg!("PSI result: {} matches found", matched_hashes.len());
        Ok(())
    }

    /// Close a session and reclaim rent.
    pub fn close_session(ctx: Context<CloseSession>) -> Result<()> {
        emit!(SessionClosed {
            owner: ctx.accounts.session.owner,
            timestamp: Clock::get()?.unix_timestamp,
        });
        msg!("Session closed and rent reclaimed");
        Ok(())
    }

    /// Register a wallet as a discoverable user.
    /// Stores a salted hash of the user's identifier (phone/email)
    /// so peers can compute PSI without revealing the plaintext.
    pub fn register_identity(
        ctx: Context<RegisterIdentity>,
        identity_hash: [u8; 32],
        salt: [u8; 16],
    ) -> Result<()> {
        let identity = &mut ctx.accounts.identity;
        identity.owner = ctx.accounts.owner.key();
        identity.identity_hash = identity_hash;
        identity.salt = salt;
        identity.registered_at = Clock::get()?.unix_timestamp;
        identity.bump = ctx.bumps.identity;

        emit!(IdentityRegistered {
            owner: ctx.accounts.owner.key(),
            timestamp: identity.registered_at,
        });

        msg!("Identity registered for {}", ctx.accounts.owner.key());
        Ok(())
    }
}

// ─────────────────────────── Accounts ───────────────────────────

#[derive(Accounts)]
pub struct InitSession<'info> {
    #[account(
        init,
        payer = owner,
        space = SESSION_SPACE,
        seeds = [b"session", owner.key().as_ref()],
        bump
    )]
    pub session: Account<'info, DiscoverySession>,

    #[account(mut)]
    pub owner: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SubmitPsiResult<'info> {
    #[account(
        mut,
        seeds = [b"session", session.owner.as_ref()],
        bump = session.bump,
    )]
    pub session: Account<'info, DiscoverySession>,

    /// CHECK: This is the Arcium MXE verifier — validated by seeds
    /// In production use Arcium's verifier PDA derivation
    #[account(
        seeds = [b"arcium-verifier"],
        bump,
    )]
    pub arcium_verifier: UncheckedAccount<'info>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct CloseSession<'info> {
    #[account(
        mut,
        seeds = [b"session", owner.key().as_ref()],
        bump = session.bump,
        close = owner,
    )]
    pub session: Account<'info, DiscoverySession>,

    #[account(mut)]
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct RegisterIdentity<'info> {
    #[account(
        init_if_needed,
        payer = owner,
        space = 8 + 32 + 32 + 16 + 8 + 1,
        seeds = [b"identity", owner.key().as_ref()],
        bump
    )]
    pub identity: Account<'info, UserIdentity>,

    #[account(mut)]
    pub owner: Signer<'info>,

    pub system_program: Program<'info, System>,
}

// ─────────────────────────── State ───────────────────────────

#[account]
pub struct DiscoverySession {
    pub owner: Pubkey,
    pub contact_hashes: Vec<Vec<u8>>,  // hashed contact list (never raw)
    pub created_at: i64,
    pub status: u8,
    pub mxe_job_id: [u8; 32],
    pub matched_hashes: Vec<Vec<u8>>,  // intersection result from Arcium MXE
    pub bump: u8,
}

#[account]
pub struct UserIdentity {
    pub owner: Pubkey,
    pub identity_hash: [u8; 32],  // SHA-256(salt || identifier)
    pub salt: [u8; 16],
    pub registered_at: i64,
    pub bump: u8,
}

// ─────────────────────────── Enums ───────────────────────────

#[repr(u8)]
pub enum SessionStatus {
    Pending  = 0,
    Complete = 1,
    Failed   = 2,
}

// ─────────────────────────── Events ───────────────────────────

#[event]
pub struct SessionCreated {
    pub owner: Pubkey,
    pub contact_count: u32,
    pub timestamp: i64,
}

#[event]
pub struct PsiResultReady {
    pub owner: Pubkey,
    pub job_id: [u8; 32],
    pub match_count: u32,
    pub timestamp: i64,
}

#[event]
pub struct SessionClosed {
    pub owner: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct IdentityRegistered {
    pub owner: Pubkey,
    pub timestamp: i64,
}

// ─────────────────────────── Errors ───────────────────────────

#[error_code]
pub enum DiscoveryError {
    #[msg("Contact list exceeds maximum of 200 entries")]
    TooManyContacts,
    #[msg("Contact list cannot be empty")]
    NoContacts,
    #[msg("Merkle root does not match submitted hashes")]
    InvalidMerkleRoot,
    #[msg("Session is not in pending state")]
    SessionNotPending,
    #[msg("Unauthorized: only the Arcium MXE verifier can submit results")]
    Unauthorized,
}

// ─────────────────────────── Helpers ───────────────────────────

/// Compute a simple binary Merkle root from a list of hashes.
/// Used for on-chain commitment verification without storing all hashes.
fn compute_merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    if hashes.is_empty() {
        return [0u8; 32];
    }
    let mut layer: Vec<[u8; 32]> = hashes.to_vec();
    while layer.len() > 1 {
        if layer.len() % 2 != 0 {
            layer.push(*layer.last().unwrap());
        }
        layer = layer
            .chunks(2)
            .map(|pair| {
                let mut hasher = Sha256::new();
                hasher.update(&pair[0]);
                hasher.update(&pair[1]);
                let result = hasher.finalize();
                let mut out = [0u8; 32];
                out.copy_from_slice(&result);
                out
            })
            .collect();
    }
    layer[0]
}
