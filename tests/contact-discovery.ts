import * as anchor from "@coral-xyz/anchor";
import { Program, BN } from "@coral-xyz/anchor";
import { ContactDiscovery } from "../target/types/contact_discovery";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  LAMPORTS_PER_SOL,
} from "@solana/web3.js";
import { createHash, randomBytes } from "crypto";
import { expect } from "chai";

// ─── Helpers ─────────────────────────────────────────────────

function hashContact(salt: Buffer, identifier: string): Buffer {
  return createHash("sha256")
    .update(salt)
    .update(identifier)
    .digest();
}

function computeMerkleRoot(hashes: Buffer[]): Buffer {
  if (hashes.length === 0) return Buffer.alloc(32);
  let layer = [...hashes];
  while (layer.length > 1) {
    if (layer.length % 2 !== 0) layer.push(layer[layer.length - 1]);
    const next: Buffer[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      next.push(
        createHash("sha256").update(layer[i]).update(layer[i + 1]).digest()
      );
    }
    layer = next;
  }
  return layer[0];
}

function sessionPDA(
  programId: PublicKey,
  owner: PublicKey
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("session"), owner.toBuffer()],
    programId
  );
}

function identityPDA(
  programId: PublicKey,
  owner: PublicKey
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("identity"), owner.toBuffer()],
    programId
  );
}

// ─── Test Suite ──────────────────────────────────────────────

describe("private-contact-discovery", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace
    .ContactDiscovery as Program<ContactDiscovery>;

  let alice: Keypair;
  let aliceSalt: Buffer;
  let aliceHashes: Buffer[];

  before(async () => {
    alice = Keypair.generate();
    aliceSalt = randomBytes(16);

    // Fund alice
    const sig = await provider.connection.requestAirdrop(
      alice.publicKey,
      2 * LAMPORTS_PER_SOL
    );
    await provider.connection.confirmTransaction(sig);

    console.log("  Alice:", alice.publicKey.toBase58());
    console.log("  Program:", program.programId.toBase58());
  });

  // ── Identity Registration ──

  it("registers a user identity", async () => {
    const salt = randomBytes(16);
    const identityHash = hashContact(salt, "alice@example.com");
    const [identityPda] = identityPDA(program.programId, alice.publicKey);

    await program.methods
      .registerIdentity(
        Array.from(identityHash) as any,
        Array.from(salt) as any
      )
      .accounts({
        identity: identityPda,
        owner: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([alice])
      .rpc();

    const identity = await program.account.userIdentity.fetch(identityPda);
    expect(identity.owner.toBase58()).to.equal(alice.publicKey.toBase58());
    expect(Buffer.from(identity.identityHash as any)).to.deep.equal(identityHash);
    console.log("  ✓ Identity registered, hash:", identityHash.toString("hex").slice(0, 16) + "...");
  });

  // ── Session Initialization ──

  it("initializes a discovery session with hashed contacts", async () => {
    const contacts = [
      "bob@example.com",
      "+14155551234",
      "charlie@example.com",
      "+14155555678",
    ];

    aliceHashes = contacts.map((c) => hashContact(aliceSalt, c));
    const merkleRoot = computeMerkleRoot(aliceHashes);
    const [sessionPda] = sessionPDA(program.programId, alice.publicKey);

    const hashArrays = aliceHashes.map((h) => Array.from(h)) as any;

    await program.methods
      .initSession(hashArrays, Array.from(merkleRoot) as any)
      .accounts({
        session: sessionPda,
        owner: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([alice])
      .rpc();

    const session = await program.account.discoverySession.fetch(sessionPda);
    expect(session.owner.toBase58()).to.equal(alice.publicKey.toBase58());
    expect(session.contactHashes.length).to.equal(contacts.length);
    expect(session.status).to.equal(0); // Pending
    console.log("  ✓ Session initialized with", contacts.length, "hashed contacts");
    console.log("  ✓ Merkle root:", merkleRoot.toString("hex").slice(0, 16) + "...");
  });

  it("rejects invalid merkle root", async () => {
    const bob = Keypair.generate();
    const sig = await provider.connection.requestAirdrop(
      bob.publicKey,
      LAMPORTS_PER_SOL
    );
    await provider.connection.confirmTransaction(sig);

    const salt = randomBytes(16);
    const hashes = [hashContact(salt, "test@example.com")];
    const badRoot = randomBytes(32); // intentionally wrong
    const [sessionPda] = sessionPDA(program.programId, bob.publicKey);

    try {
      await program.methods
        .initSession(
          hashes.map((h) => Array.from(h)) as any,
          Array.from(badRoot) as any
        )
        .accounts({
          session: sessionPda,
          owner: bob.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([bob])
        .rpc();
      expect.fail("Should have thrown");
    } catch (e: any) {
      expect(e.message).to.include("InvalidMerkleRoot");
      console.log("  ✓ Correctly rejected invalid merkle root");
    }
  });

  it("rejects empty contact list", async () => {
    const bob = Keypair.generate();
    const sig = await provider.connection.requestAirdrop(
      bob.publicKey,
      LAMPORTS_PER_SOL
    );
    await provider.connection.confirmTransaction(sig);
    const [sessionPda] = sessionPDA(program.programId, bob.publicKey);

    try {
      await program.methods
        .initSession([], Array.from(Buffer.alloc(32)) as any)
        .accounts({
          session: sessionPda,
          owner: bob.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([bob])
        .rpc();
      expect.fail("Should have thrown");
    } catch (e: any) {
      expect(e.message).to.include("NoContacts");
      console.log("  ✓ Correctly rejected empty contact list");
    }
  });

  // ── PSI Result Submission ──

  it("submits PSI result (simulating Arcium MXE callback)", async () => {
    const [sessionPda] = sessionPDA(program.programId, alice.publicKey);
    const [verifierPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("arcium-verifier")],
      program.programId
    );

    // Simulate Arcium MXE returning the intersection
    const jobId = randomBytes(32);
    const matchedHashes = [aliceHashes[0], aliceHashes[2]]; // 2 out of 4 match

    // In production: Arcium MXE verifier signs and submits this
    await program.methods
      .submitPsiResult(
        Array.from(jobId) as any,
        matchedHashes.map((h) => Array.from(h)) as any
      )
      .accounts({
        session: sessionPda,
        arciumVerifier: verifierPda,
        authority: provider.wallet.publicKey,
      })
      .rpc();

    const session = await program.account.discoverySession.fetch(sessionPda);
    expect(session.status).to.equal(1); // Complete
    expect(session.matchedHashes.length).to.equal(2);
    console.log(
      "  ✓ PSI result submitted:",
      session.matchedHashes.length,
      "matches"
    );
    console.log("  ✓ Session status: Complete");
  });

  // ── Session Cleanup ──

  it("closes session and reclaims rent", async () => {
    const [sessionPda] = sessionPDA(program.programId, alice.publicKey);
    const balanceBefore = await provider.connection.getBalance(alice.publicKey);

    await program.methods
      .closeSession()
      .accounts({
        session: sessionPda,
        owner: alice.publicKey,
      })
      .signers([alice])
      .rpc();

    const balanceAfter = await provider.connection.getBalance(alice.publicKey);
    expect(balanceAfter).to.be.greaterThan(balanceBefore);
    console.log(
      "  ✓ Session closed, rent reclaimed:",
      (balanceAfter - balanceBefore) / LAMPORTS_PER_SOL,
      "SOL"
    );
  });

  // ── PSI Correctness (pure JS) ──

  it("verifies PSI logic off-chain", () => {
    const salt = Buffer.from("testSalt12345678");
    const contactsA = ["alice@x.com", "bob@x.com", "charlie@x.com", "dave@x.com"];
    const contactsB = ["bob@x.com", "charlie@x.com", "eve@x.com", "frank@x.com"];

    const hashesA = new Set(contactsA.map((c) => hashContact(salt, c).toString("hex")));
    const hashesB = new Set(contactsB.map((c) => hashContact(salt, c).toString("hex")));

    const intersection = [...hashesA].filter((h) => hashesB.has(h));
    expect(intersection.length).to.equal(2);
    console.log(
      "  ✓ PSI correctness: 2 mutual contacts found from (4 × 4) without revealing non-matches"
    );
  });
});
