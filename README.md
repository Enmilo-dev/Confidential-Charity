# Private Impact Charity: A Technical Reference Implementation for FHEVM v0.9

## Table of Contents
1. [High-Level Overview](#high-level-overview)
2. [Why FHEVM v0.9](#why-fhevm-v09)
3. [Threat Model & Privacy Guarantees](#threat-model--privacy-guarantees)
4. [Core Design Decisions](#core-design-decisions)
5. [Function-by-Function Walkthrough](#function-by-function-walkthrough)
6. [Why Progress Reveal Is Omitted](#why-progress-reveal-is-omitted)
7. [Demo Withdraw Model](#demo-withdraw-model)
8. [Security Considerations](#security-considerations)
9. [Why This Is a Reference Implementation](#why-this-is-a-reference-implementation)

---

## High-Level Overview

### The Problem
Traditional fundraising on Ethereum exposes every donation amount, total raised, and goal status in plaintext. This creates several problems:

1. **Donor privacy**: Anyone can trace which addresses donated how much
2. **Goal gaming**: If a campaign is close to its goal, strategic donors can manipulate perception by withholding or flooding donations at the last moment
3. **Competitive intelligence**: Rival campaigns can monitor progress and adjust their strategy accordingly
4. **Psychological effects**: Campaigns far from their goal may discourage further participation

### Why Traditional Ethereum Cannot Solve This
Ethereum's execution model is fundamentally transparent. Every state transition must be:
- Verifiable by all validators
- Reproducible from transaction inputs
- Stored in plaintext on-chain

Standard encryption approaches fail because:
- **Symmetric encryption**: Contract cannot hold private keys without exposure
- **Asymmetric encryption**: Cannot perform arithmetic on ciphertexts (cannot add donations)
- **Zero-knowledge proofs**: Can prove statements about hidden values but cannot maintain encrypted state across multiple transactions

### Why Fully Homomorphic Encryption Is Required
Fully Homomorphic Encryption (FHE) allows computation on encrypted data without decryption. This contract requires:

1. **Addition**: Accumulating donations while keeping amounts hidden
2. **Comparison**: Checking if total ≥ goal without revealing either value
3. **Persistent encrypted state**: Maintaining `encryptedTotal` across multiple transactions
4. **Selective disclosure**: Only revealing goal status at campaign end

FHE is the only cryptographic primitive that provides all four properties simultaneously.

---

## Why FHEVM v0.9

### Self-Relaying Architecture
FHEVM v0.9 uses a "self-relaying" model where:
- Encrypted values never exist in plaintext on-chain
- Homomorphic operations occur in a separate FHE coprocessor
- Results are re-encrypted and returned to the EVM
- Decryption requires cryptographic permission and off-chain signature verification

This differs from older FHE schemes that attempted to perform homomorphic operations directly in the EVM.

### Why `externalEuint32` Is Used
The type `externalEuint32` represents an encrypted value created off-chain by a user's client. The workflow is:

1. User encrypts their value locally using the network's public key
2. User submits ciphertext + zero-knowledge proof of correctness
3. Contract calls `FHE.fromExternal()` to convert external ciphertext into on-chain `euint32`
4. The proof prevents malformed ciphertexts from corrupting contract state

**Why this matters**: Without `externalEuint32`, users could submit arbitrary ciphertexts that decrypt to values they don't actually possess (e.g., donating encrypted "1 million" when they only hold 1 token).

### Why Encrypted Values Must Be Explicitly Allowed
The line `FHE.allowThis(goal)` grants this contract permission to operate on the encrypted value. FHEVM's permission model works as follows:

- Each encrypted value has an access control list (ACL)
- Only addresses in the ACL can perform operations on that ciphertext
- `FHE.allowThis()` adds `address(this)` to the ACL
- Without this, `FHE.add()` or `FHE.ge()` would revert

**Security rationale**: Prevents malicious contracts from operating on encrypted values they shouldn't access. Even though the contract cannot decrypt the value, homomorphic operations could still leak information through side channels.

### Why Decryption Is Permissioned and Delayed
Decryption in FHEVM occurs through a two-phase protocol:

1. **Request phase**: Contract calls `FHE.makePubliclyDecryptable()` to mark a ciphertext for decryption
2. **Signature phase**: Off-chain relayers decrypt the value and produce a signature proving correctness
3. **Verification phase**: Contract calls `FHE.checkSignatures()` to verify the decrypted value matches the encrypted handle

**Why delayed**: Immediate decryption would require synchronous communication with the FHE coprocessor, breaking the EVM's deterministic execution model.

**Why signed**: Prevents anyone from submitting false decryptions. The signature cryptographically binds the plaintext to the encrypted handle.

---

## Threat Model & Privacy Guarantees

### What Information Is Hidden
1. **Campaign goal**: Only the creator knows the fundraising target
2. **Donation amounts**: Each individual contribution is encrypted
3. **Running total**: No one can observe how close the campaign is to its goal during the campaign
4. **Goal status during campaign**: Even comparative information (e.g., "50% funded") is unavailable

### What Information Is Intentionally Public
1. **Campaign existence**: The fact that campaign N exists is public
2. **Campaign owner**: Address that created the campaign
3. **Deadline**: Campaign end time (required for trustless finalization)
4. **Donor identity**: Addresses that called `donate()` are visible
5. **Number of donations**: Observable through `DonationReceived` events
6. **Final goal status**: Whether the goal was reached (revealed only after deadline)

### Why ETH Is Not Used
This contract does not handle actual ETH transfers for a critical reason: **transfer amounts would appear in plaintext**.

If the contract used `msg.value`:
```solidity
function donate(uint256 campaignId) external payable {
    // msg.value is visible to everyone → privacy leak
}
```

Even if we stored an encrypted record, the plaintext `msg.value` on the transaction would reveal the donation amount.

**Alternative approaches**:
- Use an encrypted ERC20 token where balances are encrypted (future work)
- Handle ETH in a separate escrow contract that only knows campaign IDs, not amounts (adds complexity)
- Off-chain settlement where this contract only authorizes withdrawals (this contract's approach)

### What an Observer Cannot Infer
An observer monitoring all transactions cannot determine:

1. **Campaign viability**: Whether a campaign is likely to succeed
2. **Donation distribution**: Whether donations are concentrated or distributed
3. **Strategic timing**: Whether late donations were attempting to push the campaign over the goal
4. **Donor wealth**: Cannot correlate donation amounts with donor addresses

The only information leaked is behavioral metadata (who donated, when), which is unavoidable in a public blockchain without full anonymity (e.g., Zcash-style shielded pools).

---

## Core Design Decisions

### 1. Encrypted Goals and Totals

**What is done**:
```solidity
euint32 encryptedGoal;
euint32 encryptedTotal;
```

**Why it is done**:
- `encryptedGoal`: Prevents strategic donors from knowing the exact target
- `encryptedTotal`: Hides progress to avoid discouragement or gaming

**What would break if done differently**:
- **Plaintext goal**: Donors could wait until the campaign is near its goal, then donate just enough to claim credit for success
- **Plaintext total**: The "Kickstarter effect" where stalled campaigns become self-fulfilling failures

### 2. Encrypted Comparison (`FHE.ge`)

**What is done**:
```solidity
ebool isReached = FHE.ge(campaign.encryptedTotal, campaign.encryptedGoal);
```

**Why it is done**:
- Compares two encrypted values homomorphically
- Result is also encrypted (`ebool`)
- No intermediate plaintext values exist

**How it works**:
- `FHE.ge(a, b)` performs greater-or-equal comparison on ciphertexts
- Returns encrypted boolean (ebool)
- Implementation uses TFHE bitwise comparison circuits

**What would break if done differently**:
- **Decrypt first, then compare**: Would reveal both goal and total
- **Reveal total only**: Would allow reverse-engineering the goal through multiple test campaigns
- **Approximate comparison**: Could leak information through error bounds

### 3. Boolean Decryption Workflow

**What is done**:
```solidity
FHE.makePubliclyDecryptable(campaign.encryptedGoalReached);
```

**Why it is done**:
- Marks the encrypted boolean for decryption by the network
- Allows relayers to generate a proof without revealing other encrypted values
- Minimizes information disclosure (only 1 bit: goal reached yes/no)

**What would break if done differently**:
- **Decrypt total**: Would reveal exact amount raised
- **Decrypt both total and goal**: Would reveal complete financial data
- **No decryption**: Campaign owner could never prove goal was reached

**Why only the boolean**:
The boolean represents the minimum information needed to decide fund release. Revealing more would violate privacy without adding utility.

### 4. Two-Phase Finalize

**What is done**:
```solidity
// Phase 1: Compute encrypted result
function allowFinalize(uint256 campaignId) external {
    ebool isReached = FHE.ge(campaign.encryptedTotal, campaign.encryptedGoal);
    FHE.makePubliclyDecryptable(campaign.encryptedGoalReached);
    emit FinalizeDecryptionAllowed(campaignId);
}

// Phase 2: Submit decrypted result
function submitFinalize(uint256 campaignId, bool goalReached, bytes memory signature) external {
    FHE.checkSignatures(handle, cleartext, signature);
    campaign.withdrawAuthorized = goalReached;
}
```

**Why it is done**:
- **Phase 1**: Triggers off-chain decryption process
- **Phase 2**: Verifies and commits the decrypted result

**What would break if done differently**:
- **Single transaction**: Impossible due to asynchronous decryption
- **No signature verification**: Anyone could submit false results
- **Automatic decryption**: Would require trust in a centralized oracle

**Security properties**:
1. Only values marked with `makePubliclyDecryptable` can be decrypted
2. Decryption signature cryptographically binds plaintext to ciphertext
3. Contract verifies signature before accepting the result
4. Owner cannot selectively discard unfavorable results (decryption is deterministic)

---

## Function-by-Function Walkthrough

### `createCampaign`

**Purpose**: Initializes a new confidential fundraising campaign.

**Inputs**:
- `externalEuint32 encryptedGoal`: Creator's encrypted fundraising target
- `bytes calldata inputProof`: Zero-knowledge proof that the encrypted goal is well-formed
- `uint256 durationDays`: Campaign length (1-365 days)
- `string calldata metadataURI`: Off-chain reference for campaign description

**Cryptographic operations**:
```solidity
euint32 goal = FHE.fromExternal(encryptedGoal, inputProof);
```
- Verifies the ZK proof
- Converts external ciphertext to internal encrypted type
- Prevents malicious actors from submitting invalid ciphertexts

```solidity
euint32 total = FHE.asEuint32(0);
```
- Creates an encrypted zero
- Initializes the donation accumulator

```solidity
FHE.allowThis(goal);
FHE.allowThis(total);
```
- Grants this contract permission to operate on these ciphertexts
- Required for future `FHE.add()` and `FHE.ge()` operations

**Why permission checks exist**:
- No special permission checks here (anyone can create a campaign)
- In a production system, might add stake requirements or identity verification

**How FHE safety is preserved**:
- Goal never decrypted until campaign ends
- Initial total is provably zero (no hidden starting balance)

---

### `donate`

**Purpose**: Adds an encrypted donation to a campaign's running total.

**Inputs**:
- `uint256 campaignId`: Target campaign
- `externalEuint32 encryptedAmount`: Donor's encrypted contribution
- `bytes calldata inputproof`: Proof of valid encryption

**Cryptographic operations**:
```solidity
euint32 amount = FHE.fromExternal(encryptedAmount, inputproof);
campaign.encryptedTotal = FHE.add(campaign.encryptedTotal, amount);
```
- Verifies donation amount is correctly encrypted
- Performs homomorphic addition on ciphertexts
- Result is a new ciphertext representing the sum

**Why permission checks exist**:
- `campaignExists`: Prevents donations to non-existent campaigns
- `campaignActive`: Ensures campaign is open and not expired
- No donor whitelist (anyone can donate)

**How FHE safety is preserved**:
```solidity
FHE.allowThis(campaign.encryptedTotal);
```
- Updates ACL for the new ciphertext
- Without this, future operations on `encryptedTotal` would fail

**What this function does NOT do**:
- Does not transfer actual tokens (demo-only contract)
- Does not validate minimum donation amounts (would require encrypted comparison)
- Does not prevent donation overflow (32-bit limit)

---

### `allowFinalize`

**Purpose**: Initiates the decryption process for goal status.

**Inputs**:
- `uint256 campaignId`: Campaign to finalize

**Cryptographic operations**:
```solidity
ebool isReached = FHE.ge(campaign.encryptedTotal, campaign.encryptedGoal);
```
- Performs homomorphic greater-or-equal comparison
- Returns encrypted boolean (true if total ≥ goal, false otherwise)

```solidity
FHE.makePubliclyDecryptable(campaign.encryptedGoalReached);
```
- Marks this specific `ebool` for decryption
- Relayers can now decrypt this value and generate a signature
- Does NOT decrypt other encrypted values (goal and total remain hidden)

**Why permission checks exist**:
- `onlyCampaignOwner`: Only creator can initiate finalization
- `!campaign.finalized`: Prevents double-finalization
- `block.timestamp >= campaign.deadline`: Ensures campaign has ended

**How FHE safety is preserved**:
- Only the boolean result is marked for decryption
- Goal and total remain encrypted forever
- Even the campaign owner cannot force decryption of the actual amounts

**Timing considerations**:
- Must be called after deadline (trustless trigger)
- Must be called before `submitFinalize` (two-phase requirement)
- Gas cost is modest (mostly memory operations)

---

### `submitFinalize`

**Purpose**: Verifies and commits the decrypted goal status.

**Inputs**:
- `uint256 campaignId`: Campaign being finalized
- `bool goalReached`: Plaintext decryption result
- `bytes memory signature`: Cryptographic proof of correct decryption

**Cryptographic operations**:
```solidity
bytes32[] memory handle = new bytes32[](1);
handle[0] = FHE.toBytes32(campaign.encryptedGoalReached);
bytes memory cleartext = abi.encode(goalReached);
FHE.checkSignatures(handle, cleartext, signature);
```

**What `checkSignatures` does**:
1. Extracts the encrypted handle (ciphertext identifier)
2. Verifies the signature was produced by an authorized relayer
3. Confirms the signature binds this specific `goalReached` value to this specific ciphertext
4. Reverts if signature is invalid or mismatched

**Why permission checks exist**:
- `onlyCampaignOwner`: Only creator can submit the result (though anyone could in theory)
- `!campaign.finalized`: Prevents result from being changed after commitment

**Why anyone can submit decrypted data safely**:
- The signature verification ensures correctness
- A malicious actor cannot submit `goalReached = true` if the encrypted comparison yielded `false`
- The cryptographic binding between ciphertext and plaintext is unforgeable

**Result of successful verification**:
```solidity
campaign.withdrawAuthorized = goalReached;
campaign.isActive = false;
campaign.finalized = true;
```
- Campaign is permanently closed
- Withdrawal is authorized only if goal was reached
- No further modifications possible

---

### `demoWithdraw`

**Purpose**: Demonstrates withdrawal authorization without handling real funds.

**Inputs**:
- `uint256 campaignId`: Campaign to withdraw from

**Cryptographic operations**: None (plaintext-only function).

**Why permission checks exist**:
- `onlyCampaignOwner`: Only creator can withdraw
- `campaign.finalized`: Ensures goal status has been verified
- `campaign.withdrawAuthorized`: Only succeeds if goal was reached

**What this function does**:
```solidity
emit WithdrawAuthorized(campaignId, campaign.owner);
```
- Emits an event signaling withdrawal permission
- Off-chain systems can observe this event and release funds
- No ETH transfer occurs on-chain

**Why this pattern is used**: See [Demo Withdraw Model](#demo-withdraw-model) below.

---

## Why Progress Reveal Is Omitted

### The Temptation of Progress Bars
Many fundraising platforms show real-time progress (e.g., "75% funded"). This is not implemented here.

### Why Partial Reveals Weaken Privacy

**Scenario 1: Strategic exploitation**
If `getCurrentPercentage()` returned `encryptedTotal / encryptedGoal`:
- The result would be a 32-bit encrypted fraction
- Decrypting periodically would reveal the rate of change
- Donors could infer optimal donation timing

**Scenario 2: Statistical attacks**
If progress were revealed at fixed intervals:
- An observer could correlate donations with progress changes
- By creating multiple test campaigns with known goals, an attacker could reverse-engineer the function
- Over many campaigns, this would leak goal distributions

**Scenario 3: Psychological manipulation**
- Revealing that a campaign is at "99% of goal" creates enormous pressure for a final push
- Conversely, "1% funded" discourages participation
- The encrypted approach removes this gamification

### Why Only Final Boolean Disclosure Is Safer
A single bit of information (goal reached: yes/no) leaked at the end reveals:
- Almost nothing about the total raised (only an inequality)
- Nothing about individual donations
- Nothing about the goal magnitude

**Information theory perspective**:
- Progress reveal: Continuous information leakage over time
- Final boolean: Single bit revealed at conclusion
- The difference is exponential in entropy terms

### Trade-Offs Between UX and Cryptographic Integrity
This contract prioritizes cryptographic soundness over user experience. A production system might:
- Allow voluntary progress disclosure by the campaign owner
- Use secure multi-party computation to reveal statistical aggregates
- Implement differential privacy to add noise to progress reports

However, each of these introduces complexity and potential vulnerabilities. For a reference implementation, simplicity is preferred.

---

## Demo Withdraw Model

### Why This Contract Does Not Transfer ETH

**Problem**: ETH transfers require plaintext amounts.

```solidity
// This would defeat the purpose
payable(owner).transfer(plaintextAmount); // ← Privacy leak
```

Even if we maintained encrypted records internally, the actual transfer reveals the amount in the transaction data.

### Why Emitting Authorization Events Is Safer

**The pattern used**:
```solidity
emit WithdrawAuthorized(campaignId, campaign.owner);
```

**How this works**:
1. Contract cryptographically proves goal was reached
2. Contract emits authorization event
3. Off-chain system (exchange, escrow service, Layer 2) observes event
4. Off-chain system releases funds to campaign owner
5. Real amounts never touch the encrypted contract

**Benefits**:
- Full privacy on-chain
- Flexible settlement mechanisms
- No smart contract holds funds (reduced attack surface)
- Compatible with future encrypted token standards

### How This Pattern Avoids On-Chain Financial Leakage

**Separation of concerns**:
- **On-chain**: Cryptographic proof of goal achievement
- **Off-chain**: Actual fund transfer

**Trust model**:
- Donors deposit funds into an escrow (custodial exchange, L2, multisig)
- Escrow trusts this contract to determine goal status
- No need for the contract to touch funds directly

**Future integration**:
Once FHEVM-compatible encrypted ERC20 tokens exist:
```solidity
// Hypothetical future code
encryptedToken.transfer(campaign.owner, campaign.encryptedTotal);
```
This would enable fully on-chain settlement with preserved privacy.

---

## Security Considerations

### 1. Replay Protection

**Issue**: Could an attacker reuse a signature from a previous finalization?

**Mitigation**:
```solidity
bytes32[] memory handle = new bytes32[](1);
handle[0] = FHE.toBytes32(campaign.encryptedGoalReached);
```
The signature is bound to the specific `encryptedGoalReached` ciphertext, which is unique per campaign. Replaying a signature from Campaign A on Campaign B will fail because the encrypted handles differ.

**Additional safety**:
```solidity
require(!campaign.finalized, "Already finalized");
```
Prevents re-finalization of the same campaign.

### 2. Decryption Abuse Prevention

**Issue**: Could a malicious relayer selectively decrypt and only submit favorable results?

**Mitigation**:
- Decryption is deterministic (same ciphertext always decrypts to the same plaintext)
- Once `makePubliclyDecryptable` is called, anyone can request decryption from the network
- Multiple independent relayers can verify the result
- If a relayer submits an incorrect `goalReached` value, `checkSignatures` will revert

**Consequence**: Campaign owner cannot censor unfavorable results. If the goal was not reached, no valid signature for `goalReached = true` exists.

### 3. Unauthorized Finalize Prevention

**Issue**: Could someone finalize a campaign prematurely or without permission?

**Mitigation**:
```solidity
modifier onlyCampaignOwner(uint256 campaignId) {
    require(msg.sender == campaigns[campaignId].owner, "Only campaign owner");
    _;
}

require(block.timestamp >= campaign.deadline, "Not ended");
```

**Rationale**: Only the campaign owner can initiate finalization, and only after the deadline. This prevents:
- Front-running by competitors
- Premature closure during an active campaign
- Griefing attacks

**Alternative design**: Allow anyone to call `allowFinalize` after the deadline. This would be trustless but might incur gas costs for public goods. The current design leaves this decision to the campaign owner.

### 4. Why Anyone Can Submit Decrypted Data Safely

**Issue**: If `submitFinalize` were permissionless, couldn't an attacker submit false data?

**Mitigation**:
```solidity
FHE.checkSignatures(handle, cleartext, signature);
```
The signature verification ensures that only the correct decryption can be submitted. An attacker without a valid signature cannot change the result.

**Design choice**: Currently `onlyCampaignOwner` is enforced, but this could be relaxed to allow any address with a valid signature to submit. The owner modifier is a conservative choice that prevents potential griefing (e.g., an attacker submitting many failed attempts to burn the owner's gas).

### 5. Front-Running and MEV Considerations

**Issue**: Can a block proposer see donations in the mempool and front-run?

**Analysis**:
- Transaction data contains ciphertexts, which are semantically secure
- Proposer cannot decrypt the amount
- Proposer can observe *that* a donation occurred and the donor's address
- Proposer cannot reorder donations to influence goal status (finalization is after deadline)

**Residual risk**: Timing-based MEV (e.g., a proposer delaying a donation to the next block). This is a general blockchain problem not specific to FHE.

### 6. Ciphertext Overflow

**Issue**: `euint32` has a maximum value of 2^32 - 1. What if donations exceed this?

**Current behavior**: Homomorphic addition modulo 2^32. If overflow occurs, the total wraps around.

**Impact**: Campaigns with extremely high donation volumes could overflow, causing incorrect goal comparisons.

**Mitigation strategies** (not implemented, for simplicity):
- Use `euint64` for larger campaigns
- Add overflow detection (difficult with encrypted values)
- Cap donations at creation time

For a demo contract, this is acceptable. Production systems should assess expected donation volumes and choose appropriate bit widths.

---
## Why This Is a Reference Implementation

### Why This Contract Is Intentionally Minimal

**Design philosophy**: This contract demonstrates core FHEVM primitives without extraneous features.

**What is omitted**:
- Refunds (would require encrypted balance tracking per donor)
- Partial withdrawals (would reveal amounts)
- Campaign updates (changing goal would complicate privacy model)
- Multi-token support (adds contract complexity)
- Governance (out of scope)

**Why these omissions matter**: Each additional feature would require careful cryptographic analysis. By stripping to essentials, this contract serves as a clear teaching example.

### What Future Developers Can Build on Top of It

**Composable privacy primitives**:
```solidity
// Example: Campaign marketplace
contract Marketplace {
    Confidential charityContract;
    
    function recommendCampaign(address user) external view returns (uint256) {
        // Uses encrypted goal data without accessing plaintext
    }
}
```

**Possible extensions**:
1. **Encrypted voting**: Replace "donations" with "votes", compare against encrypted quorum
2. **Sealed-bid auctions**: Replace "goal" with "highest bid", compare bids homomorphically
3. **Private allocations**: Use this as a building block for confidential grants

**Integration patterns**:
```solidity
// Hypothetical: Encrypted ERC20 integration
import {EncryptedERC20} from "fhevm-erc20";

contract PrivateCharity is Confidential {
    EncryptedERC20 public donationToken;
    
    function donateToken(uint256 campaignId, externalEuint32 amount, bytes calldata proof) external {
        // Transfer encrypted amount from donor to contract
        donationToken.encryptedTransferFrom(msg.sender, address(this), amount, proof);
        
        // Add to campaign (same logic as current donate function)
        campaigns[campaignId].encryptedTotal = FHE.add(campaigns[campaignId].encryptedTotal, amount);
    }
}
```

### Why Simplicity Improves Auditability in FHE Systems

**Cryptographic complexity**:
FHE is already complex. Each homomorphic operation has:
- Gas costs (higher than plaintext equivalents)
- Security assumptions (ciphertext leakage risks)
- Correctness requirements (proof verification)

**Audit surface**:
A simple contract with 5 functions and 2 encrypted operations is auditable. A complex contract with 20 functions and 50 encrypted operations is exponentially harder to verify.

**Formal verification**:
This contract's logic could be formally verified:
```
∀ campaignId: 
  (encryptedTotal >= encryptedGoal) ⟺ (goalReached = true after finalization)
```

Adding features would require additional proofs.

**Security invariants**:
This contract maintains:
1. Goal is never decrypted before finalization
2. Total is never decrypted at all
3. Only authorized decryptions occur
4. Finalization is deterministic

Each additional feature risks violating an invariant.

### Learning Path for Developers

**Recommended study order**:
1. Understand this contract (encrypted state + comparison + decryption)
2. Study FHEVM ERC20 (encrypted balances + transfers)
3. Study FHEVM NFT privacy (encrypted metadata)
4. Build domain-specific applications

**Key concepts demonstrated**:
- `externalEuint32` input handling
- Homomorphic arithmetic (`FHE.add`)
- Homomorphic comparison (`FHE.ge`)
- Permission management (`FHE.allowThis`)
- Decryption workflow (`makePubliclyDecryptable` + `checkSignatures`)

**Next steps**:
- Implement encrypted refunds (requires donor tracking)
- Add encrypted minimum donation threshold
- Create multi-campaign coordination logic
- Build UI with client-side encryption

---

## Conclusion

This contract represents a foundational pattern for confidential state machines on FHEVM. By separating cryptographic primitives (encrypted arithmetic, comparison, controlled decryption) from application logic, it provides a reusable template for privacy-preserving smart contracts.

The design prioritizes:
- **Correctness**: Cryptographic operations are used as intended
- **Minimalism**: No unnecessary features
- **Clarity**: Code structure mirrors the FHE workflow
- **Security**: Conservative permission model

For production use, developers should:
- Assess gas costs for expected usage patterns
- Integrate with encrypted token standards
- Add application-specific features carefully
- Conduct thorough security audits

This contract is not a product—it is a pedagogical reference. Its value lies in demonstrating how FHE can be applied to a familiar use case (fundraising) in a way that illuminates the underlying architecture.

**Further Reading**:
- [FHEVM Documentation](https://docs.zama.org/protocol)
- [Migrate to v0.9](https://docs.zama.org/protocol/solidity-guides/development-guide/migration)

**Contract Address**: To be deployed on Zama devnet  
**License**: BSD 3-Clause Clear License 
**Version**: FHEVM v0.9
