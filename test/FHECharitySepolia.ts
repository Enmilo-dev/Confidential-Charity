import { expect } from "chai";
import { ethers, fhevm } from "hardhat";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import type { Confidential } from "../types";

async function mineBlock() {
  await ethers.provider.send("evm_mine", []);
}

describe("Confidential Charity", function () {
  let confidential: Confidential;
  let owner: HardhatEthersSigner;
  let alice: HardhatEthersSigner; // Donor
  let bob: HardhatEthersSigner;   // Observer

  const GOAL_AMOUNT = 1000;
  const DONATION_AMOUNT = 1500;
  const DURATION_DAYS = 1;

  beforeEach(async function () {
    // 1. Enforce Mock Environment (matching your example)
    if (!fhevm.isMock) {
      console.log("This test requires FHEVM mock environment");
      this.skip();
    }

    [owner, alice, bob] = await ethers.getSigners();

    // 2. Deploy Contract
    const ConfidentialFactory = await ethers.getContractFactory("Confidential");
    confidential = await ConfidentialFactory.deploy();
    await confidential.waitForDeployment();

    console.log("Setup complete. Contract deployed at:", await confidential.getAddress());
  });

  describe("Campaign Creation", function () {
    it("should allow creating a campaign with encrypted goal", async function () {
      const contractAddr = await confidential.getAddress();

      // Encrypt Goal (Alice/Owner)
      // Note: Must use .add32() because contract expects externalEuint32
      const encryptedGoal = await fhevm
        .createEncryptedInput(contractAddr, owner.address)
        .add32(GOAL_AMOUNT)
        .encrypt();

      await confidential.createCampaign(
        encryptedGoal.handles[0],
        encryptedGoal.inputProof,
        DURATION_DAYS,
        "ipfs://metadata"
      );
      await mineBlock();

      const campaign = await confidential.campaigns(1);
      expect(campaign.owner).to.equal(owner.address);
      expect(campaign.isActive).to.equal(true);
      
      console.log("Campaign created successfully");
    });
  });

  describe("Donation Logic", function () {
    // Setup a campaign before each donation test
    beforeEach(async function () {
      const contractAddr = await confidential.getAddress();
      const encryptedGoal = await fhevm
        .createEncryptedInput(contractAddr, owner.address)
        .add32(GOAL_AMOUNT)
        .encrypt();

      await confidential.createCampaign(
        encryptedGoal.handles[0],
        encryptedGoal.inputProof,
        DURATION_DAYS,
        "ipfs://metadata"
      );
      await mineBlock();
    });

    it("should accept encrypted donations", async function () {
      const contractAddr = await confidential.getAddress();
      const campaignId = 1;

      // Encrypt Donation (Alice)
      const encryptedDonation = await fhevm
        .createEncryptedInput(contractAddr, alice.address)
        .add32(DONATION_AMOUNT)
        .encrypt();

      await confidential.connect(alice).donate(
        campaignId,
        encryptedDonation.handles[0],
        encryptedDonation.inputProof
      );
      await mineBlock();

      // Verification: In Mock mode, we can debug/decrypt the total
      // This is a "cheat" available only in tests to verify logic
      const campaign = await confidential.campaigns(campaignId);
      const totalHandle = campaign.encryptedTotal;
      
      // Decrypt locally to verify math worked (Mock Feature)
      // Note: This requires the specific mock decryption utility if available, 
      // or we trust the transaction didn't revert.
      console.log("Donation processed encrypted");
    });
  });

  describe("Finalization (Mock Limitation)", function () {
    // ... setup campaign & donation ...
    beforeEach(async function () {
      const contractAddr = await confidential.getAddress();
      
      // Create
      const encryptedGoal = await fhevm.createEncryptedInput(contractAddr, owner.address).add32(GOAL_AMOUNT).encrypt();
      await confidential.createCampaign(encryptedGoal.handles[0], encryptedGoal.inputProof, DURATION_DAYS, "meta");
      
      // Donate
      const encryptedDonation = await fhevm.createEncryptedInput(contractAddr, alice.address).add32(DONATION_AMOUNT).encrypt();
      await confidential.connect(alice).donate(1, encryptedDonation.handles[0], encryptedDonation.inputProof);
      await mineBlock();
    });

    it("should allow requesting finalization", async function () {
        // Fast forward time to pass deadline
        // Helper to increase time in Hardhat Network
        await ethers.provider.send("evm_increaseTime", [86400 * 2]); // +2 days
        await mineBlock();

        await expect(confidential.connect(owner).allowFinalize(1))
            .to.emit(confidential, "FinalizeDecryptionAllowed")
            .withArgs(1);
        
        console.log("Finalization allowed (Decryption requested)");
    });

    // NOTE: The 'submitFinalize' step requires a valid cryptographic signature 
    // from the Zama Gateway. In pure Mock mode, 'FHE.checkSignatures' will 
    // revert unless you have the full Gateway Mock setup. 
  });
});
