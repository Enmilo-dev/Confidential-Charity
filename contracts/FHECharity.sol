// SPDX-License-Identifier: BSD 3-Clause Clear License
pragma solidity ^0.8.24;

// FHEVM core primitives
// - euint32 / ebool: encrypted integers and booleans
// - externalEuint32: encrypted input coming from off-chain client
import {FHE, euint8, euint32, ebool, externalEuint32} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";

/// @title Private Impact Charity (Demo)
/// @notice Demonstrates confidential fundraising logic using FHEVM v0.9
/// @dev This contract intentionally avoids real ETH transfers to prevent
///      privacy leakage and focuses purely on encrypted state transitions.
contract Confidential is ZamaEthereumConfig {
    /// @notice Represents a single fundraising campaign
    /// @dev All sensitive values (goal and total) are stored encrypted
    struct Campaign {
        uint256 id; // Campaign identifier
        address owner; // Campaign creator
        euint32 encryptedGoal; // Encrypted fundraising goal
        euint32 encryptedTotal; // Encrypted accumulated donations
        uint256 deadline; // Campaign end timestamp (plaintext)
        string metadataURI; // Off-chain metadata reference
        bool isActive; // Campaign activity flag
        bool finalized; // Finalization status
        bool withdrawAuthorized; // True only if goal is reached
        ebool encryptedGoalReached; // Encrypted result of (total >= goal)
    }

    /// @notice Incremental campaign counter
    uint256 public currentCampaignId;

    /// @notice Storage for all campaigns
    mapping(uint256 => Campaign) public campaigns;

    //EVENTS
    /// @notice Emitted when a new campaign is created
    event CampaignCreated(uint256 indexed campaignId, address indexed owner, uint256 deadline);

    /// @notice Emitted on every encrypted donation
    event DonationReceived(uint256 indexed campaignId, address indexed donor);

    /// @notice Signals that encrypted goal result can now be decrypted
    event FinalizeDecryptionAllowed(uint256 indexed campaignId);

    /// @notice Emitted after goal status is verified via signature
    event CampaignFinalized(uint256 indexed campaignId, bool goalReached);

    /// @notice Demo-only withdrawal authorization event (no ETH transfer)
    event WithdrawAuthorized(uint256 indexed campaignId, address indexed owner);

    //MODIFIERS
    /// @dev Restricts function to campaign owner
    modifier onlyCampaignOwner(uint256 campaignId) {
        require(msg.sender == campaigns[campaignId].owner, "Only campaign owner");
        _;
    }

    /// @dev Ensures campaign exists
    modifier campaignActive(uint256 campaignId) {
        require(campaigns[campaignId].isActive, "Campaign is not active");
        require(block.timestamp < campaigns[campaignId].deadline, "Campaign ended");
        _;
    }

    /// @dev Ensures campaign is active and before deadline
    modifier campaignExists(uint256 campaignId) {
        require(campaigns[campaignId].owner != address(0), "Invalid campaign");
        _;
    }

    //CONSTRUCTOR
    constructor() {
        currentCampaignId = 0;
    }

    //CAMPAIGN CREATION
    /// @notice Creates a new confidential fundraising campaign
    /// @param encryptedGoal Encrypted fundraising goal (provided off-chain)
    /// @param inputProof Proof for encrypted input correctness
    /// @param durationDays Campaign duration (1–365 days)
    /// @param metadataURI Off-chain metadata reference
    function createCampaign(
        externalEuint32 encryptedGoal,
        bytes calldata inputProof,
        uint256 durationDays,
        string calldata metadataURI
    ) external returns (uint256) {
        require(durationDays > 0 && durationDays <= 365, "Invalid duration! Please keep it under 365 days");

        currentCampaignId++;

        // Convert external encrypted input into on-chain encrypted value
        euint32 goal = FHE.fromExternal(encryptedGoal, inputProof);
        euint32 total = FHE.asEuint32(0);

        // Allow contract to operate on encrypted values
        FHE.allowThis(goal);
        FHE.allowThis(total);

        campaigns[currentCampaignId] = Campaign({
            id: currentCampaignId,
            owner: msg.sender,
            encryptedGoal: goal,
            encryptedTotal: total,
            deadline: block.timestamp + (durationDays * 1 days),
            metadataURI: metadataURI,
            isActive: true,
            finalized: false,
            withdrawAuthorized: false,
            encryptedGoalReached: FHE.asEbool(false)
        });

        emit CampaignCreated(currentCampaignId, msg.sender, campaigns[currentCampaignId].deadline);
        return currentCampaignId;
    }

    //DONATION
    /// @notice Adds an encrypted donation to a campaign
    /// @dev Donation amount is never revealed on-chain
    function donate(
        uint256 campaignId,
        externalEuint32 encryptedAmount,
        bytes calldata inputproof
    ) external campaignExists(campaignId) campaignActive(campaignId) {
        // Convert encrypted input into encrypted value
        euint32 amount = FHE.fromExternal(encryptedAmount, inputproof);

        Campaign storage campaign = campaigns[campaignId];

        // Homomorphically add donation to encrypted total
        campaign.encryptedTotal = FHE.add(campaign.encryptedTotal, amount);
        FHE.allowThis(campaign.encryptedTotal);

        emit DonationReceived(campaignId, msg.sender);
    }

    //FINALIZE (GOAL CHECK)
    /// @notice Step 1: Compute whether goal was reached (encrypted)
    /// @dev Result is stored encrypted and later decrypted via signature
    function allowFinalize(uint256 campaignId) external campaignExists(campaignId) onlyCampaignOwner(campaignId) {
        Campaign storage campaign = campaigns[campaignId];
        require(!campaign.finalized, "Already finalized");
        require(block.timestamp >= campaign.deadline, "Not ended");

        // Encrypted comparison: total >= goal
        ebool isReached = FHE.ge(campaign.encryptedTotal, campaign.encryptedGoal);

        campaign.encryptedGoalReached = isReached;
        FHE.allowThis(isReached);

        // Allow public decryption of encrypted boolean
        FHE.makePubliclyDecryptable(campaign.encryptedGoalReached);

        emit FinalizeDecryptionAllowed(campaignId);
    }

    /// @notice Step 2: Submit decryption of goal status
    function submitFinalize(
        uint256 campaignId,
        bool goalReached,
        bytes memory signature
    ) external campaignExists(campaignId) onlyCampaignOwner(campaignId) {
        Campaign storage campaign = campaigns[campaignId];
        require(!campaign.finalized, "Already finalized");

        bytes32[] memory handle = new bytes32[](1);
        handle[0] = FHE.toBytes32(campaign.encryptedGoalReached);

        bytes memory cleartext = abi.encode(goalReached);

        // Verify decrypted value against encrypted handle
        FHE.checkSignatures(handle, cleartext, signature);

        campaign.withdrawAuthorized = goalReached;

        campaign.isActive = false;
        campaign.finalized = true;
        emit CampaignFinalized(campaignId, goalReached);
    }

    /// @notice Demo-only withdrawal authorization
    /// @dev No ETH is transferred; event is used for off-chain handling
    function demoWithdraw(uint256 campaignId) external campaignExists(campaignId) onlyCampaignOwner(campaignId) {
        Campaign storage campaign = campaigns[campaignId];

        require(campaign.finalized, "Campaign not finalized");
        require(campaign.withdrawAuthorized, "Withdraw not authorized");

        emit WithdrawAuthorized(campaignId, campaign.owner);
    }
}
