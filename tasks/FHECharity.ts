import { task } from "hardhat/config";
import type { TaskArguments } from "hardhat/types";
import { FhevmType } from "@fhevm/hardhat-plugin";

/* ------------------------------------------------ */
/* Address                                          */
/* ------------------------------------------------ */

task("demo:address", "Print deployed contract address").setAction(
  async (_: TaskArguments, hre) => {
    const deployment = await hre.deployments.get("FHECounter");
    console.log("Contract address:", deployment.address);
  }
);

/* ------------------------------------------------ */
/* Read encrypted state                              */
/* ------------------------------------------------ */

task("demo:read", "Decrypt and read encrypted counter")
  .addOptionalParam("address", "Contract address override")
  .setAction(async (args: TaskArguments, hre) => {
    const { ethers, deployments, fhevm } = hre;

    await fhevm.initializeCLIApi();

    const deployment = args.address
      ? { address: args.address }
      : await deployments.get("FHECounter");

    const [signer] = await ethers.getSigners();
    const contract = await ethers.getContractAt("FHECounter", deployment.address);

    const encryptedValue = await contract.getCount();

    if (encryptedValue === ethers.ZeroHash) {
      console.log("Encrypted value is zero");
      return;
    }

    const clear = await fhevm.userDecryptEuint(
      FhevmType.euint32,
      encryptedValue,
      deployment.address,
      signer
    );

    console.log("Encrypted:", encryptedValue);
    console.log("Decrypted:", clear.toString());
  });

/* ------------------------------------------------ */
/* Submit encrypted input                            */
/* ------------------------------------------------ */

task("demo:increment", "Increment using encrypted input")
  .addParam("value", "Increment value")
  .addOptionalParam("address", "Contract address override")
  .setAction(async (args: TaskArguments, hre) => {
    const { ethers, deployments, fhevm } = hre;

    const value = Number(args.value);
    if (!Number.isInteger(value)) {
      throw new Error("value must be an integer");
    }

    await fhevm.initializeCLIApi();

    const deployment = args.address
      ? { address: args.address }
      : await deployments.get("FHECounter");

    const [signer] = await ethers.getSigners();
    const contract = await ethers.getContractAt("FHECounter", deployment.address);

    const encryptedInput = await fhevm
      .createEncryptedInput(deployment.address, signer.address)
      .add32(value)
      .encrypt();

    const tx = await contract.increment(
      encryptedInput.handles[0],
      encryptedInput.inputProof
    );

    console.log("TX sent:", tx.hash);
    await tx.wait();
    console.log("Increment successful");
  });
