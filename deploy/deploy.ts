import { DeployFunction } from "hardhat-deploy/types";
import { HardhatRuntimeEnvironment } from "hardhat/types";

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const { deployer } = await hre.getNamedAccounts();
  const { deploy } = hre.deployments;

  const deployedFHECharity = await deploy("Confidential", {
    from: deployer,
    log: true,
  });

  console.log(`Confidential contract: `, deployedFHECharity.address);
};
export default func;
func.id = "deploy_confidential"; // id required to prevent reexecution
func.tags = ["Confidential"];
