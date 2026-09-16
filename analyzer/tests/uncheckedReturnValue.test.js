import { analyzeSolidity } from "../analyzer.js";

const vulnerableContract = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableReturnValue {

    function sendEther(address payable user) external {
        user.call{value: 1 ether}("");
    }
}
`;

const secureContract = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecureReturnValue {

    function sendEther(address payable user) external {
        (bool success, ) = user.call{value: 1 ether}("");
        require(success, "Transfer failed");
    }
}
`;

console.log("=================================");
console.log("SCF-007 TEST");
console.log("=================================");

console.log("\nVULNERABLE CONTRACT\n");

const vulnerableResult =
  analyzeSolidity(vulnerableContract);

console.log(
  JSON.stringify(
    vulnerableResult.findings,
    null,
    2
  )
);

console.log(
  "\nSCF-007 findings:",
  vulnerableResult.findings.filter(
    (finding) =>
      finding.id === "SCF-007"
  ).length
);

console.log("\nSECURE CONTRACT\n");

const secureResult =
  analyzeSolidity(secureContract);

console.log(
  JSON.stringify(
    secureResult.findings,
    null,
    2
  )
);

console.log(
  "\nSCF-007 findings:",
  secureResult.findings.filter(
    (finding) =>
      finding.id === "SCF-007"
  ).length
);

console.log("\n=================================");
console.log("EXPECTED");
console.log("=================================");
console.log("Vulnerable: 1 SCF-007 finding");
console.log("Secure:     0 SCF-007 findings");