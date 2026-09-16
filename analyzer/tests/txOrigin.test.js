import { analyzeSolidity } from "../analyzer.js";

const vulnerableContract = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableTxOrigin {

    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function withdraw() external {
        require(
            tx.origin == owner,
            "Not owner"
        );

        payable(msg.sender).transfer(
            address(this).balance
        );
    }
}
`;

const secureContract = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecureTxOrigin {

    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function withdraw() external {
        require(
            msg.sender == owner,
            "Not owner"
        );

        payable(msg.sender).transfer(
            address(this).balance
        );
    }
}
`;

console.log("=================================");
console.log("SCF-008 TEST");
console.log("=================================");

console.log("\nVULNERABLE CONTRACT\n");

const vulnerableResult =
  analyzeSolidity(
    vulnerableContract
  );

console.log(
  JSON.stringify(
    vulnerableResult.findings,
    null,
    2
  )
);

console.log(
  "\nSCF-008 findings:",
  vulnerableResult.findings.filter(
    (finding) =>
      finding.id === "SCF-008"
  ).length
);

console.log("\nSECURE CONTRACT\n");

const secureResult =
  analyzeSolidity(
    secureContract
  );

console.log(
  JSON.stringify(
    secureResult.findings,
    null,
    2
  )
);

console.log(
  "\nSCF-008 findings:",
  secureResult.findings.filter(
    (finding) =>
      finding.id === "SCF-008"
  ).length
);

console.log("\n=================================");
console.log("EXPECTED");
console.log("=================================");
console.log("Vulnerable: 1 SCF-008 finding");
console.log("Secure:     0 SCF-008 findings");