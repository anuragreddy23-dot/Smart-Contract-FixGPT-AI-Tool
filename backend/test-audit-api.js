async function main() {
  const response = await fetch("http://127.0.0.1:5000/api/audit", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      contractName: "VulnerableVault",
      solidityVersion: "0.8.20",
      sourceCode: `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);

        balances[msg.sender] = 0;
    }
}
`
    })
  });

  console.log("HTTP Status:", response.status);

  const data = await response.json();

  console.log(JSON.stringify(data, null, 2));
}

main().catch((error) => {
  console.error("Test failed:", error);
});