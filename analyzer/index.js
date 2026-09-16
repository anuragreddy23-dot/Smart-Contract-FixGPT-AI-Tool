import { analyzeSolidity } from "./analyzer.js";

const sourceCode = `
pragma solidity ^0.8.20;

contract VulnerableTest {

    address public owner;
    mapping(address => uint256) public balances;
    address[] public users;

    constructor() {
        owner = msg.sender;
    }

    function mint(uint256 amount) external {
        balances[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);

        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success);

        balances[msg.sender] -= amount;
    }

    function unsafeArithmetic(uint256 amount) external {
        unchecked {
            balances[msg.sender] -= amount;
        }
    }

    function processUsers() external {
        for (uint256 i = 0; i < users.length; i++) {
            // Processing
        }
    }

    function randomNumber() external view returns (uint256) {
        return uint256(
            keccak256(
                abi.encodePacked(
                    block.timestamp,
                    block.number
                )
            )
        );
    }
}
`;

console.log("========================================");
console.log("Smart Contract FixGPT");
console.log("Static Security Analyzer");
console.log("========================================");

const result = analyzeSolidity(sourceCode);

if (!result.success) {
    console.log("\n❌ Solidity parsing failed.");
    console.log(result.errors);
    process.exit(1);
}

console.log("\n✅ Solidity parsed successfully.");

console.log("\nContract Structure:");
console.log(JSON.stringify(result.contractStructure, null, 2));

console.log("\nSecurity Findings:");
console.log(JSON.stringify(result.findings, null, 2));

console.log(`\nTotal findings: ${result.findings.length}`);