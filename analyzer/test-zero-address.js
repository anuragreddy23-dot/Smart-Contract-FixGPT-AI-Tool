import { parseSolidity } from "./parsers/solidityParser.js";

const source = `
pragma solidity ^0.8.20;

contract VulnerableZeroAddress {
    address public owner;

    function setOwner(address newOwner) external {
        owner = newOwner;
    }
}
`;

const result = parseSolidity(source);

if (!result.success) {
    console.log("Parsing failed:");
    console.log(result.errors);
    process.exit(1);
}

const contract = result.ast.children.find(
    (node) => node.type === "ContractDefinition"
);

const fn = contract?.subNodes?.find(
    (node) =>
        node.type === "FunctionDefinition" &&
        node.name === "setOwner"
);

console.log("\n=== FUNCTION NODE ===\n");
console.log(JSON.stringify(fn, null, 2));