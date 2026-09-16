export function extractContractStructure(ast) {
  const contracts = [];

  if (!ast || !Array.isArray(ast.children)) {
    return contracts;
  }

  for (const node of ast.children) {
    if (node.type !== "ContractDefinition") {
      continue;
    }

    const functions = [];

    for (const subNode of node.subNodes || []) {
      if (subNode.type !== "FunctionDefinition") {
        continue;
      }

      let functionName = subNode.name || "fallback/receive";
      let functionType = "function";

      // Solidity parser represents constructors as FunctionDefinition
      if (subNode.isConstructor === true) {
        functionName = "constructor";
        functionType = "constructor";
      }

      functions.push({
        name: functionName,
        type: functionType,
        visibility: subNode.visibility || "unknown",
        stateMutability: subNode.stateMutability || "nonpayable",
        line: subNode.loc?.start?.line || 0
      });
    }

    contracts.push({
      name: node.name,
      kind: node.kind,
      line: node.loc?.start?.line || 0,
      functions
    });
  }

  return contracts;
}