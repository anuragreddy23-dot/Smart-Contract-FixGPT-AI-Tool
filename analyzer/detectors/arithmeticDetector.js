function containsArithmeticOperation(node) {
  if (!node) {
    return false;
  }

  const text = JSON.stringify(node);

  return (
    text.includes('"type":"BinaryOperation"') &&
    (
      text.includes('"operator":"+"') ||
      text.includes('"operator":"-"') ||
      text.includes('"operator":"*"') ||
      text.includes('"operator":"/"') ||
      text.includes('"operator":"%"') ||
      text.includes('"operator":"+="') ||
      text.includes('"operator":"-="') ||
      text.includes('"operator":"*="') ||
      text.includes('"/="')
    )
  );
}

function containsUncheckedBlock(node) {
  if (!node) {
    return false;
  }

  const text = JSON.stringify(node);

  return text.includes('"type":"UncheckedStatement"');
}

export function detectArithmetic(ast) {
  const findings = [];

  if (!ast || !Array.isArray(ast.children)) {
    return findings;
  }

  for (const contract of ast.children) {
    if (contract.type !== "ContractDefinition") {
      continue;
    }

    for (const node of contract.subNodes || []) {
      if (node.type !== "FunctionDefinition") {
        continue;
      }

      const functionName =
        node.name || "fallback/receive";

      if (!containsUncheckedBlock(node)) {
        continue;
      }

      if (!containsArithmeticOperation(node)) {
        continue;
      }

      findings.push({
        id: "SCF-003",
        title: "Unchecked Arithmetic Operation",
        severity: "Medium",
        confidence: "High",
        category: "Arithmetic",
        contractName: contract.name,
        functionName,
        lineNumber: node.loc?.start?.line || 0,
        description:
          "The function performs arithmetic inside an unchecked block. Solidity will not automatically revert if the arithmetic operation overflows or underflows.",
        impact:
          "An attacker or unexpected input may cause an integer overflow or underflow, potentially resulting in incorrect balances, accounting errors, or loss of funds.",
        recommendation:
          "Avoid unchecked arithmetic unless the operation is proven safe. Otherwise, use checked arithmetic or explicitly validate the arithmetic bounds before performing the operation.",
        vulnerableCode:
          "Arithmetic operation is performed inside an unchecked block."
      });
    }
  }

  return findings;
}