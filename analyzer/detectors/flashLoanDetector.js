function walk(node, callback) {
  if (!node || typeof node !== "object") {
    return;
  }

  callback(node);

  for (const key of Object.keys(node)) {
    if (
      key === "loc" ||
      key === "range" ||
      key === "__parent"
    ) {
      continue;
    }

    const value = node[key];

    if (Array.isArray(value)) {
      for (const child of value) {
        if (child && typeof child === "object") {
          walk(child, callback);
        }
      }
    } else if (
      value &&
      typeof value === "object"
    ) {
      walk(value, callback);
    }
  }
}

function addParents(ast) {
  walk(ast, (node) => {
    for (const key of Object.keys(node)) {
      if (
        key === "loc" ||
        key === "range" ||
        key === "__parent"
      ) {
        continue;
      }

      const value = node[key];

      if (Array.isArray(value)) {
        for (const child of value) {
          if (child && typeof child === "object") {
            child.__parent = node;
          }
        }
      } else if (
        value &&
        typeof value === "object"
      ) {
        value.__parent = node;
      }
    }
  });
}

function getContractName(node) {
  let current = node;

  while (current) {
    if (current.type === "ContractDefinition") {
      return current.name || "UnknownContract";
    }

    current = current.__parent;
  }

  return "UnknownContract";
}

function getFunctionName(node) {
  let current = node;

  while (current) {
    if (current.type === "FunctionDefinition") {
      return current.name || "fallback/receive";
    }

    current = current.__parent;
  }

  return "contract-level";
}

export function detectFlashLoan(ast) {
  const findings = [];

  if (!ast) {
    return findings;
  }

  addParents(ast);

  walk(ast, (node) => {
    if (node.type !== "FunctionCall") {
      return;
    }

    const expression =
      node.expression;

    if (
      expression?.type !== "MemberAccess"
    ) {
      return;
    }

    const memberName =
      expression.memberName || "";

    if (
      !/flashLoan|flashBorrow|flashMint/i.test(
        memberName
      )
    ) {
      return;
    }

    findings.push({
      id: "SCF-015",
      title: "Flash-Loan Manipulation Risk",
      severity: "High",
      confidence: "Low",
      category: "DeFi",
      contractName:
        getContractName(node),
      functionName:
        getFunctionName(node),
      lineNumber:
        node.loc?.start?.line || 0,
      description:
        "The contract interacts with a flash-loan mechanism. Flash loans can provide attackers with large temporary capital and should be considered when validating prices, collateral, voting power, or accounting invariants.",
      impact:
        "If security-critical calculations rely on balances, reserves, prices, or other state that can be temporarily manipulated, an attacker may exploit the transaction before the flash loan is repaid.",
      recommendation:
        "Validate protocol invariants against flash-loan manipulation. Avoid using manipulable spot balances or prices as trusted security inputs and use robust oracle and accounting mechanisms.",
      vulnerableCode: ""
    });
  });

  return findings;
}