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

export function detectUnsafeEthTransfer(ast) {
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
      expression.memberName;

    if (
      memberName !== "transfer" &&
      memberName !== "send"
    ) {
      return;
    }

    findings.push({
      id: "SCF-020",
      title:
        "Unsafe ETH Transfer Pattern",
      severity: "Medium",
      confidence: "Medium",
      category:
        "Fund Handling",
      contractName:
        getContractName(node),
      functionName:
        getFunctionName(node),
      lineNumber:
        node.loc?.start?.line || 0,
      description:
        `The contract uses address.${memberName}() for ETH transfer. This pattern should be reviewed for gas-stipend limitations and failure handling.`,
      impact:
        "ETH transfers using transfer or send may fail for recipient contracts because of gas-stipend or execution constraints, potentially causing withdrawals or other operations to fail.",
      recommendation:
        "Consider using a low-level call with an explicit success check where appropriate. Apply reentrancy protection and checks-effects-interactions when using call for ETH transfers.",
      vulnerableCode: ""
    });
  });

  return findings;
}