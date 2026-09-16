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

export function detectDelegatecall(ast) {
  const findings = [];

  if (!ast) {
    return findings;
  }

  addParents(ast);

  walk(ast, (node) => {
    if (node.type !== "FunctionCall") {
      return;
    }

    const expression = node.expression;

    if (
      expression?.type !== "MemberAccess" ||
      expression.memberName !== "delegatecall"
    ) {
      return;
    }

    findings.push({
      id: "SCF-011",
      title: "Unsafe delegatecall Usage",
      severity: "High",
      confidence: "Medium",
      category: "External Calls",
      contractName: getContractName(node),
      functionName: getFunctionName(node),
      lineNumber: node.loc?.start?.line || 0,
      description:
        "The contract performs a delegatecall. The target contract's code executes in the context of the calling contract and can modify its storage and access its balance.",
      impact:
        "If the delegatecall target is attacker-controlled or insufficiently trusted, malicious code may modify storage, change ownership, drain funds, or corrupt contract state.",
      recommendation:
        "Restrict delegatecall targets to trusted immutable or strongly controlled implementations. Validate upgrade authorization and carefully review storage compatibility.",
      vulnerableCode: ""
    });
  });

  return findings;
}