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

function addParentReferences(ast) {
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
          if (
            child &&
            typeof child === "object"
          ) {
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

export function detectSelfdestruct(ast) {
  const findings = [];

  if (!ast) {
    return findings;
  }

  addParentReferences(ast);

  walk(ast, (node) => {
    if (
      node.type !== "FunctionCall"
    ) {
      return;
    }

    const expression =
      node.expression;

    if (
      expression?.type !==
        "Identifier" ||
      expression.name !==
        "selfdestruct"
    ) {
      return;
    }

    const contractName =
      getContractName(node);

    const functionName =
      getFunctionName(node);

    findings.push({
      id: "SCF-009",
      title:
        "Dangerous selfdestruct Usage",
      severity: "High",
      confidence: "High",
      category:
        "Contract Destruction",
      contractName,
      functionName,
      lineNumber:
        node.loc?.start?.line || 0,
      description:
        "The contract uses selfdestruct, which can destroy the contract and transfer its remaining Ether to a specified address.",
      impact:
        "An attacker or unauthorized user may permanently disable contract functionality if access control is missing or incorrectly implemented. Even where protected, selfdestruct can create significant operational and security risks.",
      recommendation:
        "Avoid selfdestruct unless it is strictly required. If it is necessary, protect it with strong access control and carefully review the destruction mechanism.",
      vulnerableCode: ""
    });
  });

  return findings;
}