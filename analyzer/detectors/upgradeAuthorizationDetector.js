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

function hasAccessModifier(node) {
  return (node.modifiers || []).some(
    (modifier) =>
      /onlyOwner|onlyAdmin|authorized|role|governance/i.test(
        modifier.name || ""
      )
  );
}

export function detectUpgradeAuthorization(ast) {
  const findings = [];

  if (!ast) {
    return findings;
  }

  addParents(ast);

  walk(ast, (node) => {
    if (
      node.type !== "FunctionDefinition" ||
      !node.body
    ) {
      return;
    }

    const functionName =
      node.name || "";

    if (
      !/upgrade|upgradeTo|upgradeToAndCall|setImplementation|setBeacon/i.test(
        functionName
      )
    ) {
      return;
    }

    if (
      hasAccessModifier(node)
    ) {
      return;
    }

    findings.push({
      id: "SCF-018",
      title: "Unsafe Upgrade Authorization",
      severity: "Critical",
      confidence: "Medium",
      category: "Upgradeability",
      contractName:
        getContractName(node),
      functionName,
      lineNumber:
        node.loc?.start?.line || 0,
      description:
        "An upgrade-related function appears to be externally accessible without an obvious authorization modifier.",
      impact:
        "An unauthorized user may potentially replace the implementation contract and gain complete control over upgradeable contract behavior and storage.",
      recommendation:
        "Protect implementation upgrades with strong role-based authorization or governance. Review upgrade delays, timelocks, multisignature controls, and implementation validation.",
      vulnerableCode: ""
    });
  });

  return findings;
}