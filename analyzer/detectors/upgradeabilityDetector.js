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
        if (
          child &&
          typeof child === "object"
        ) {
          child.__parent = node;
          walk(child, callback);
        }
      }
    } else if (
      value &&
      typeof value === "object"
    ) {
      value.__parent = node;
      walk(value, callback);
    }
  }
}

function addParentReferences(ast) {
  walk(ast, () => {});
}

function isPublicOrExternalFunction(node) {
  return (
    node.type === "FunctionDefinition" &&
    (
      node.visibility === "public" ||
      node.visibility === "external"
    )
  );
}

function isInitializerFunction(functionName) {
  if (!functionName) {
    return false;
  }

  return /^(initialize|init|setup|initializeContract)$/i.test(
    functionName
  );
}

function hasInitializationProtection(node) {
  const modifiers =
    node.modifiers || [];

  return modifiers.some(
    (modifier) => {
      const modifierName =
        modifier.name || "";

      return (
        /onlyOwner/i.test(modifierName) ||
        /onlyAdmin/i.test(modifierName) ||
        /^initializer$/i.test(modifierName) ||
        /^reinitializer$/i.test(modifierName)
      );
    }
  );
}

export function detectUpgradeability(ast) {
  const findings = [];

  if (!ast) {
    return findings;
  }

  addParentReferences(ast);

  walk(ast, (node) => {
    if (
      !isPublicOrExternalFunction(node)
    ) {
      return;
    }

    const functionName =
      node.name || "";

    if (
      !isInitializerFunction(
        functionName
      )
    ) {
      return;
    }

    if (
      hasInitializationProtection(node)
    ) {
      return;
    }

    const contractName =
      getContractName(node);

    findings.push({
      id: "SCF-010",
      title:
        "Unprotected Initializer",
      severity: "Critical",
      confidence: "Medium",
      category:
        "Upgradeability",
      contractName,
      functionName:
        functionName ||
        "fallback/receive",
      lineNumber:
        node.loc?.start?.line || 0,
      description:
        "An externally accessible initializer-style function does not appear to have initialization or access-control protection.",
      impact:
        "An attacker may be able to initialize contract state before the legitimate owner or administrator, potentially gaining privileged control.",
      recommendation:
        "Protect initializer functions using a trusted initialization mechanism such as OpenZeppelin Initializable, initializer, or reinitializer, and ensure initialization can only occur once.",
      vulnerableCode: ""
    });
  });

  return findings;
}

