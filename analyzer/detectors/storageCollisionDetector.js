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

function getStateVariables(contractNode) {
  return (contractNode.subNodes || [])
    .filter(
      (node) =>
        node.type ===
        "StateVariableDeclaration"
    )
    .flatMap(
      (node) =>
        node.variables || []
    );
}

export function detectStorageCollision(ast) {
  const findings = [];

  if (!ast) {
    return findings;
  }

  const contracts = [];

  walk(ast, (node) => {
    if (
      node.type ===
      "ContractDefinition"
    ) {
      contracts.push(node);
    }
  });

  const stateMap =
    new Map();

  for (const contract of contracts) {
    const variables =
      getStateVariables(
        contract
      );

    for (const variable of variables) {
      if (!variable.name) {
        continue;
      }

      const existing =
        stateMap.get(
          variable.name
        );

      if (existing) {
        findings.push({
          id: "SCF-019",
          title:
            "Potential Storage Collision",
          severity: "High",
          confidence: "Low",
          category:
            "Upgradeability",
          contractName:
            contract.name ||
            "UnknownContract",
          functionName:
            "contract-level",
          lineNumber:
            variable.loc?.start?.line ||
            0,
          description:
            `State variable "${variable.name}" appears in multiple contracts. In upgradeable systems, incompatible storage layouts can cause storage collisions.`,
          impact:
            "A storage-layout mismatch between proxy and implementation contracts can corrupt state, change ownership or balances, or make variables reference unintended storage slots.",
          recommendation:
            "Compare complete storage layouts between proxy and implementation versions. Preserve variable ordering, types, inheritance layout, and storage gaps according to the chosen upgradeability framework.",
          vulnerableCode: ""
        });
      } else {
        stateMap.set(
          variable.name,
          {
            contract:
              contract.name
          }
        );
      }
    }
  }

  return findings;
}