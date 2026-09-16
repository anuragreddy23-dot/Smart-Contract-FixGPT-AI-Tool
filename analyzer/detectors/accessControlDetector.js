function isAdministrativeName(name) {
  if (!name) {
    return false;
  }

  const lowerName =
    name.toLowerCase();

  const exactNames = new Set([
    "upgrade",
    "upgradeto",
    "upgradeandcall",
    "pause",
    "unpause",
    "setowner",
    "setadmin",
    "transferownership",
    "renounceownership",
    "rescue",
    "rescuetokens",
    "rescueeth",
    "withdrawadmin",
    "mint",
    "burn"
  ]);

  if (exactNames.has(lowerName)) {
    return true;
  }

  const prefixes = [
    "setadmin",
    "setowner",
    "upgrade",
    "rescue"
  ];

  return prefixes.some(
    (prefix) =>
      lowerName.startsWith(prefix)
  );
}

function hasAccessControl(node) {
  const text =
    JSON.stringify(node);

  return (
    text.includes("onlyOwner") ||
    text.includes("onlyAdmin") ||
    text.includes("AccessControl") ||
    text.includes("Ownable") ||
    text.includes("msg.sender") ||
    text.includes("hasRole") ||
    text.includes("checkRole")
  );
}

function hasAuthorizationModifier(node) {
  const modifiers =
    node.modifiers || [];

  return modifiers.some(
    (modifier) => {
      const name =
        modifier?.name || "";

      return (
        /onlyowner/i.test(name) ||
        /onlyadmin/i.test(name) ||
        /onlyrole/i.test(name) ||
        /auth/i.test(name) ||
        /owner/i.test(name)
      );
    }
  );
}

export function detectAccessControl(ast) {
  const findings = [];

  if (
    !ast ||
    !Array.isArray(ast.children)
  ) {
    return findings;
  }

  for (const contract of ast.children) {
    if (
      contract.type !==
      "ContractDefinition"
    ) {
      continue;
    }

    for (const node of contract.subNodes || []) {
      if (
        node.type !==
        "FunctionDefinition"
      ) {
        continue;
      }

      const functionName =
        node.name ||
        "fallback/receive";

      const visibility =
        node.visibility;

      if (
        visibility !== "public" &&
        visibility !== "external"
      ) {
        continue;
      }

      if (
        !isAdministrativeName(
          functionName
        )
      ) {
        continue;
      }

      if (
        hasAuthorizationModifier(
          node
        )
      ) {
        continue;
      }

      if (
        hasAccessControl(node)
      ) {
        continue;
      }

      findings.push({
        id: "SCF-002",

        title:
          "Potential Missing Access Control",

        severity: "High",

        confidence: "Medium",

        category:
          "Access Control",

        contractName:
          contract.name,

        functionName,

        lineNumber:
          node.loc?.start?.line || 0,

        description:
          "This externally accessible administrative function does not appear to enforce an authorization check.",

        impact:
          "An unauthorized user may be able to invoke the function and modify privileged contract state or perform an administrative action.",

        recommendation:
          "Restrict the function using an appropriate authorization mechanism such as onlyOwner, AccessControl, or another role-based permission system.",

        vulnerableCode:
          "Administrative function is externally accessible without an apparent authorization check."
      });
    }
  }

  return findings;
}