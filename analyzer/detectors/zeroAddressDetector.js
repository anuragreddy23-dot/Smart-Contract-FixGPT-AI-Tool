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

function getContractName(node) {
  let current = node;

  while (current) {
    if (
      current.type ===
      "ContractDefinition"
    ) {
      return (
        current.name ||
        "UnknownContract"
      );
    }

    current = current.__parent;
  }

  return "UnknownContract";
}

function hasZeroAddressCheck(
  body,
  parameterName
) {
  let found = false;

  walk(body, (node) => {
    if (
      node.type !==
      "BinaryOperation"
    ) {
      return;
    }

    if (
      node.operator !== "==" &&
      node.operator !== "!="
    ) {
      return;
    }

    const left = node.left;
    const right = node.right;

    const leftParameter =
      left?.type === "Identifier" &&
      left.name === parameterName;

    const rightParameter =
      right?.type === "Identifier" &&
      right.name === parameterName;

    const leftZeroAddress =
      left?.type === "FunctionCall" &&
      left.expression?.type ===
        "Identifier" &&
      left.expression.name === "address";

    const rightZeroAddress =
      right?.type === "FunctionCall" &&
      right.expression?.type ===
        "Identifier" &&
      right.expression.name === "address";

    if (
      (leftParameter &&
        rightZeroAddress) ||
      (rightParameter &&
        leftZeroAddress)
    ) {
      found = true;
    }
  });

  return found;
}

function parameterNeedsValidation(
  functionName,
  parameterName
) {
  const text =
    `${functionName} ${parameterName}`.toLowerCase();

  const securitySensitiveNames = [
    "owner",
    "admin",
    "operator",
    "manager",
    "recipient",
    "receiver",
    "beneficiary",
    "spender",
    "token",
    "implementation",
    "proxy",
    "router",
    "oracle",
    "treasury",
    "fee",
    "vault"
  ];

  return securitySensitiveNames.some(
    (keyword) =>
      text.includes(keyword)
  );
}

export function detectZeroAddress(ast) {
  const findings = [];

  if (!ast) {
    return findings;
  }

  addParents(ast);

  walk(ast, (node) => {
    if (
      node.type !==
        "FunctionDefinition" ||
      !node.body
    ) {
      return;
    }

    const functionName =
      node.name ||
      "fallback/receive";

    const parameters =
      node.parameters ||
      [];

    for (const parameter of parameters) {
      if (
        parameter.type !==
          "VariableDeclaration" ||
        parameter.typeName?.type !==
          "ElementaryTypeName" ||
        parameter.typeName.name !==
          "address"
      ) {
        continue;
      }

      const parameterName =
        parameter.name;

      if (!parameterName) {
        continue;
      }

      if (
        !parameterNeedsValidation(
          functionName,
          parameterName
        )
      ) {
        continue;
      }

      if (
        hasZeroAddressCheck(
          node.body,
          parameterName
        )
      ) {
        continue;
      }

      const contractName =
        getContractName(node);

      findings.push({
        id: "SCF-012",

        title:
          "Missing Zero-Address Validation",

        severity: "Medium",

        confidence: "Low",

        category:
          "Input Validation",

        contractName,

        functionName,

        lineNumber:
          node.loc?.start?.line || 0,

        description:
          `The function accepts security-sensitive address parameter "${parameterName}" without an apparent zero-address validation.`,

        impact:
          "Passing address(0) may permanently assign an unusable address, burn tokens, or break contract functionality depending on how the parameter is used.",

        recommendation:
          `Validate "${parameterName}" against address(0) when a zero address would be invalid for the application's business logic.`,

        vulnerableCode:
          `Address parameter "${parameterName}" does not have an apparent address(0) validation.`
      });
    }
  });

  return findings;
}