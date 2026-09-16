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

    current =
      current.__parent;
  }

  return "UnknownContract";
}

function isSignatureFunction(name) {
  if (!name) {
    return false;
  }

  return /sign|signature|permit|execute|claim|meta|authorization|authorize|verify/i.test(
    name
  );
}

export function detectSignatureMalleability(ast) {
  const findings = [];

  if (!ast) {
    return findings;
  }

  addParents(ast);

  walk(ast, (node) => {
    if (
      node.type !==
      "FunctionDefinition"
    ) {
      return;
    }

    if (!node.body) {
      return;
    }

    const functionName =
      node.name ||
      "fallback/receive";

    let hasECDSA = false;
    let hasSignatureParameters = false;
    let hasRawSignatureComponents = false;

    walk(node.body, (child) => {
      if (
        child.type === "FunctionCall" &&
        child.expression?.type ===
          "Identifier" &&
        /ecrecover/i.test(
          child.expression.name || ""
        )
      ) {
        hasECDSA = true;
      }

      if (
        child.type === "VariableDeclaration" &&
        /signature|digest|hash|r|s|v/i.test(
          child.name || ""
        )
      ) {
        hasSignatureParameters = true;
      }

      if (
        child.type === "Identifier" &&
        /^(r|s|v)$/i.test(
          child.name || ""
        )
      ) {
        hasRawSignatureComponents = true;
      }
    });

    if (!hasECDSA) {
      return;
    }

    if (
      !isSignatureFunction(
        functionName
      ) &&
      !hasSignatureParameters &&
      !hasRawSignatureComponents
    ) {
      return;
    }

    findings.push({
      id: "SCF-017",

      title:
        "Signature Malleability Review",

      severity: "Medium",

      confidence: "Low",

      category:
        "Cryptography",

      contractName:
        getContractName(node),

      functionName,

      lineNumber:
        node.loc?.start?.line || 0,

      description:
        "The contract performs low-level ECDSA signature recovery. Canonical signature validation and protection against signature malleability should be reviewed.",

      impact:
        "Incorrect ECDSA handling can allow multiple representations of a signature or cause authorization and replay-protection assumptions to fail.",

      recommendation:
        "Prefer a well-tested signature library such as OpenZeppelin ECDSA. Validate the signer, enforce canonical ECDSA signatures, and implement nonce, deadline, chain, and contract-domain protections where appropriate.",

      vulnerableCode:
        "ecrecover-based signature verification detected."
    });
  });

  return findings;
}