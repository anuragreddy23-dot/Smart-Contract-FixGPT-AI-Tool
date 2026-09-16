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

export function detectSignatureReplay(ast) {
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
      !/permit|execute|meta|signature|signed|claim|withdraw/i.test(
        functionName
      )
    ) {
      return;
    }

    let hasECDSARecovery = false;
    let hasNonceReference = false;
    let hasDeadlineReference = false;

    walk(node.body, (child) => {
      if (
        child.type === "FunctionCall" &&
        child.expression?.type === "Identifier" &&
        /ecrecover/i.test(
          child.expression.name || ""
        )
      ) {
        hasECDSARecovery = true;
      }

      if (
        child.type === "Identifier" &&
        /nonce|usedNonce|deadline|expiry|expiration/i.test(
          child.name || ""
        )
      ) {
        if (
          /nonce/i.test(
            child.name || ""
          )
        ) {
          hasNonceReference = true;
        }

        if (
          /deadline|expiry|expiration/i.test(
            child.name || ""
          )
        ) {
          hasDeadlineReference = true;
        }
      }
    });

    if (
      !hasECDSARecovery
    ) {
      return;
    }

    if (
      hasNonceReference ||
      hasDeadlineReference
    ) {
      return;
    }

    findings.push({
      id: "SCF-016",
      title: "Potential Signature Replay",
      severity: "High",
      confidence: "Medium",
      category: "Authentication",
      contractName:
        getContractName(node),
      functionName,
      lineNumber:
        node.loc?.start?.line || 0,
      description:
        "The function appears to recover an ECDSA signer but no obvious nonce or expiration mechanism was detected.",
      impact:
        "A previously valid signature may potentially be submitted again and replayed if the signed operation does not contain sufficient uniqueness or expiration constraints.",
      recommendation:
        "Include a per-user or per-operation nonce and, where appropriate, a deadline or expiration value in the signed message. Mark nonces as consumed before completing the operation.",
      vulnerableCode: ""
    });
  });

  return findings;
}