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

function getLine(node) {
  return node?.loc?.start?.line || 0;
}

function getMemberName(node) {
  if (!node) {
    return null;
  }

  if (node.type === "MemberAccess") {
    return node.memberName || null;
  }

  if (node.type === "NameValueExpression") {
    return getMemberName(node.expression);
  }

  return null;
}

function isApprovalCall(node) {
  if (
    !node ||
    node.type !== "FunctionCall"
  ) {
    return false;
  }

  const memberName =
    getMemberName(node.expression);

  return (
    memberName === "approve" ||
    memberName === "increaseAllowance"
  );
}

export function detectTokenApproval(ast) {
  const findings = [];

  if (!ast) {
    return findings;
  }

  walk(ast, (node) => {
    if (!isApprovalCall(node)) {
      return;
    }

    let functionName =
      "unknown";

    let contractName =
      "UnknownContract";

    let current = node;

    while (current) {
      if (
        current.type ===
        "FunctionDefinition"
      ) {
        functionName =
          current.name ||
          "fallback/receive";
      }

      if (
        current.type ===
        "ContractDefinition"
      ) {
        contractName =
          current.name ||
          "UnknownContract";

        break;
      }

      current =
        current.__parent;
    }

    const memberName =
      getMemberName(node.expression) ||
      "approve";

    findings.push({
      id: "SCF-013",

      title:
        "Token Approval Requires Review",

      severity: "Medium",

      confidence: "Low",

      category:
        "Token Security",

      contractName,

      functionName,

      lineNumber:
        getLine(node),

      description:
        `The contract performs a token ${memberName} operation. Approval-related logic should be reviewed for unsafe spender permissions and excessive allowances.`,

      impact:
        "An incorrect or overly permissive token allowance may allow an unintended spender to transfer tokens from the approving account.",

      recommendation:
        "Verify that the spender is trusted, the approved amount is intentional, and allowance changes cannot be abused. Consider safer allowance-management patterns where appropriate.",

      vulnerableCode:
        `${memberName} call detected.`
    });
  });

  return findings;
}