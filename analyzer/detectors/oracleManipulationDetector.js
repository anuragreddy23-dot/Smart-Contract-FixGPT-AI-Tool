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

function isOracleLikeFunction(functionName) {
  return /price|oracle|rate|value|exchange/i.test(
    functionName || ""
  );
}

export function detectOracleManipulation(ast) {
  const findings = [];

  if (!ast) {
    return findings;
  }

  addParents(ast);

  walk(ast, (node) => {
    if (node.type !== "FunctionCall") {
      return;
    }

    const expression =
      node.expression;

    if (
      expression?.type !== "MemberAccess"
    ) {
      return;
    }

    const memberName =
      expression.memberName || "";

    const isReserveRead =
      memberName === "getReserves";

    const isSpotPriceRead =
      memberName === "slot0";

    if (
      !isReserveRead &&
      !isSpotPriceRead
    ) {
      return;
    }

    const functionName =
      getFunctionName(node);

    if (
      !isOracleLikeFunction(
        functionName
      )
    ) {
      return;
    }

    findings.push({
      id: "SCF-014",
      title: "Potential Price Oracle Manipulation",
      severity: "High",
      confidence: "Low",
      category: "DeFi / Oracle",
      contractName:
        getContractName(node),
      functionName,
      lineNumber:
        node.loc?.start?.line || 0,
      description:
        "The contract reads an AMM reserve or spot-price value inside a price-like function. A spot price from a manipulable liquidity pool may not be a reliable oracle.",
      impact:
        "An attacker may temporarily manipulate pool liquidity or price and cause the contract to use an incorrect asset valuation.",
      recommendation:
        "Do not rely solely on a manipulable AMM spot price for security-critical valuation. Consider a robust oracle, TWAP, multiple independent sources, deviation checks, and stale-price validation.",
      vulnerableCode: ""
    });
  });

  return findings;
}