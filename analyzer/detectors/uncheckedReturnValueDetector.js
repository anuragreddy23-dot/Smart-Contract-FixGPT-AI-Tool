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

function isLowLevelCall(node) {
  if (!node || node.type !== "FunctionCall") {
    return false;
  }

  const memberName =
    getMemberName(node.expression);

  return [
    "call",
    "delegatecall",
    "staticcall"
  ].includes(memberName);
}

export function detectUncheckedReturnValues(ast) {
  const findings = [];

  function visit(
    node,
    contractName = "UnknownContract",
    functionName = "unknown",
    parent = null
  ) {
    if (!node || typeof node !== "object") {
      return;
    }

    let currentContract =
      contractName;

    let currentFunction =
      functionName;

    if (
      node.type === "ContractDefinition"
    ) {
      currentContract =
        node.name || "UnknownContract";
    }

    if (
      node.type === "FunctionDefinition"
    ) {
      currentFunction =
        node.isConstructor
          ? "constructor"
          : node.name || "fallback/receive";
    }

    /*
     * Detect an ignored low-level call:
     *
     * user.call{value: amount}("");
     *
     * The AST is:
     *
     * ExpressionStatement
     *   FunctionCall
     *     NameValueExpression
     *       MemberAccess
     *
     * A checked call such as:
     *
     * (bool success, ) = user.call(...);
     *
     * is NOT an ExpressionStatement,
     * so it will not be reported.
     */

    if (
      node.type === "ExpressionStatement" &&
      isLowLevelCall(node.expression)
    ) {
      const memberName =
        getMemberName(
          node.expression.expression
        ) || "call";

      findings.push({
        id: "SCF-007",
        title: "Unchecked Return Value",
        severity: "Medium",
        confidence: "High",
        category: "External Calls",
        contractName: currentContract,
        functionName: currentFunction,
        lineNumber: getLine(
          node.expression
        ),
        description:
          `The ${memberName} return value is ignored. Low-level calls return a success flag that should be checked.`,
        impact:
          "A failed external call may be silently ignored, allowing execution to continue even though the intended operation failed.",
        recommendation:
          `Capture the return value of ${memberName} and explicitly handle failure.`
      });
    }

    for (
      const key of Object.keys(node)
    ) {
      if (
        key === "loc" ||
        key === "range"
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
            visit(
              child,
              currentContract,
              currentFunction,
              node
            );
          }
        }
      } else if (
        value &&
        typeof value === "object"
      ) {
        visit(
          value,
          currentContract,
          currentFunction,
          node
        );
      }
    }
  }

  visit(ast);

  return findings;
}