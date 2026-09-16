function getLine(node) {
  return node?.loc?.start?.line || 0;
}

function isTxOrigin(node) {
  return (
    node?.type === "MemberAccess" &&
    node.memberName === "origin" &&
    node.expression?.type === "Identifier" &&
    node.expression.name === "tx"
  );
}

export function detectTxOrigin(ast) {
  const findings = [];

  function visit(
    node,
    contractName = "UnknownContract",
    functionName = "unknown"
  ) {
    if (!node || typeof node !== "object") {
      return;
    }

    let currentContract = contractName;
    let currentFunction = functionName;

    if (node.type === "ContractDefinition") {
      currentContract =
        node.name || "UnknownContract";
    }

    if (node.type === "FunctionDefinition") {
      currentFunction =
        node.isConstructor
          ? "constructor"
          : node.name || "fallback/receive";
    }

    /*
     * Detect tx.origin when it is used anywhere
     * inside a function.
     *
     * Example:
     *
     * require(tx.origin == owner);
     *
     * tx.origin == owner
     *
     * tx.origin is unsafe for authorization because
     * an intermediate contract can become part of
     * the transaction flow.
     */

    if (isTxOrigin(node)) {
      findings.push({
        id: "SCF-008",
        title: "tx.origin Authentication",
        severity: "High",
        confidence: "High",
        category: "Authentication",
        contractName: currentContract,
        functionName: currentFunction,
        lineNumber: getLine(node),
        description:
          "The contract uses tx.origin for authentication or authorization. tx.origin represents the original transaction sender and can be abused by malicious intermediary contracts.",
        impact:
          "An attacker may trick an authorized user into interacting with a malicious contract that calls the vulnerable contract, causing tx.origin to remain the authorized user's address.",
        recommendation:
          "Use msg.sender for authorization instead of tx.origin. msg.sender identifies the immediate caller of the function."
      });
    }

    for (const key of Object.keys(node)) {
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
              currentFunction
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
          currentFunction
        );
      }
    }
  }

  visit(ast);

  return findings;
}