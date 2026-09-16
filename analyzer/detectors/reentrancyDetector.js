function containsExternalCall(node) {
  if (!node) {
    return false;
  }

  const text = JSON.stringify(node);

  return (
    text.includes('"MemberAccess"') &&
    (
      text.includes('"call"') ||
      text.includes('"send"') ||
      text.includes('"transfer"')
    )
  );
}

function containsStateChange(node) {
  if (!node) {
    return false;
  }

  const text = JSON.stringify(node);

  return (
    text.includes('"Assignment"') ||
    text.includes('"BinaryOperation"')
  );
}

export function detectReentrancy(ast) {
  const findings = [];

  if (!ast || !Array.isArray(ast.children)) {
    return findings;
  }

  for (const contract of ast.children) {
    if (contract.type !== "ContractDefinition") {
      continue;
    }

    for (const node of contract.subNodes || []) {
      if (node.type !== "FunctionDefinition") {
        continue;
      }

      const functionName = node.name || "fallback/receive";
      const statements = node.body?.statements || [];

      let externalCallIndex = -1;
      let externalCallNode = null;

      for (let i = 0; i < statements.length; i++) {
        if (containsExternalCall(statements[i])) {
          externalCallIndex = i;
          externalCallNode = statements[i];
          break;
        }
      }

      if (externalCallIndex === -1) {
        continue;
      }

      let stateUpdateAfterCall = false;

      for (
        let i = externalCallIndex + 1;
        i < statements.length;
        i++
      ) {
        if (containsStateChange(statements[i])) {
          stateUpdateAfterCall = true;
          break;
        }
      }

      if (!stateUpdateAfterCall) {
        continue;
      }

      findings.push({
        id: "SCF-001",
        title: "Potential Reentrancy Vulnerability",
        severity: "High",
        confidence: "Medium",
        category: "Reentrancy",
        contractName: contract.name,
        functionName,
        lineNumber: externalCallNode.loc?.start?.line || 0,
        description:
          "The function performs an external interaction before a state-changing operation. A malicious contract may be able to re-enter the function before the state is updated.",
        impact:
          "An attacker may repeatedly invoke the vulnerable function and potentially withdraw or manipulate assets beyond the intended amount.",
        recommendation:
          "Update critical state before the external interaction using the Checks-Effects-Interactions pattern. A suitable reentrancy guard may also be appropriate depending on the contract design.",
        vulnerableCode: "External call occurs before the state update."
      });
    }
  }

  return findings;
}