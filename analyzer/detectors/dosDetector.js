function findLoops(node) {
  const loops = [];

  function visit(current) {
    if (!current || typeof current !== "object") {
      return;
    }

    if (
      current.type === "ForStatement" ||
      current.type === "WhileStatement" ||
      current.type === "DoWhileStatement"
    ) {
      loops.push(current);
    }

    for (const [key, value] of Object.entries(current)) {
      if (key === "loc" || key === "range") {
        continue;
      }

      if (Array.isArray(value)) {
        for (const item of value) {
          visit(item);
        }
      } else if (value && typeof value === "object") {
        visit(value);
      }
    }
  }

  visit(node);

  return loops;
}

function usesDynamicArrayLength(loop) {
  const text = JSON.stringify(loop);

  return (
    text.includes('"memberName":"length"') &&
    (
      text.includes('"type":"Identifier"') ||
      text.includes('"type":"IndexAccess"')
    )
  );
}

export function detectDenialOfService(ast) {
  const findings = [];
  const reportedLoops = new Set();

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

      const functionName =
        node.name || "fallback/receive";

      const loops = findLoops(node);

      for (const loop of loops) {
        if (!usesDynamicArrayLength(loop)) {
          continue;
        }

        const lineNumber =
          loop.loc?.start?.line || 0;

        const findingKey =
          `${contract.name}:${functionName}:${lineNumber}`;

        if (reportedLoops.has(findingKey)) {
          continue;
        }

        reportedLoops.add(findingKey);

        findings.push({
          id: "SCF-005",
          title: "Potential Denial of Service from Unbounded Loop",
          severity: "Medium",
          confidence: "Medium",
          category: "Denial of Service",
          contractName: contract.name,
          functionName,
          lineNumber,
          description:
            "The function contains a loop whose termination condition appears to depend on a dynamic array length. If the collection can grow without a practical bound, the function may eventually require more gas than the block gas limit allows.",
          impact:
            "An attacker or normal contract growth may increase the collection size until the function becomes too expensive to execute, potentially preventing important operations from completing.",
          recommendation:
            "Avoid iterating over unbounded collections in a single transaction. Consider pagination, bounded batches, pull-based processing, or another design that limits gas consumption per transaction.",
          vulnerableCode:
            "Loop iteration count depends on a dynamic collection."
        });
      }
    }
  }

  return findings;
}