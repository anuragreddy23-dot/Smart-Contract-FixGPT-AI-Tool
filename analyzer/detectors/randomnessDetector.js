function findRandomnessPatterns(node) {
  const matches = [];

  function visit(current) {
    if (!current || typeof current !== "object") return;

    if (
      current.type === "MemberAccess" &&
      (
        current.memberName === "timestamp" ||
        current.memberName === "number" ||
        current.memberName === "difficulty" ||
        current.memberName === "prevrandao"
      )
    ) {
      matches.push(current);
    }

    for (const [key, value] of Object.entries(current)) {
      if (key === "loc" || key === "range") continue;

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

  return matches;
}

function looksLikeRandomnessContext(node) {
  if (!node) return false;

  const text = JSON.stringify(node).toLowerCase();

  const randomnessKeywords = [
    "random",
    "randomness",
    "winner",
    "lottery",
    "raffle",
    "seed",
    "nonce"
  ];

  const randomnessOperations = [
    "keccak256",
    "sha256",
    "modulo"
  ];

  const hasRandomnessKeyword =
    randomnessKeywords.some((keyword) => text.includes(keyword));

  const hasRandomnessOperation =
    randomnessOperations.some((operation) => text.includes(operation));

  // A predictable blockchain value is suspicious when it is
  // combined with a hashing operation or used in a randomness-like context.
  return hasRandomnessKeyword || hasRandomnessOperation;
}

export function detectWeakRandomness(ast) {
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

      const matches = findRandomnessPatterns(node);

      if (matches.length === 0) {
        continue;
      }

      if (!looksLikeRandomnessContext(node)) {
        continue;
      }

      const firstMatch = matches[0];

      findings.push({
        id: "SCF-006",
        title: "Potential Weak Randomness",
        severity: "Medium",
        confidence: "Medium",
        category: "Randomness",
        contractName: contract.name,
        functionName,
        lineNumber: firstMatch.loc?.start?.line || 0,
        description:
          "The function appears to use predictable blockchain values such as block.timestamp or block.number as part of a randomness-related calculation.",
        impact:
          "Users or attackers may be able to predict or influence the resulting value, which can compromise lotteries, games, rewards, NFT traits, or other security-sensitive randomness.",
        recommendation:
          "Do not rely on predictable block properties for security-sensitive randomness. Use a verifiable randomness solution such as Chainlink VRF or another appropriately designed randomness mechanism.",
        vulnerableCode:
          "Predictable blockchain value used in a randomness-related calculation."
      });
    }
  }

  return findings;
}