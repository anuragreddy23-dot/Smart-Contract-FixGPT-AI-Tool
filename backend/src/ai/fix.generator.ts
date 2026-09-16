import { Finding } from "../types/audit.js";

export interface FixResult {
  fixedCode: string;
  securityPattern: string;
  sideEffects: string[];
}

/*
 * =========================================================
 * SCF-001
 * Reentrancy
 * =========================================================
 */

function fixReentrancy(
  sourceCode: string,
  finding: Finding
): FixResult {
  const lines = sourceCode.split(/\r?\n/);

  const lineIndex = finding.lineNumber - 1;

  if (
    lineIndex < 0 ||
    lineIndex >= lines.length
  ) {
    return {
      fixedCode: sourceCode,
      securityPattern:
        "Checks-Effects-Interactions pattern.",
      sideEffects: [
        "The vulnerable statement could not be safely identified.",
        "Manual review is required."
      ]
    };
  }

  /*
   * Find a state-changing assignment after the
   * vulnerable external call.
   */
  const nextLines = lines.slice(lineIndex + 1);

  const stateChangeIndex =
    nextLines.findIndex(
      (line) => {
        const trimmed = line.trim();

        if (!trimmed) {
          return false;
        }

        if (
          trimmed.startsWith("//") ||
          trimmed.startsWith("/*") ||
          trimmed.startsWith("*")
        ) {
          return false;
        }

        if (
          trimmed.includes("require(") ||
          trimmed.startsWith("return") ||
          trimmed.startsWith("emit") ||
          trimmed.startsWith("revert")
        ) {
          return false;
        }

        if (
          trimmed.includes("bool success")
        ) {
          return false;
        }

        return (
          trimmed.includes("=") &&
          !trimmed.includes("==") &&
          !trimmed.includes("=>")
        );
      }
    );

  if (stateChangeIndex === -1) {
    return {
      fixedCode: sourceCode,
      securityPattern:
        "Checks-Effects-Interactions pattern.",
      sideEffects: [
        "No suitable state update was identified.",
        "Manual review is required."
      ]
    };
  }

  const actualStateIndex =
    lineIndex +
    1 +
    stateChangeIndex;

  const stateLine =
    lines[actualStateIndex];

  if (!stateLine) {
    return {
      fixedCode: sourceCode,
      securityPattern:
        "Checks-Effects-Interactions pattern.",
      sideEffects: [
        "The state-changing statement could not be safely identified.",
        "Manual review is required."
      ]
    };
  }

  /*
   * Do not move obvious control-flow statements.
   */
  const trimmedStateLine =
    stateLine.trim();

  if (
    trimmedStateLine.startsWith("return") ||
    trimmedStateLine.startsWith("emit") ||
    trimmedStateLine.startsWith("revert") ||
    trimmedStateLine.startsWith("assembly")
  ) {
    return {
      fixedCode: sourceCode,
      securityPattern:
        "Checks-Effects-Interactions pattern.",
      sideEffects: [
        "The detected statement did not appear to be a safe state update.",
        "Manual review is required."
      ]
    };
  }

  lines.splice(
    actualStateIndex,
    1
  );

  lines.splice(
    lineIndex,
    0,
    stateLine
  );

  return {
    fixedCode: lines.join("\n"),
    securityPattern:
      "Checks-Effects-Interactions pattern.",
    sideEffects: [
      "State is updated before the external interaction.",
      "Manual review is recommended for complex state dependencies."
    ]
  };
}

/*
 * =========================================================
 * SCF-002
 * Missing Access Control
 * =========================================================
 */

function fixAccessControl(
  sourceCode: string,
  finding: Finding
): FixResult {
  const escapedFunctionName =
    finding.functionName.replace(
      /[.*+?^${}()|[\]\\]/g,
      "\\$&"
    );

  const functionRegex =
    new RegExp(
      `(function\\s+${escapedFunctionName}\\b[^\\{]*)(\\{)`,
      "m"
    );

  const match =
    sourceCode.match(functionRegex);

  if (!match) {
    return {
      fixedCode: sourceCode,
      securityPattern:
        "Role-based access control.",
      sideEffects: [
        "The target function could not be safely identified.",
        "Manual review is required."
      ]
    };
  }

  if (
    sourceCode.includes("onlyOwner") ||
    sourceCode.includes("onlyAdmin")
  ) {
    return {
      fixedCode: sourceCode,
      securityPattern:
        "Role-based access control.",
      sideEffects: [
        "An existing access-control modifier was detected.",
        "Manual review is required."
      ]
    };
  }

  /*
   * Important:
   *
   * This fixer does not create an Ownable implementation.
   * It only adds the modifier when the source already provides
   * the corresponding modifier.
   *
   * Otherwise automatically inserting onlyOwner would create
   * invalid Solidity.
   */
  const hasOnlyOwnerModifier =
    /\bmodifier\s+onlyOwner\b/.test(
      sourceCode
    );

  if (!hasOnlyOwnerModifier) {
    return {
      fixedCode: sourceCode,
      securityPattern:
        "Role-based access control.",
      sideEffects: [
        "No existing onlyOwner modifier was found.",
        "An access-control modifier was not automatically inserted because doing so could produce invalid Solidity.",
        "Manual review is required."
      ]
    };
  }

  const fixedCode =
    sourceCode.replace(
      functionRegex,
      `$1 onlyOwner$2`
    );

  return {
    fixedCode,
    securityPattern:
      "onlyOwner role-based access control.",
    sideEffects: [
      "Only an authorized owner can call the protected function.",
      "The existing onlyOwner modifier is used.",
      "Manual review is required to confirm the authorization model."
    ]
  };
}

/*
 * =========================================================
 * SCF-003
 * Unchecked Arithmetic
 * =========================================================
 */

function fixArithmetic(
  sourceCode: string
): FixResult {
  const fixedCode =
    sourceCode.replace(
      /unchecked\s*\{([\s\S]*?)\}/g,
      "$1"
    );

  if (
    fixedCode === sourceCode
  ) {
    return {
      fixedCode: sourceCode,
      securityPattern:
        "Checked arithmetic using Solidity overflow protection.",
      sideEffects: [
        "No unchecked arithmetic block was identified.",
        "Manual review is required."
      ]
    };
  }

  return {
    fixedCode,
    securityPattern:
      "Checked arithmetic using Solidity overflow and underflow protection.",
    sideEffects: [
      "Arithmetic operations will use Solidity's checked arithmetic.",
      "Gas usage may increase slightly.",
      "Intentional overflow logic should be reviewed manually."
    ]
  };
}

/*
 * =========================================================
 * SCF-004
 * Unsafe External Calls
 * =========================================================
 *
 * The fixer only reorders an obvious state assignment.
 *
 * It intentionally does NOT rewrite:
 *
 *     target.call(...)
 *
 * into:
 *
 *     (bool success, ) = target.call(...);
 *
 * because automatically changing arbitrary call expressions
 * can break valid Solidity syntax and business logic.
 */
function fixExternalCall(
  sourceCode: string
): FixResult {
  /*
   * SCF-004 fixer
   *
   * Uses the complete source string rather than relying on one
   * Solidity statement per line. This makes the fixer work for
   * both normally formatted Solidity and minified/single-line code.
   *
   * The fixer only moves an obvious state assignment that occurs
   * after a low-level call. The external call itself is preserved.
   */

  const callRegex =
    /\.(call|staticcall)\s*(?:\{[^}]*\})?\s*\(/g;

  const callMatch =
    callRegex.exec(sourceCode);

  if (!callMatch) {
    return {
      fixedCode: sourceCode,
      securityPattern:
        "Checks-Effects-Interactions and safe external-call handling.",
      sideEffects: [
        "The low-level external call could not be safely identified.",
        "Destination and calldata require contextual review.",
        "Manual security review is recommended."
      ]
    };
  }

  const callIndex = callMatch.index;

  /*
   * Find the Solidity function declaration containing the call.
   * This works even when the function declaration and body are
   * on the same line as the rest of the contract.
   */
  const functionRegex =
    /function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)[^{;]*\{/g;

  let functionMatch: RegExpExecArray | null = null;
  let candidate: RegExpExecArray | null = null;

  while ((candidate = functionRegex.exec(sourceCode)) !== null) {
    if (candidate.index <= callIndex) {
      functionMatch = candidate;
    } else {
      break;
    }
  }

  if (!functionMatch) {
    return {
      fixedCode: sourceCode,
      securityPattern:
        "Checks-Effects-Interactions pattern.",
      sideEffects: [
        "The containing function could not be safely identified.",
        "The low-level call was preserved.",
        "Manual security review is recommended."
      ]
    };
  }

  const functionStart = functionMatch.index;
  const openingBraceIndex =
    sourceCode.indexOf("{", functionStart);

  if (openingBraceIndex === -1 || openingBraceIndex > callIndex) {
    return {
      fixedCode: sourceCode,
      securityPattern:
        "Checks-Effects-Interactions pattern.",
      sideEffects: [
        "The containing function body could not be safely identified.",
        "The low-level call was preserved.",
        "Manual security review is recommended."
      ]
    };
  }

  /*
   * Find the matching closing brace for the function.
   * Ignore braces inside strings and comments so that ordinary
   * Solidity text does not confuse the brace counter.
   */
  let depth = 0;
  let functionEnd = -1;
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let inLineComment = false;
  let inBlockComment = false;

  for (
    let i = openingBraceIndex;
    i < sourceCode.length;
    i++
  ) {
    const character = sourceCode[i];
    const nextCharacter = sourceCode[i + 1];

    if (inLineComment) {
      if (character === "\n") {
        inLineComment = false;
      }
      continue;
    }

    if (inBlockComment) {
      if (character === "*" && nextCharacter === "/") {
        inBlockComment = false;
        i++;
      }
      continue;
    }

    if (inSingleQuote) {
      if (character === "\\" && nextCharacter) {
        i++;
        continue;
      }
      if (character === "'") {
        inSingleQuote = false;
      }
      continue;
    }

    if (inDoubleQuote) {
      if (character === "\\" && nextCharacter) {
        i++;
        continue;
      }
      if (character === '"') {
        inDoubleQuote = false;
      }
      continue;
    }

    if (character === "/" && nextCharacter === "/") {
      inLineComment = true;
      i++;
      continue;
    }

    if (character === "/" && nextCharacter === "*") {
      inBlockComment = true;
      i++;
      continue;
    }

    if (character === "'") {
      inSingleQuote = true;
      continue;
    }

    if (character === '"') {
      inDoubleQuote = true;
      continue;
    }

    if (character === "{") {
      depth++;
    } else if (character === "}") {
      depth--;

      if (depth === 0) {
        functionEnd = i;
        break;
      }
    }
  }

  if (functionEnd === -1 || callIndex > functionEnd) {
    return {
      fixedCode: sourceCode,
      securityPattern:
        "Checks-Effects-Interactions pattern.",
      sideEffects: [
        "The containing function body could not be safely identified.",
        "The low-level call was preserved.",
        "Manual security review is recommended."
      ]
    };
  }

  const functionBody =
    sourceCode.slice(
      openingBraceIndex + 1,
      functionEnd
    );

  const relativeCallIndex =
    callIndex -
    (openingBraceIndex + 1);

  /*
   * Everything after the external call and before the end of the
   * same function is searched for a simple state assignment.
   */
  const afterCall =
    functionBody.slice(
      relativeCallIndex
    );

  /*
   * Match simple storage/state assignments such as:
   *
   * balances[msg.sender] -= amount;
   * balances[msg.sender] = newBalance;
   * owner = newOwner;
   *
   * Exclude comparisons and Solidity arrows.
   */
  const assignmentRegex =
    /(?:^|[;\n\r])(\s*)([A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]+\])?\s*(?:=|\+=|-=|\*=|\/=|%=)\s*[^=;{}]+;)/m;

  const stateMatch =
    afterCall.match(assignmentRegex);

  if (!stateMatch || stateMatch.index === undefined) {
    return {
      fixedCode: sourceCode,
      securityPattern:
        "Checks-Effects-Interactions pattern.",
      sideEffects: [
        "No clear state-changing assignment was found after the external interaction.",
        "The low-level call was preserved.",
        "Manual security review is recommended."
      ]
    };
  }

  const stateStatement =
    stateMatch[2].trim();

  /*
   * Do not move declarations or obvious non-state operations.
   */
  if (
    /^(uint|uint256|int|int256|address|bool|bytes|string)\b/.test(
      stateStatement
    ) ||
    stateStatement.startsWith("return") ||
    stateStatement.startsWith("emit") ||
    stateStatement.startsWith("revert") ||
    stateStatement.startsWith("require")
  ) {
    return {
      fixedCode: sourceCode,
      securityPattern:
        "Checks-Effects-Interactions pattern.",
      sideEffects: [
        "The detected statement did not appear to be a safe state update.",
        "The low-level call was preserved.",
        "Manual security review is recommended."
      ]
    };
  }

  /*
   * Calculate absolute positions of the state statement.
   * Include leading whitespace/newline only when it is directly
   * attached to the statement, leaving the surrounding source intact.
   */
  const afterCallStart =
    openingBraceIndex +
    1 +
    relativeCallIndex;

  const stateRelativeStart =
    stateMatch.index +
    stateMatch[0].indexOf(stateStatement);

  const stateAbsoluteStart =
    afterCallStart +
    stateRelativeStart;

  const stateAbsoluteEnd =
    stateAbsoluteStart +
    stateStatement.length;

  /*
   * Do not rewrite if the state assignment already appears before
   * the call. This protects already-mitigated code.
   */
  const beforeCall =
    functionBody.slice(
      0,
      relativeCallIndex
    );

  const assignmentBeforeCallRegex =
    /(?:^|[;\n\r])\s*[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]+\])?\s*(?:=|\+=|-=|\*=|\/=|%=)\s*[^=;{}]+;/m;

  if (assignmentBeforeCallRegex.test(beforeCall)) {
    return {
      fixedCode: sourceCode,
      securityPattern:
        "Checks-Effects-Interactions pattern.",
      sideEffects: [
        "A state-changing assignment already occurs before the external interaction.",
        "The external call was not rewritten.",
        "The low-level call and its return value still require contextual review."
      ]
    };
  }

  /*
   * Remove the original state assignment and insert it immediately
   * before the low-level call.
   */
  /*
   * The regex match points to ".call" / ".staticcall", but the
   * state update must be inserted before the ENTIRE external-call
   * statement, not between the target expression and ".call".
   *
   * Example:
   *
   *   (bool success, ) = payable(msg.sender).call{value: amount}("");
   *
   * The insertion point therefore starts at the beginning of this
   * statement, immediately after the previous semicolon.
   */
  let externalStatementStart =
    callIndex;

  for (
    let i = callIndex - 1;
    i >= openingBraceIndex + 1;
    i--
  ) {
    const character = sourceCode[i];

    if (character === ";") {
      externalStatementStart = i + 1;
      break;
    }
  }

  while (
    externalStatementStart < callIndex &&
    /\s/.test(sourceCode[externalStatementStart])
  ) {
    externalStatementStart++;
  }

  /*
   * If the external-call statement begins with an assignment such
   * as "(bool success, ) =", walk backwards to the beginning of the
   * statement rather than inserting before ".call".
   */
  const withoutState =
    sourceCode.slice(0, stateAbsoluteStart) +
    sourceCode.slice(stateAbsoluteEnd);

  /*
   * Because the state assignment is after the external call, removing
   * it does not change the position of the external statement start.
   */
  const insertionIndex =
    externalStatementStart;

  const indentation =
    sourceCode
      .slice(
        sourceCode.lastIndexOf("\n", insertionIndex - 1) + 1,
        insertionIndex
      )
      .match(/^\s*/)?.[0] || "";

  const insertionText =
    `${indentation}${stateStatement}\n`;

  const fixedCode =
    withoutState.slice(0, insertionIndex) +
    insertionText +
    withoutState.slice(insertionIndex);

  return {
    fixedCode,
    securityPattern:
      "Checks-Effects-Interactions pattern.",
    sideEffects: [
      "The detected state-changing assignment was moved before the external interaction.",
      "The low-level call was preserved.",
      "The external call and its return value still require contextual review."
    ]
  };
}

function fixDenialOfService(
  sourceCode: string
): FixResult {
  const loopRegex =
    /for\s*\(\s*uint(?:256)?\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*0\s*;\s*\1\s*<\s*([A-Za-z_][A-Za-z0-9_]*)\.length\s*;\s*\1\+\+\s*\)/g;

  const match =
    loopRegex.exec(sourceCode);

  if (!match) {
    return {
      fixedCode: sourceCode,
      securityPattern:
        "Bounded iteration.",
      sideEffects: [
        "The vulnerable loop could not be safely transformed.",
        "Manual review is required."
      ]
    };
  }

  const indexVariable =
    match[1];

  const arrayName =
    match[2];

  const replacement =
    `for (uint256 ${indexVariable} = 0; ${indexVariable} < ${arrayName}.length && ${indexVariable} < 50; ${indexVariable}++)`;

  return {
    fixedCode:
      sourceCode.replace(
        loopRegex,
        replacement
      ),

    securityPattern:
      "Bounded iteration / pagination.",

    sideEffects: [
      "The loop is limited to 50 iterations.",
      "Large collections may no longer be processed completely in one transaction.",
      "A proper pagination or batch-processing design should be considered."
    ]
  };
}

/*
 * =========================================================
 * SCF-006
 * Weak Randomness
 * =========================================================
 */

function fixWeakRandomness(
  sourceCode: string
): FixResult {
  return {
    fixedCode: sourceCode,

    securityPattern:
      "Verifiable randomness using a trusted randomness source.",

    sideEffects: [
      "Weak randomness was not automatically replaced.",
      "Consider a verifiable randomness provider such as Chainlink VRF.",
      "Manual security review is required."
    ]
  };
}

/*
 * =========================================================
 * SCF-007
 * Unchecked Return Value
 * =========================================================
 */

function fixUncheckedReturnValue(
  sourceCode: string,
  finding: Finding
): FixResult {
  const lines =
    sourceCode.split(/\r?\n/);

  const lineIndex =
    finding.lineNumber - 1;

  if (
    lineIndex < 0 ||
    lineIndex >= lines.length
  ) {
    return {
      fixedCode: sourceCode,
      securityPattern:
        "Explicit success checking for low-level calls.",
      sideEffects: [
        "The vulnerable statement could not be located.",
        "Manual review is required."
      ]
    };
  }

  const originalLine =
    lines[lineIndex];

  const match =
    originalLine.match(
      /^(\s*)(.+?)\.(call|delegatecall|staticcall)(\s*(?:\{[^}]*\})?\s*\([^;]*\))\s*;\s*$/
    );

  if (!match) {
    return {
      fixedCode: sourceCode,
      securityPattern:
        "Explicit success checking for low-level calls.",
      sideEffects: [
        "The low-level call could not be safely transformed.",
        "Manual review is required."
      ]
    };
  }

  const indentation =
    match[1];

  const target =
    match[2];

  const callType =
    match[3];

  const argumentsPart =
    match[4];

  const callExpression =
    `${target}.${callType}${argumentsPart}`;

  const fixedLines = [
    `${indentation}(bool success, ) = ${callExpression};`,
    `${indentation}require(success, "External call failed");`
  ];

  lines.splice(
    lineIndex,
    1,
    ...fixedLines
  );

  return {
    fixedCode:
      lines.join("\n"),

    securityPattern:
      "Explicit success checking for low-level calls.",

    sideEffects: [
      "The function now checks whether the low-level call succeeded.",
      "The transaction will revert when the external call fails.",
      "Manual review is recommended to confirm that reverting is appropriate."
    ]
  };
}

/*
 * =========================================================
 * SCF-008
 * tx.origin
 * =========================================================
 */

function fixTxOrigin(
  sourceCode: string
): FixResult {
  const fixedCode =
    sourceCode.replace(
      /\btx\.origin\b/g,
      "msg.sender"
    );

  if (
    fixedCode === sourceCode
  ) {
    return {
      fixedCode: sourceCode,
      securityPattern:
        "Immediate-caller authentication using msg.sender.",
      sideEffects: [
        "No tx.origin usage was found.",
        "Manual review is required."
      ]
    };
  }

  return {
    fixedCode,

    securityPattern:
      "Immediate-caller authentication using msg.sender.",

    sideEffects: [
      "Authorization now checks the immediate caller.",
      "Intermediary contracts will no longer inherit authorization from the original transaction sender.",
      "Any application logic intentionally relying on tx.origin must be reviewed manually."
    ]
  };
}

/*
 * =========================================================
 * SCF-009
 * selfdestruct
 * =========================================================
 */

function fixSelfdestruct(
  sourceCode: string
): FixResult {
  return {
    fixedCode: sourceCode,

    securityPattern:
      "Avoid contract destruction unless strictly required.",

    sideEffects: [
      "selfdestruct was not automatically removed.",
      "Removing it may change business logic.",
      "Strong access control should be verified.",
      "Manual security review is required."
    ]
  };
}

/*
 * =========================================================
 * SCF-010
 * Unprotected Initializer
 * =========================================================
 */

function fixUpgradeability(
  sourceCode: string
): FixResult {
  return {
    fixedCode: sourceCode,

    securityPattern:
      "Protected one-time initialization using a trusted upgradeability pattern.",

    sideEffects: [
      "The initializer was not automatically modified.",
      "Consider OpenZeppelin Initializable with initializer or reinitializer.",
      "Initialization should be protected against unauthorized and repeated calls.",
      "Manual security review is required."
    ]
  };
}

/*
 * =========================================================
 * SCF-011
 * delegatecall
 * =========================================================
 */

function fixDelegatecall(
  sourceCode: string
): FixResult {
  return {
    fixedCode: sourceCode,

    securityPattern:
      "Trusted delegatecall target with strict upgrade authorization.",

    sideEffects: [
      "delegatecall was not automatically removed.",
      "Removing delegatecall can break proxy or library architecture.",
      "The target implementation must be trusted and access-controlled.",
      "Storage compatibility should be reviewed manually."
    ]
  };
}

/*
 * =========================================================
 * SCF-012
 * Zero Address
 * =========================================================
 */

function fixZeroAddress(
  sourceCode: string
): FixResult {
  return {
    fixedCode: sourceCode,

    securityPattern:
      "Explicit address(0) validation.",

    sideEffects: [
      "A zero-address check was not automatically inserted.",
      "Whether address(0) is valid depends on business logic.",
      "Manual review is required."
    ]
  };
}

/*
 * =========================================================
 * SCF-013
 * Token Approval
 * =========================================================
 */

function fixTokenApproval(
  sourceCode: string
): FixResult {
  return {
    fixedCode: sourceCode,

    securityPattern:
      "Safe token allowance management.",

    sideEffects: [
      "The approval operation was not automatically rewritten.",
      "Allowance semantics differ between ERC-20 implementations.",
      "Review spender validation and allowance changes manually."
    ]
  };
}

/*
 * =========================================================
 * SCF-014
 * Oracle Manipulation
 * =========================================================
 */

function fixOracleManipulation(
  sourceCode: string
): FixResult {
  return {
    fixedCode: sourceCode,

    securityPattern:
      "Robust oracle design with manipulation-resistant pricing.",

    sideEffects: [
      "The price source was not automatically replaced.",
      "Consider TWAP, Chainlink, or multiple independent price sources.",
      "Stale prices and deviation limits should be reviewed.",
      "Manual DeFi security review is required."
    ]
  };
}

/*
 * =========================================================
 * SCF-015
 * Flash Loan
 * =========================================================
 */

function fixFlashLoan(
  sourceCode: string
): FixResult {
  return {
    fixedCode: sourceCode,

    securityPattern:
      "Flash-loan-resistant accounting and invariants.",

    sideEffects: [
      "Flash-loan interaction was not automatically modified.",
      "Security depends on protocol accounting and economic invariants.",
      "Spot balances and prices should not automatically be treated as trusted values.",
      "Manual DeFi review is required."
    ]
  };
}

/*
 * =========================================================
 * SCF-016
 * Signature Replay
 * =========================================================
 */

function fixSignatureReplay(
  sourceCode: string
): FixResult {
  return {
    fixedCode: sourceCode,

    securityPattern:
      "Nonce and deadline based signature replay protection.",

    sideEffects: [
      "A nonce was not automatically inserted.",
      "Signed message construction must match the off-chain signing implementation.",
      "Nonce consumption and expiration must be verified manually."
    ]
  };
}

/*
 * =========================================================
 * SCF-017
 * Signature Malleability
 * =========================================================
 */

function fixSignatureMalleability(
  sourceCode: string
): FixResult {
  return {
    fixedCode: sourceCode,

    securityPattern:
      "Canonical ECDSA signature validation.",

    sideEffects: [
      "Signature handling was not automatically rewritten.",
      "Prefer a well-tested signature library such as OpenZeppelin ECDSA.",
      "Manual cryptographic review is required."
    ]
  };
}

/*
 * =========================================================
 * SCF-018
 * Upgrade Authorization
 * =========================================================
 */

function fixUpgradeAuthorization(
  sourceCode: string
): FixResult {
  return {
    fixedCode: sourceCode,

    securityPattern:
      "Strong authorization for implementation upgrades.",

    sideEffects: [
      "Upgrade authorization was not automatically changed.",
      "Consider multisig, governance, timelocks, and role-based access control.",
      "The complete upgrade architecture must be reviewed manually."
    ]
  };
}

/*
 * =========================================================
 * SCF-019
 * Storage Collision
 * =========================================================
 */

function fixStorageCollision(
  sourceCode: string
): FixResult {
  return {
    fixedCode: sourceCode,

    securityPattern:
      "Compatible upgradeable storage layout.",

    sideEffects: [
      "Storage variables were not automatically reordered.",
      "Changing storage order can corrupt existing deployed state.",
      "Compare compiler-generated storage layouts before upgrading.",
      "Manual upgradeability review is required."
    ]
  };
}

/*
 * =========================================================
 * SCF-020
 * Unsafe ETH Transfer
 * =========================================================
 */

function fixUnsafeEthTransfer(
  sourceCode: string
): FixResult {
  return {
    fixedCode: sourceCode,

    securityPattern:
      "Checked low-level ETH transfer with reentrancy protection.",

    sideEffects: [
      "The ETH transfer was not automatically rewritten.",
      "Replacing transfer with call requires reentrancy protection and Checks-Effects-Interactions.",
      "Manual review is required before changing fund-transfer behavior."
    ]
  };
}

/*
 * =========================================================
 * Main FixGPT Dispatcher
 * =========================================================
 */

export function generateFix(
  finding: Finding,
  sourceCode: string
): FixResult {
  switch (finding.id) {
    case "SCF-001":
      return fixReentrancy(
        sourceCode,
        finding
      );

    case "SCF-002":
      return fixAccessControl(
        sourceCode,
        finding
      );

    case "SCF-003":
      return fixArithmetic(
        sourceCode
      );

    case "SCF-004":
      return fixExternalCall(
        sourceCode
      );

    case "SCF-005":
      return fixDenialOfService(
        sourceCode
      );

    case "SCF-006":
      return fixWeakRandomness(
        sourceCode
      );

    case "SCF-007":
      return fixUncheckedReturnValue(
        sourceCode,
        finding
      );

    case "SCF-008":
      return fixTxOrigin(
        sourceCode
      );

    case "SCF-009":
      return fixSelfdestruct(
        sourceCode
      );

    case "SCF-010":
      return fixUpgradeability(
        sourceCode
      );

    case "SCF-011":
      return fixDelegatecall(
        sourceCode
      );

    case "SCF-012":
      return fixZeroAddress(
        sourceCode
      );

    case "SCF-013":
      return fixTokenApproval(
        sourceCode
      );

    case "SCF-014":
      return fixOracleManipulation(
        sourceCode
      );

    case "SCF-015":
      return fixFlashLoan(
        sourceCode
      );

    case "SCF-016":
      return fixSignatureReplay(
        sourceCode
      );

    case "SCF-017":
      return fixSignatureMalleability(
        sourceCode
      );

    case "SCF-018":
      return fixUpgradeAuthorization(
        sourceCode
      );

    case "SCF-019":
      return fixStorageCollision(
        sourceCode
      );

    case "SCF-020":
      return fixUnsafeEthTransfer(
        sourceCode
      );

    default:
      return {
        fixedCode: sourceCode,

        securityPattern:
          "Manual security review.",

        sideEffects: [
          "No automatic fixer is available for this finding.",
          "Manual review is required."
        ]
      };
  }
}