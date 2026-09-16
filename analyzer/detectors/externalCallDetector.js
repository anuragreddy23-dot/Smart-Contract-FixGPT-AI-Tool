function getLine(node) {
  return node?.loc?.start?.line || 0;
}

function getColumn(node) {
  return node?.loc?.start?.column || 0;
}

/* =========================================================
   CHECK WHETHER AN AST NODE IS A STATE-CHANGING ASSIGNMENT
   ========================================================= */

function isStateChangingAssignment(node) {
  if (!node || typeof node !== "object") {
    return false;
  }

  /*
   * Solidity parser may represent assignments in different
   * AST forms depending on the expression.
   *
   * Supported assignment operators:
   * =
   * +=
   * -=
   * *=
   * /=
   * %=
   */

  const assignmentOperators = new Set([
    "=",
    "+=",
    "-=",
    "*=",
    "/=",
    "%="
  ]);

  /*
   * Standard Assignment AST node.
   */
  if (node.type === "Assignment") {
    return assignmentOperators.has(node.operator);
  }

  /*
   * @solidity-parser/parser can represent expressions such as:
   *
   * balances[msg.sender] -= amount;
   * owner = newOwner;
   * total += amount;
   *
   * as BinaryOperation nodes.
   */
  if (node.type === "BinaryOperation") {
    return assignmentOperators.has(node.operator);
  }

  /*
   * ExpressionStatement wrapper.
   */
  if (
    node.type === "ExpressionStatement" &&
    node.expression
  ) {
    return isStateChangingAssignment(node.expression);
  }

  return false;
}

/* =========================================================
   FIND STATE-CHANGING OPERATIONS
   ========================================================= */

function findStateUpdates(functionNode) {
  const updates = [];

  function visit(current) {
    if (
      !current ||
      typeof current !== "object"
    ) {
      return;
    }

    /*
     * Check both Assignment and BinaryOperation forms.
     */
    if (
      (current.type === "Assignment" ||
        current.type === "BinaryOperation") &&
      isStateChangingAssignment(current)
    ) {
      updates.push(current);
    }

    /*
     * Ignore metadata and circular references.
     */
    for (const [key, value] of Object.entries(current)) {
      if (
        key === "loc" ||
        key === "range" ||
        key === "__parent"
      ) {
        continue;
      }

      if (Array.isArray(value)) {
        for (const item of value) {
          visit(item);
        }
      } else if (
        value &&
        typeof value === "object"
      ) {
        visit(value);
      }
    }
  }

  visit(functionNode);

  return updates;
}

/* =========================================================
   FIND LOW-LEVEL EXTERNAL CALLS
   ========================================================= */

function findExternalCalls(functionNode) {
  const matches = [];

  function visit(current) {
    if (
      !current ||
      typeof current !== "object"
    ) {
      return;
    }

    if (
      current.type === "MemberAccess" &&
      (
        current.memberName === "call" ||
        current.memberName === "staticcall"
      )
    ) {
      matches.push(current);
    }

    /*
     * Ignore metadata and circular references.
     */
    for (const [key, value] of Object.entries(current)) {
      if (
        key === "loc" ||
        key === "range" ||
        key === "__parent"
      ) {
        continue;
      }

      if (Array.isArray(value)) {
        for (const item of value) {
          visit(item);
        }
      } else if (
        value &&
        typeof value === "object"
      ) {
        visit(value);
      }
    }
  }

  visit(functionNode);

  return matches;
}

/* =========================================================
   DETECT EXTERNAL CALLS
   ========================================================= */

export function detectExternalCalls(ast) {
  const findings = [];

  if (
    !ast ||
    !Array.isArray(ast.children)
  ) {
    return findings;
  }

  /* -------------------------------------------------------
     LOOP THROUGH CONTRACTS
     ------------------------------------------------------- */

  for (const contract of ast.children) {
    if (
      contract.type !== "ContractDefinition"
    ) {
      continue;
    }

    /* -----------------------------------------------------
       LOOP THROUGH CONTRACT MEMBERS
       ----------------------------------------------------- */

    for (const node of contract.subNodes || []) {
      if (
        node.type !== "FunctionDefinition"
      ) {
        continue;
      }

      const functionName =
        node.name ||
        "fallback/receive";

      /* ---------------------------------------------------
         FIND LOW-LEVEL CALLS
         --------------------------------------------------- */

      const matches =
        findExternalCalls(node);

      /* ---------------------------------------------------
         FIND STATE UPDATES
         --------------------------------------------------- */

      const stateUpdates =
        findStateUpdates(node);

      const seenLocations = new Set();

      /* ---------------------------------------------------
         PROCESS EACH CALL
         --------------------------------------------------- */

      for (const match of matches) {
        const lineNumber =
          getLine(match);

        const column =
          getColumn(match);

        const locationKey =
          `${lineNumber}:${column}:${match.memberName}`;

        /*
         * Prevent duplicate reports.
         */
        if (
          seenLocations.has(locationKey)
        ) {
          continue;
        }

        seenLocations.add(locationKey);

        /* -------------------------------------------------
           CHECK WHETHER STATE CHANGED BEFORE CALL
           ------------------------------------------------- */

        const stateUpdateBeforeCall =
          stateUpdates.some((update) => {
            const updateLine =
              getLine(update);

            const updateColumn =
              getColumn(update);

            return (
              updateLine < lineNumber ||
              (
                updateLine === lineNumber &&
                updateColumn < column
              )
            );
          });

        /* -------------------------------------------------
           SAFE .call()
           -------------------------------------------------

           Example:

           balances[msg.sender] -= amount;

           payable(msg.sender).call{value: amount}("");

           This follows Checks-Effects-Interactions,
           so do not report SCF-004.
        */

        if (
          match.memberName === "call" &&
          stateUpdateBeforeCall
        ) {
          continue;
        }

        /* -------------------------------------------------
           SEVERITY
           ------------------------------------------------- */

        let severity = "Medium";

        if (
          match.memberName === "staticcall"
        ) {
          severity = "Low";
        }

        /* -------------------------------------------------
           DESCRIPTION
           ------------------------------------------------- */

        let description =
          `The function performs a low-level ${match.memberName} call. The destination and call data should be carefully validated because execution is transferred to another contract.`;

        if (
          match.memberName === "call" &&
          !stateUpdateBeforeCall
        ) {
          description =
            "The function performs a low-level call before an apparent state-changing operation. The external interaction may allow unexpected execution before contract state is updated.";
        }

        /* -------------------------------------------------
           FINDING
           ------------------------------------------------- */

        findings.push({
          id: "SCF-004",

          title: "Low-Level External Call",

          severity,

          confidence: "Medium",

          category: "External Calls",

          contractName:
            contract.name,

          functionName,

          lineNumber,

          description,

          impact:
            "An unexpected or malicious target may execute arbitrary external logic and can introduce reentrancy, unexpected state changes, or other security risks.",

          recommendation:
            "Validate the destination and call data where appropriate. Follow the Checks-Effects-Interactions pattern and consider a reentrancy guard when external calls can interact with contract state.",

          vulnerableCode:
            `Low-level ${match.memberName} call detected.`
        });
      }
    }
  }

  return findings;
}