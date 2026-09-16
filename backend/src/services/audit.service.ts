import {
  AuditRequest,
  AuditResponse,
  Finding,
  VerificationResult
} from "../types/audit.js";

import { analyzeSolidity } from "fixgpt-analyzer";

import {
  analyzeFindingWithAI
} from "../ai/ai.service.js";

import {
  compileSolidity
} from "./solidity.compiler.js";


/* =========================================================
   CONTRACT NAME DETECTION
========================================================= */

function detectContractName(
  sourceCode: string,
  fallbackName: string
): string {
  const match = sourceCode.match(
    /\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)/
  );

  return match?.[1] || fallbackName;
}


/* =========================================================
   SECURITY SCORE
========================================================= */

function calculateSecurityScore(
  findings: Finding[]
): number {
  let score = 100;

  const uniqueFindings =
    new Set<string>();

  for (const finding of findings) {
    const key =
      `${finding.id}:${finding.contractName}:${finding.functionName}:${finding.lineNumber}`;

    if (uniqueFindings.has(key)) {
      continue;
    }

    uniqueFindings.add(key);

    switch (finding.severity) {
      case "Critical":
        score -= 30;
        break;

      case "High":
        score -= 20;
        break;

      case "Medium":
        score -= 10;
        break;

      case "Low":
        score -= 5;
        break;

      case "Informational":
        score -= 1;
        break;
    }
  }

  return Math.max(0, score);
}


/* =========================================================
   CHECKS-EFFECTS-INTERACTIONS VERIFICATION
========================================================= */

/*
 * Determines whether a state-changing operation occurs
 * before a low-level external call inside the SAME function.
 *
 * This is specifically used for SCF-004 verification.
 */
function hasStateUpdateBeforeExternalCall(
  sourceCode: string,
  functionName: string
): boolean {
  if (
    !sourceCode ||
    !functionName
  ) {
    return false;
  }

  const lines =
    sourceCode.split(/\r?\n/);

  /*
   * Find the target function.
   */
  const functionRegex =
    new RegExp(
      `^\\s*function\\s+${functionName.replace(
        /[.*+?^${}()|[\]\\]/g,
        "\\$&"
      )}\\b`
    );

  const functionStart =
    lines.findIndex(
      (line) =>
        functionRegex.test(line)
    );

  if (functionStart === -1) {
    return false;
  }

  /*
   * Find the end of the function
   * using brace depth.
   */
  let braceDepth = 0;
  let started = false;
  let functionEnd = lines.length - 1;

  for (
    let i = functionStart;
    i < lines.length;
    i++
  ) {
    const line = lines[i];

    for (
      const character of line
    ) {
      if (character === "{") {
        braceDepth++;
        started = true;
      }

      if (character === "}") {
        braceDepth--;

        if (
          started &&
          braceDepth === 0
        ) {
          functionEnd = i;
          break;
        }
      }
    }

    if (
      started &&
      braceDepth === 0
    ) {
      break;
    }
  }

  /*
   * Only inspect the target function.
   */
  const functionLines =
    lines.slice(
      functionStart,
      functionEnd + 1
    );

  const functionBody =
    functionLines.join("\n");

  /*
   * Find low-level external interaction.
   *
   * Matches:
   *
   * .call(...)
   * .call{value: ...}(...)
   * .staticcall(...)
   */
  const externalCallRegex =
    /\.(call|staticcall)\s*(?:\{[^}]*\})?\s*\(/;

  const externalCallMatch =
    functionBody.match(
      externalCallRegex
    );

  if (!externalCallMatch) {
    return false;
  }

  const externalCallIndex =
    externalCallMatch.index ?? -1;

  if (
    externalCallIndex === -1
  ) {
    return false;
  }

  /*
   * Everything before the external interaction.
   */
  const beforeCall =
    functionBody.slice(
      0,
      externalCallIndex
    );

  /*
   * State-changing operations we consider:
   *
   * owner = ...
   * balances[msg.sender] = ...
   * balances[msg.sender] -= ...
   * balances[msg.sender] += ...
   *
   * The regex deliberately does not treat:
   *
   * == 
   * =>
   *
   * as assignments.
   */
  const stateUpdateRegex =
    /\b[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]+\])?\s*(?:=|\+=|-=|\*=|\/=|%=)\s*[^=]/;

  return stateUpdateRegex.test(
    beforeCall
  );
}


/* =========================================================
   VERIFY GENERATED FIX
========================================================= */

function verifyFix(
  originalFinding: Finding,
  fixedCode: string,
  contractName: string
): VerificationResult {

  const actualContractName =
    detectContractName(
      fixedCode,
      contractName
    );

  console.log(
    `Verifying fixed code using contract: ${actualContractName}`
  );


  /* -------------------------------------------------------
     STEP 1 — COMPILE FIXED CODE
  ------------------------------------------------------- */

  const compilation =
    compileSolidity(
      fixedCode,
      actualContractName
    );

  if (!compilation.success) {

    console.error(
      "FIX VERIFICATION COMPILATION FAILED"
    );

    console.error(
      "Contract:",
      actualContractName
    );

    console.error(
      "Compiler errors:",
      compilation.errors
    );

    return {
      status: "Verification Failed",
      remainingFindings: [],
      compilerErrors:
        compilation.errors,
      compilerWarnings:
        compilation.warnings
    };
  }


  /* -------------------------------------------------------
     STEP 2 — RE-RUN STATIC SECURITY ANALYZER
  ------------------------------------------------------- */

  const verification =
    analyzeSolidity(
      fixedCode
    );

  if (!verification.success) {

    console.error(
      "FIX VERIFICATION ANALYZER FAILED"
    );

    console.error(
      "Contract:",
      actualContractName
    );

    return {
      status: "Verification Failed",
      remainingFindings: [],
      compilerErrors: [],
      compilerWarnings:
        compilation.warnings
    };
  }


  /* -------------------------------------------------------
     STEP 3 — FIND SAME VULNERABILITY
  ------------------------------------------------------- */

  const remainingFindings =
    verification.findings.filter(
      (finding) =>
        finding.id ===
        originalFinding.id
    );

/* -------------------------------------------------------
   STEP 4 — SPECIAL HANDLING FOR SCF-004
------------------------------------------------------- */

/*
 * SCF-004 is now verified by re-running the static analyzer.
 *
 * The detector no longer reports .call() when a state-changing
 * operation occurs before the call.
 *
 * Therefore:
 *
 *   Unsafe:
 *      external call
 *      ↓
 *      state update
 *      → SCF-004 remains
 *
 *   Safe:
 *      state update
 *      ↓
 *      external call
 *      → SCF-004 disappears
 *
 * If the original SCF-004 finding is gone after re-analysis,
 * it is completely Fixed.
 *
 * The mitigation check is retained as an additional safeguard
 * for cases where the analyzer may still report the call.
 */

if (
  originalFinding.id === "SCF-004"
) {

  const mitigated =
    hasStateUpdateBeforeExternalCall(
      fixedCode,
      originalFinding.functionName
    );

  console.log(
    `SCF-004 mitigation check: ${mitigated}`
  );

  /*
   * If the analyzer no longer reports SCF-004,
   * the general verification logic below will mark it Fixed.
   *
   * If the analyzer still reports SCF-004 but the state update
   * has moved before the call, mark it Partially Fixed.
   */
  if (
    mitigated &&
    remainingFindings.length > 0
  ) {
    return {
      status: "Partially Fixed",
      remainingFindings,
      compilerErrors: [],
      compilerWarnings:
        compilation.warnings
    };
  }
}


  /* -------------------------------------------------------
     STEP 5 — FINDING COMPLETELY REMOVED
  ------------------------------------------------------- */

  if (
    remainingFindings.length === 0
  ) {

    return {
      status: "Fixed",
      remainingFindings: [],
      compilerErrors: [],
      compilerWarnings:
        compilation.warnings
    };
  }


  /* -------------------------------------------------------
     STEP 6 — NOT FIXED
  ------------------------------------------------------- */

  return {
    status: "Not Fixed",
    remainingFindings,
    compilerErrors: [],
    compilerWarnings:
      compilation.warnings
  };
}


/* =========================================================
   MAIN AUDIT SERVICE
========================================================= */

export async function analyzeContract(
  request: AuditRequest
): Promise<AuditResponse> {

  const {
    contractName,
    solidityVersion,
    sourceCode
  } = request;


  console.log(
    `Analyzing contract: ${contractName}`
  );

  console.log(
    `Solidity version: ${solidityVersion}`
  );


  /* -------------------------------------------------------
     DETECT CONTRACT NAME
  ------------------------------------------------------- */

  const detectedContractName =
    detectContractName(
      sourceCode,
      contractName
    );

  console.log(
    `Detected Solidity contract: ${detectedContractName}`
  );


  /* -------------------------------------------------------
     RUN STATIC ANALYSIS
  ------------------------------------------------------- */

  const result =
    analyzeSolidity(
      sourceCode
    );


  if (!result.success) {

    return {
      auditId:
        `audit_${Date.now()}`,

      status: "failed",

      score: 0,

      findings: []
    };
  }


  /* -------------------------------------------------------
     PROCESS FINDINGS
  ------------------------------------------------------- */

  const findings: Finding[] = [];


  for (
    const finding
    of result.findings
  ) {

    console.log(
      `Processing ${finding.id} in ${finding.functionName}`
    );


    /* -----------------------------------------------------
       AI FIX GENERATION
    ----------------------------------------------------- */

    const aiAnalysis =
      await analyzeFindingWithAI(
        finding,
        sourceCode
      );


    /* -----------------------------------------------------
       VERIFY GENERATED FIX
    ----------------------------------------------------- */

    const verification =
      verifyFix(
        finding,
        aiAnalysis.fixedCode,
        detectedContractName
      );


    /* -----------------------------------------------------
       ADD COMPLETE FINDING
    ----------------------------------------------------- */

    findings.push({

      ...finding,

      aiAnalysis,

      verification

    });
  }


  /* -------------------------------------------------------
     CALCULATE SECURITY SCORE
  ------------------------------------------------------- */

  const score =
    calculateSecurityScore(
      findings
    );


  /* -------------------------------------------------------
     FINAL RESPONSE
  ------------------------------------------------------- */

  return {

    auditId:
      `audit_${Date.now()}`,

    status: "completed",

    score,

    findings

  };
}