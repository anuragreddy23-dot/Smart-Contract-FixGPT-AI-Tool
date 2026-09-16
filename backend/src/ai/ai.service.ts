import { Finding } from "../types/audit.js";
import { generateFix } from "./fix.generator.js";


/* =========================================================
   AI ANALYSIS TYPE
========================================================= */

export interface AIAnalysis {
  summary: string;
  explanation: string;
  fix: string;
  fixedCode: string;
  securityPattern: string;
  sideEffects: string[];
}


/* =========================================================
   TEXT NORMALIZATION
========================================================= */

function normalizeText(
  text: string
): string {

  if (!text) {
    return "";
  }

  return text
    .replace(
      /functionappears/gi,
      "function appears"
    )
    .replace(
      /externalcall/gi,
      "external call"
    )
    .replace(
      /externalinteraction/gi,
      "external interaction"
    )
    .replace(
      /revertif/gi,
      "revert if"
    )
    .replace(
      /beforethe/gi,
      "before the"
    )
    .replace(
      /afterthe/gi,
      "after the"
    )
    .replace(
      /checkedarithmetic/gi,
      "checked arithmetic"
    )
    .replace(
      /securitysensitive/gi,
      "security-sensitive"
    )
    .replace(
      /gasusage/gi,
      "gas usage"
    )
    .replace(
      /gasexhaustion/gi,
      "gas exhaustion"
    )
    .replace(
      /onlyowner/gi,
      "onlyOwner"
    )
    .replace(
      /onlyadmin/gi,
      "onlyAdmin"
    )
    .replace(
      /verifiablerandomness/gi,
      "verifiable randomness"
    )
    .replace(
      /manualreview/gi,
      "manual review"
    )
    .replace(
      /low-level call call/gi,
      "low-level call"
    )
    .replace(
      /external interactionbefore/gi,
      "external interaction before"
    )
    .replace(
      /appropriatefollow/gi,
      "appropriate. Follow"
    )
    .replace(
      /appropriate\.Follow/gi,
      "appropriate. Follow"
    )
    .replace(
      /\s+/g,
      " "
    )
    .trim();
}


/* =========================================================
   SIDE EFFECT NORMALIZATION
========================================================= */

function normalizeSideEffects(
  sideEffects: string[]
): string[] {

  return sideEffects.map(
    (effect) =>
      normalizeText(effect)
  );
}


/* =========================================================
   AI FINDING ANALYSIS
========================================================= */

export async function analyzeFindingWithAI(
  finding: Finding,
  sourceCode: string
): Promise<AIAnalysis> {

  /*
   * The current MVP uses the deterministic
   * FixGPT remediation engine.
   *
   * This interface is intentionally kept separate
   * so a real LLM provider can be connected later.
   */

  const fixResult =
    generateFix(
      finding,
      sourceCode
    );


  return {

    summary:
      normalizeText(
        `Potential ${finding.category} issue detected in ${finding.functionName}.`
      ),

    explanation:
      normalizeText(
        finding.description
      ),

    fix:
      normalizeText(
        finding.recommendation
      ),

    fixedCode:
      fixResult.fixedCode,

    securityPattern:
      normalizeText(
        fixResult.securityPattern
      ),

    sideEffects:
      normalizeSideEffects(
        fixResult.sideEffects
      )
  };
}