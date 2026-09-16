import { parseSolidity } from "./parsers/solidityParser.js";
import { extractContractStructure } from "./parsers/contractStructure.js";

import { detectReentrancy } from "./detectors/reentrancyDetector.js";
import { detectAccessControl } from "./detectors/accessControlDetector.js";
import { detectArithmetic } from "./detectors/arithmeticDetector.js";
import { detectExternalCalls } from "./detectors/externalCallDetector.js";
import { detectDenialOfService } from "./detectors/dosDetector.js";
import { detectWeakRandomness } from "./detectors/randomnessDetector.js";
import { detectUncheckedReturnValues } from "./detectors/uncheckedReturnValueDetector.js";
import { detectTxOrigin } from "./detectors/txOriginDetector.js";
import { detectSelfdestruct } from "./detectors/selfdestructDetector.js";
import { detectUpgradeability } from "./detectors/upgradeabilityDetector.js";

import { detectDelegatecall } from "./detectors/delegatecallDetector.js";
import { detectZeroAddress } from "./detectors/zeroAddressDetector.js";
import { detectTokenApproval } from "./detectors/tokenApprovalDetector.js";
import { detectOracleManipulation } from "./detectors/oracleManipulationDetector.js";
import { detectFlashLoan } from "./detectors/flashLoanDetector.js";
import { detectSignatureReplay } from "./detectors/signatureReplayDetector.js";
import { detectSignatureMalleability } from "./detectors/signatureMalleabilityDetector.js";
import { detectUpgradeAuthorization } from "./detectors/upgradeAuthorizationDetector.js";
import { detectStorageCollision } from "./detectors/storageCollisionDetector.js";
import { detectUnsafeEthTransfer } from "./detectors/unsafeEthTransferDetector.js";

import { getContextSnippet } from "./utils.js";

function normalizeFindingText(text) {
  if (!text) {
    return "";
  }

  return text
    .replace(/low-level call call/gi, "low-level call")
    .replace(/external interactionbefore/gi, "external interaction before")
    .replace(/external interactionspattern/gi, "external interactions pattern")
    .replace(/revertif/gi, "revert if")
    .replace(/beforethe/gi, "before the")
    .replace(/afterthe/gi, "after the")
    .replace(/checkedarithmetic/gi, "checked arithmetic")
    .replace(/securitysensitive/gi, "security-sensitive")
    .replace(/gasusage/gi, "gas usage")
    .replace(/gasexhaustion/gi, "gas exhaustion")
    .replace(/functionappears/gi, "function appears")
    .replace(/arandomness/gi, "a randomness")
    .replace(/ableto/gi, "able to")
    .replace(/predictor/gi, "predict or")
    .replace(/considerpagination/gi, "consider pagination")
    .replace(/unboundedcollections/gi, "unbounded collections")
    .replace(/manualreview/gi, "manual review")
    .replace(/verifiablerandomness/gi, "verifiable randomness")
    .replace(/transactionsender/gi, "transaction sender")
    .replace(/transactionorigin/gi, "transaction origin")
    .replace(/initializationmechanism/gi, "initialization mechanism")
    .replace(/accesscontrol/gi, "access control")
    .replace(/functionsusing/gi, "functions using")
    .replace(/initializationusing/gi, "initialization using")
    .replace(/openzeppelininitializable/gi, "OpenZeppelin Initializable")
    .replace(/\s+/g, " ")
    .trim();
}

function normalizeFinding(
  finding,
  sourceCode
) {
  const lineNumber =
    finding.lineNumber || 0;

  return {
    ...finding,

    title:
      normalizeFindingText(
        finding.title
      ),

    description:
      normalizeFindingText(
        finding.description
      ),

    impact:
      normalizeFindingText(
        finding.impact
      ),

    recommendation:
      normalizeFindingText(
        finding.recommendation
      ),

    vulnerableCode:
      finding.vulnerableCode ||
      getContextSnippet(
        sourceCode,
        lineNumber,
        2,
        3
      )
  };
}

export function analyzeSolidity(
  sourceCode
) {
  const parseResult =
    parseSolidity(
      sourceCode
    );

  if (!parseResult.success) {
    return {
      success: false,
      errors:
        parseResult.errors,
      contractStructure: [],
      findings: []
    };
  }

  const contractStructure =
    extractContractStructure(
      parseResult.ast
    );

  const findings = [
    ...detectReentrancy(
      parseResult.ast
    ),

    ...detectAccessControl(
      parseResult.ast
    ),

    ...detectArithmetic(
      parseResult.ast
    ),

    ...detectExternalCalls(
      parseResult.ast
    ),

    ...detectDenialOfService(
      parseResult.ast
    ),

    ...detectWeakRandomness(
      parseResult.ast
    ),

    ...detectUncheckedReturnValues(
      parseResult.ast
    ),

    ...detectTxOrigin(
      parseResult.ast
    ),

    ...detectSelfdestruct(
      parseResult.ast
    ),

    ...detectUpgradeability(
      parseResult.ast
    ),

    ...detectDelegatecall(
      parseResult.ast
    ),

    ...detectZeroAddress(
      parseResult.ast
    ),

    ...detectTokenApproval(
      parseResult.ast
    ),

    ...detectOracleManipulation(
      parseResult.ast
    ),

    ...detectFlashLoan(
      parseResult.ast
    ),

    ...detectSignatureReplay(
      parseResult.ast
    ),

    ...detectSignatureMalleability(
      parseResult.ast
    ),

    ...detectUpgradeAuthorization(
      parseResult.ast
    ),

    ...detectStorageCollision(
      parseResult.ast
    ),

    ...detectUnsafeEthTransfer(
      parseResult.ast
    )
  ];

  const normalizedFindings =
    findings.map(
      (finding) =>
        normalizeFinding(
          finding,
          sourceCode
        )
    );

  return {
    success: true,
    errors: [],
    contractStructure,
    findings:
      normalizedFindings
  };
}