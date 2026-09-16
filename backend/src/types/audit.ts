export type Severity =
  | "Critical"
  | "High"
  | "Medium"
  | "Low"
  | "Informational";

export type Confidence =
  | "High"
  | "Medium"
  | "Low";

export type VerificationStatus =
  | "Fixed"
  | "Partially Fixed"
  | "Not Fixed"
  | "Verification Failed";

export interface AuditRequest {
  contractName: string;
  solidityVersion: string;
  sourceCode: string;
}

export interface AIAnalysis {
  summary: string;
  explanation: string;
  fix: string;
  fixedCode: string;
  securityPattern: string;
  sideEffects: string[];
}

export interface VerificationResult {
  status: VerificationStatus;
  remainingFindings: Finding[];
  compilerErrors: string[];
  compilerWarnings: string[];
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  contractName: string;
  functionName: string;
  lineNumber: number;
  description: string;
  impact: string;
  recommendation: string;
  vulnerableCode?: string;

  aiAnalysis?: AIAnalysis;
  verification?: VerificationResult;
}

export interface AuditResponse {
  auditId: string;
  status: "completed" | "failed";
  score: number;
  findings: Finding[];
}