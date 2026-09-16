declare module "fixgpt-analyzer" {
  export type AnalyzerSeverity =
    | "Critical"
    | "High"
    | "Medium"
    | "Low"
    | "Informational";

  export type AnalyzerConfidence =
    | "High"
    | "Medium"
    | "Low";

  export interface AnalyzerFinding {
    id: string;
    title: string;
    severity: AnalyzerSeverity;
    confidence: AnalyzerConfidence;
    category: string;
    contractName: string;
    functionName: string;
    lineNumber: number;
    description: string;
    impact: string;
    recommendation: string;
    vulnerableCode?: string;
  }

  export interface AnalyzerResult {
    success: boolean;
    structure: unknown[];
    findings: AnalyzerFinding[];
    errors: string[];
  }

  export function analyzeSolidity(
    sourceCode: string
  ): AnalyzerResult;
}