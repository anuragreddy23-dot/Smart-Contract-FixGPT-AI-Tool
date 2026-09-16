import { useEffect, useMemo, useState } from "react";
import type { ChangeEvent, DragEvent } from "react";
import axios from "axios";
import jsPDF from "jspdf";

import {
  ShieldCheck,
  FileCode2,
  ScanSearch,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  ChevronDown,
  ChevronUp,
  Copy,
  Check,
  Code2,
  Upload,
  X,
  FileJson,
  FileText,
  History,
  Trash2,
  Eye,
  LayoutDashboard,
  RefreshCw,
  Activity,
  ShieldAlert,
  ArrowUpRight,
  Plus
} from "lucide-react";

interface Verification {
  status: string;
  compilerErrors: string[];
  compilerWarnings: string[];
  remainingFindings?: Finding[];
}

interface AIAnalysis {
  summary: string;
  explanation: string;
  fix: string;
  fixedCode: string;
  securityPattern: string;
  sideEffects: string[];
}

interface Finding {
  id: string;
  title: string;
  severity: string;
  confidence: string;
  category: string;
  contractName: string;
  functionName: string;
  lineNumber: number;
  description: string;
  impact: string;
  recommendation: string;
  vulnerableCode?: string;
  aiAnalysis?: AIAnalysis;
  verification?: Verification;
}

interface AuditResponse {
  auditId: string;
  status: string;
  score: number;
  findings: Finding[];
}

interface AuditHistoryItem {
  id: string;
  auditId: string;
  contractName: string;
  solidityVersion: string;
  score: number;
  findingsCount: number;
  fixedCount: number;
  manualReviewCount: number;
  createdAt: string;
  result: AuditResponse;
}

const DEFAULT_CODE = `// Paste your Solidity smart contract here

pragma solidity ^0.8.20;

contract Example {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    function withdraw(uint256 amount) external {
        require(
            balances[msg.sender] >= amount,
            "Insufficient balance"
        );

        (bool success,) =
            msg.sender.call{value: amount}("");

        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
    }

    receive() external payable {}
}`;

const HISTORY_STORAGE_KEY =
  "fixgpt_audit_history";

function App() {
  const [contractName, setContractName] =
    useState("Example");

  const [solidityVersion, setSolidityVersion] =
    useState("0.8.20");

  const [sourceCode, setSourceCode] =
    useState(DEFAULT_CODE);

  const [selectedFileName, setSelectedFileName] =
    useState("");

  const [loading, setLoading] =
    useState(false);

  const [error, setError] =
    useState("");

  const [result, setResult] =
    useState<AuditResponse | null>(null);

  const [openFixes, setOpenFixes] =
    useState<Record<number, boolean>>({});

  const [copied, setCopied] =
    useState<number | null>(null);

  const [isDragging, setIsDragging] =
    useState(false);

  const [auditHistory, setAuditHistory] =
    useState<AuditHistoryItem[]>([]);

  /*
   * =========================================================
   * LOAD AUDIT HISTORY
   * =========================================================
   */

  useEffect(() => {
    try {
      const savedHistory =
        localStorage.getItem(
          HISTORY_STORAGE_KEY
        );

      if (savedHistory) {
        const parsed =
          JSON.parse(savedHistory);

        if (Array.isArray(parsed)) {
          setAuditHistory(parsed);
        }
      }
    } catch (historyError) {
      console.error(
        "Unable to load audit history:",
        historyError
      );
    }
  }, []);

  /*
   * =========================================================
   * DETECT CONTRACT NAME
   * =========================================================
   */

  function detectContractName(
    code: string,
    fallback: string
  ) {
    const match = code.match(
      /\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)/
    );

    return match?.[1] || fallback;
  }

  /*
   * =========================================================
   * SAVE AUDIT HISTORY
   * =========================================================
   */

  function saveAuditToHistory(
    auditResult: AuditResponse,
    detectedName: string
  ) {
    const fixedCount =
      auditResult.findings.filter(
        (finding) =>
          finding.verification?.status ===
          "Fixed"
      ).length;

    const manualReviewCount =
      auditResult.findings.filter(
        (finding) =>
          finding.verification?.status ===
            "Not Fixed" ||
          finding.verification?.status ===
            "Verification Failed"
      ).length;

    const historyItem: AuditHistoryItem = {
      id: `${auditResult.auditId}-${Date.now()}`,
      auditId: auditResult.auditId,
      contractName: detectedName,
      solidityVersion:
        solidityVersion.trim(),
      score: auditResult.score,
      findingsCount:
        auditResult.findings.length,
      fixedCount,
      manualReviewCount,
      createdAt:
        new Date().toISOString(),
      result: auditResult
    };

    setAuditHistory((previous) => {
      const updated = [
        historyItem,
        ...previous
      ].slice(0, 20);

      localStorage.setItem(
        HISTORY_STORAGE_KEY,
        JSON.stringify(updated)
      );

      return updated;
    });
  }

  /*
   * =========================================================
   * ANALYZE CONTRACT
   * =========================================================
   */

  async function analyzeContract() {
    setError("");
    setResult(null);
    setOpenFixes({});

    if (!contractName.trim()) {
      setError(
        "Please enter a contract name."
      );
      return;
    }

    if (!solidityVersion.trim()) {
      setError(
        "Please enter the Solidity version."
      );
      return;
    }

    if (!sourceCode.trim()) {
      setError(
        "Please paste your Solidity source code."
      );
      return;
    }

    try {
      setLoading(true);

      const detectedName =
        detectContractName(
          sourceCode,
          contractName.trim()
        );

      setContractName(
        detectedName
      );

      const response =
        await axios.post<AuditResponse>(
          "/api/audit",
          {
            contractName:
              detectedName,
            solidityVersion:
              solidityVersion.trim(),
            sourceCode
          }
        );

      if (response.data.status === "failed") {
  setResult(null);
  setError(
    "The Solidity contract could not be analyzed. Please check your Solidity code and try again."
  );
  return;
}

setResult(response.data);

saveAuditToHistory(
  response.data,
  detectedName
);
      window.setTimeout(() => {
        document
          .getElementById("results")
          ?.scrollIntoView({
            behavior: "smooth"
          });
      }, 100);
    } catch (err) {
      console.error(err);

      if (axios.isAxiosError(err)) {
        if (err.response) {
          setError(
            `Audit failed: ${
              err.response.data?.message ||
              "The backend returned an error."
            }`
          );
        } else {
          setError(
            "Unable to connect to the FixGPT backend. Make sure the backend is running on port 5000."
          );
        }
      } else {
        setError(
          "Something went wrong while analyzing the contract."
        );
      }
    } finally {
      setLoading(false);
    }
  }

  /*
   * =========================================================
   * FILE PROCESSING
   * =========================================================
   */

  async function processSolidityFile(
    file: File
  ) {
    if (
      !file.name
        .toLowerCase()
        .endsWith(".sol")
    ) {
      setError(
        "Please upload a Solidity .sol file."
      );
      return;
    }

    if (
      file.size >
      2 * 1024 * 1024
    ) {
      setError(
        "The uploaded file is larger than 2 MB."
      );
      return;
    }

    try {
      setError("");

      const text =
        await file.text();

      if (!text.trim()) {
        setError(
          "The uploaded Solidity file is empty."
        );
        return;
      }

      setSourceCode(text);

      const fallbackName =
        file.name.replace(
          /\.sol$/i,
          ""
        );

      const detectedName =
        detectContractName(
          text,
          fallbackName ||
            "Example"
        );

      setContractName(
        detectedName
      );

      setSelectedFileName(
        file.name
      );

      setResult(null);
      setOpenFixes({});
    } catch (uploadError) {
      console.error(
        "File upload error:",
        uploadError
      );

      setError(
        "Unable to read the Solidity file."
      );
    }
  }

  /*
   * =========================================================
   * FILE INPUT
   * =========================================================
   */

  async function handleFileUpload(
    event: ChangeEvent<HTMLInputElement>
  ) {
    const file =
      event.target.files?.[0];

    if (!file) {
      return;
    }

    await processSolidityFile(
      file
    );

    event.target.value = "";
  }

  /*
   * =========================================================
   * DRAG & DROP
   * =========================================================
   */

  function handleDragOver(
    event: DragEvent<HTMLLabelElement>
  ) {
    event.preventDefault();
    setIsDragging(true);
  }

  function handleDragLeave(
    event: DragEvent<HTMLLabelElement>
  ) {
    event.preventDefault();
    setIsDragging(false);
  }

  async function handleDrop(
    event: DragEvent<HTMLLabelElement>
  ) {
    event.preventDefault();

    setIsDragging(false);

    const file =
      event.dataTransfer.files?.[0];

    if (!file) {
      return;
    }

    await processSolidityFile(
      file
    );
  }

  /*
   * =========================================================
   * NEW AUDIT
   * =========================================================
   */

  function startNewAudit() {
    setContractName("Example");
    setSolidityVersion("0.8.20");
    setSourceCode(DEFAULT_CODE);
    setSelectedFileName("");
    setResult(null);
    setOpenFixes({});
    setError("");

    window.scrollTo({
      top: 0,
      behavior: "smooth"
    });
  }

  /*
   * =========================================================
   * TOGGLE AI FIX
   * =========================================================
   */

  function toggleFix(
    index: number
  ) {
    setOpenFixes(
      (previous) => ({
        ...previous,
        [index]:
          !previous[index]
      })
    );
  }

  /*
   * =========================================================
   * COPY FIXED CODE
   * =========================================================
   */

  async function copyFixedCode(
    code: string,
    index: number
  ) {
    try {
      await navigator.clipboard.writeText(
        code
      );

      setCopied(index);

      window.setTimeout(() => {
        setCopied(null);
      }, 1800);
    } catch {
      setError(
        "Unable to copy the fixed code."
      );
    }
  }

  /*
   * =========================================================
   * SCORE LABEL
   * =========================================================
   */

function getScoreLabel(
  score: number
) {
  if (score >= 80) {
    return "Good";
  }

  if (score >= 40) {
    return "Risky";
  }

  return "Critical";
}

  /*
   * =========================================================
   * SCORE CLASS
   * =========================================================
   */

  function getScoreClass(
    score: number
  ) {
    if (score >= 80) {
      return "score-good";
    }

    if (score >= 60) {
      return "score-warning";
    }

    return "score-danger";
  }

  /*
   * =========================================================
   * SEVERITY
   * =========================================================
   */

  function getSeverityClass(
    severity: string
  ) {
    switch (severity) {
      case "Critical":
        return "severity-critical";

      case "High":
        return "severity-high";

      case "Medium":
        return "severity-medium";

      case "Low":
        return "severity-low";

      default:
        return "severity-info";
    }
  }

  /*
   * =========================================================
   * VERIFICATION
   * =========================================================
   */

  function getVerificationClass(
    status?: string
  ) {
    switch (status) {
      case "Fixed":
        return "verification verified";

      case "Partially Fixed":
        return "verification partially-fixed";

      case "Verification Failed":
        return "verification failed";

      case "Not Fixed":
        return "verification not-fixed";

      default:
        return "verification not-fixed";
    }
  }

  /*
   * =========================================================
   * RESULT COUNTS
   * =========================================================
   */

  const fixedCount =
    result?.findings.filter(
      (finding) =>
        finding.verification?.status ===
        "Fixed"
    ).length || 0;

  const partiallyFixedCount =
    result?.findings.filter(
      (finding) =>
        finding.verification?.status ===
        "Partially Fixed"
    ).length || 0;

  const manualReviewCount =
    result?.findings.filter(
      (finding) =>
        finding.verification?.status ===
          "Not Fixed" ||
        finding.verification?.status ===
          "Verification Failed"
    ).length || 0;

  const highRiskCount =
    result?.findings.filter(
      (finding) =>
        finding.severity ===
          "Critical" ||
        finding.severity ===
          "High"
    ).length || 0;

  /*
   * =========================================================
   * DASHBOARD CALCULATIONS
   * =========================================================
   */

  const dashboardStats =
    useMemo(() => {
      const totalAudits =
        auditHistory.length;

      const contractsScanned =
        new Set(
          auditHistory.map(
            (item) =>
              item.contractName
          )
        ).size;

      const vulnerabilities =
        auditHistory.reduce(
          (total, item) =>
            total +
            item.findingsCount,
          0
        );

      const autoFixed =
        auditHistory.reduce(
          (total, item) =>
            total +
            item.fixedCount,
          0
        );

      const averageScore =
        totalAudits === 0
          ? 0
          : Math.round(
              auditHistory.reduce(
                (total, item) =>
                  total +
                  item.score,
                0
              ) /
                totalAudits
            );

      const critical =
        auditHistory.reduce(
          (total, item) =>
            total +
            item.result.findings.filter(
              (finding) =>
                finding.severity ===
                "Critical"
            ).length,
          0
        );

      const high =
        auditHistory.reduce(
          (total, item) =>
            total +
            item.result.findings.filter(
              (finding) =>
                finding.severity ===
                "High"
            ).length,
          0
        );

      const medium =
        auditHistory.reduce(
          (total, item) =>
            total +
            item.result.findings.filter(
              (finding) =>
                finding.severity ===
                "Medium"
            ).length,
          0
        );

      const low =
        auditHistory.reduce(
          (total, item) =>
            total +
            item.result.findings.filter(
              (finding) =>
                finding.severity ===
                "Low"
            ).length,
          0
        );

      const informational =
        auditHistory.reduce(
          (total, item) =>
            total +
            item.result.findings.filter(
              (finding) =>
                finding.severity ===
                "Informational"
            ).length,
          0
        );

      return {
        totalAudits,
        contractsScanned,
        vulnerabilities,
        autoFixed,
        averageScore,
        critical,
        high,
        medium,
        low,
        informational
      };
    }, [auditHistory]);

  const maxSeverityCount =
    Math.max(
      dashboardStats.critical,
      dashboardStats.high,
      dashboardStats.medium,
      dashboardStats.low,
      dashboardStats.informational,
      1
    );

  /*
   * =========================================================
   * OPEN HISTORY AUDIT
   * =========================================================
   */

  function openHistoryAudit(
    historyItem: AuditHistoryItem
  ) {
    setContractName(
      historyItem.contractName
    );

    setSolidityVersion(
      historyItem.solidityVersion
    );

    setResult(
      historyItem.result
    );

    setOpenFixes({});

    window.setTimeout(() => {
      document
        .getElementById("results")
        ?.scrollIntoView({
          behavior: "smooth"
        });
    }, 100);
  }

  /*
   * =========================================================
   * DELETE HISTORY
   * =========================================================
   */

  function deleteHistoryAudit(
    historyId: string
  ) {
    setAuditHistory(
      (previous) => {
        const updated =
          previous.filter(
            (item) =>
              item.id !==
              historyId
          );

        localStorage.setItem(
          HISTORY_STORAGE_KEY,
          JSON.stringify(
            updated
          )
        );

        return updated;
      }
    );
  }

  /*
   * =========================================================
   * CLEAR HISTORY
   * =========================================================
   */

  function clearAuditHistory() {
    if (
      !window.confirm(
        "Clear all saved audit history?"
      )
    ) {
      return;
    }

    localStorage.removeItem(
      HISTORY_STORAGE_KEY
    );

    setAuditHistory([]);
  }

  /*
   * =========================================================
   * EXPORT JSON
   * =========================================================
   */

  function exportJSON() {
    if (!result) {
      return;
    }

    const report = {
      product:
        "Smart Contract FixGPT",
      reportType:
        "Smart Contract Security Audit",
      generatedAt:
        new Date().toISOString(),
      auditId:
        result.auditId,
      contractName,
      solidityVersion,
      securityScore:
        result.score,
      summary: {
        totalFindings:
          result.findings.length,
        highRisk:
          highRiskCount,
        autoFixed:
          fixedCount,
        partiallyFixed:
          partiallyFixedCount,
        manualReview:
          manualReviewCount
      },
      findings:
        result.findings
    };

    const blob =
      new Blob(
        [
          JSON.stringify(
            report,
            null,
            2
          )
        ],
        {
          type:
            "application/json"
        }
      );

    const url =
      URL.createObjectURL(
        blob
      );

    const link =
      document.createElement(
        "a"
      );

    link.href = url;

    link.download =
      `${contractName}-fixgpt-audit.json`;

    document.body.appendChild(
      link
    );

    link.click();

    link.remove();

    URL.revokeObjectURL(
      url
    );
  }

  /*
   * =========================================================
   * EXPORT MARKDOWN
   * =========================================================
   */

  function exportMarkdown() {
    if (!result) {
      return;
    }

    let markdown = `# Smart Contract FixGPT

## Security Audit Report

**Contract:** ${contractName}

**Solidity Version:** ${solidityVersion}

**Audit ID:** ${result.auditId}

**Generated:** ${new Date().toLocaleString()}

---

## Security Score

**${result.score}/100 — ${getScoreLabel(
      result.score
    )}**

---

## Audit Summary

- Total Findings: ${result.findings.length}
- High Risk Findings: ${highRiskCount}
- Automatically Fixed: ${fixedCount}
- Partially Fixed: ${partiallyFixedCount}
- Manual Review Required: ${manualReviewCount}

---

## Security Findings

`;

    if (
      result.findings.length ===
      0
    ) {
      markdown +=
        "No vulnerabilities were detected.\n\n";
    }

    result.findings.forEach(
      (finding, index) => {
        markdown += `### ${
          index + 1
        }. ${finding.title}

**ID:** ${finding.id}

**Severity:** ${finding.severity}

**Confidence:** ${finding.confidence}

**Category:** ${finding.category}

**Contract:** ${finding.contractName}

**Function:** ${finding.functionName}

**Line:** ${finding.lineNumber}

**Verification:** ${
          finding.verification
            ?.status ||
          "Not Available"
        }

#### Description

${finding.description}

#### Impact

${finding.impact}

#### Recommendation

${finding.recommendation}

`;

        if (
          finding.vulnerableCode
        ) {
          markdown += `#### Vulnerable Code

\`\`\`solidity
${finding.vulnerableCode}
\`\`\`

`;
        }

        if (
          finding.aiAnalysis
        ) {
          markdown += `#### AI Explanation

${finding.aiAnalysis.explanation}

#### Security Pattern

${finding.aiAnalysis.securityPattern}

`;

          if (
            finding.aiAnalysis
              .fixedCode
          ) {
            markdown += `#### Fixed Code

\`\`\`solidity
${finding.aiAnalysis.fixedCode}
\`\`\`

`;
          }

          if (
            finding.aiAnalysis
              .sideEffects
              ?.length
          ) {
            markdown += `#### Review Notes

`;

            finding.aiAnalysis.sideEffects.forEach(
              (effect) => {
                markdown += `- ${effect}\n`;
              }
            );

            markdown += "\n";
          }
        }

        markdown +=
          "---\n\n";
      }
    );

    markdown += `## Disclaimer

This report is generated using automated static analysis and AI-assisted reasoning.

Passing verification does not guarantee that a smart contract is completely secure.

Manual security review is recommended before production deployment.
`;

    const blob =
      new Blob(
        [markdown],
        {
          type:
            "text/markdown"
        }
      );

    const url =
      URL.createObjectURL(
        blob
      );

    const link =
      document.createElement(
        "a"
      );

    link.href = url;

    link.download =
      `${contractName}-fixgpt-audit.md`;

    document.body.appendChild(
      link
    );

    link.click();

    link.remove();

    URL.revokeObjectURL(
      url
    );
  }

  /*
   * =========================================================
   * EXPORT PDF
   * =========================================================
   */

  function exportPDF() {
    if (!result) {
      return;
    }

    const pdf =
      new jsPDF();

    const margin = 18;

    const pageWidth =
      pdf.internal.pageSize.getWidth();

    const pageHeight =
      pdf.internal.pageSize.getHeight();

    let y = 20;

    function ensureSpace(
      height: number
    ) {
      if (
        y + height >
        pageHeight - 18
      ) {
        pdf.addPage();
        y = 20;
      }
    }

    function addText(
      text: string,
      size = 10,
      bold = false
    ) {
      pdf.setFontSize(size);

      pdf.setFont(
        "helvetica",
        bold
          ? "bold"
          : "normal"
      );

      const lines =
        pdf.splitTextToSize(
          text,
          pageWidth -
            margin * 2
        );

      ensureSpace(
        lines.length * 5 +
          5
      );

      pdf.text(
        lines,
        margin,
        y
      );

      y +=
        lines.length * 5 +
        4;
    }

    function addHeading(
      text: string,
      size = 14
    ) {
      ensureSpace(14);

      pdf.setFont(
        "helvetica",
        "bold"
      );

      pdf.setFontSize(size);

      pdf.text(
        text,
        margin,
        y
      );

      y += 9;
    }

    addHeading(
      "Smart Contract FixGPT",
      20
    );

    addText(
      "Smart Contract Security Audit Report",
      12,
      true
    );

    y += 4;

    addText(
      `Contract: ${contractName}`,
      10,
      true
    );

    addText(
      `Solidity Version: ${solidityVersion}`
    );

    addText(
      `Audit ID: ${result.auditId}`
    );

    addText(
      `Generated: ${new Date().toLocaleString()}`
    );

    y += 4;

    addHeading(
      "Security Score",
      15
    );

    addText(
      `${result.score}/100 — ${getScoreLabel(
        result.score
      )}`,
      15,
      true
    );

    y += 4;

    addHeading(
      "Audit Summary",
      15
    );

    addText(
      `Total Findings: ${result.findings.length}`
    );

    addText(
      `High Risk Findings: ${highRiskCount}`
    );

    addText(
      `Automatically Fixed: ${fixedCount}`
    );

    addText(
      `Partially Fixed: ${partiallyFixedCount}`
    );

    addText(
      `Manual Review Required: ${manualReviewCount}`
    );

    y += 4;

    addHeading(
      "Security Findings",
      15
    );

    if (
      result.findings.length ===
      0
    ) {
      addText(
        "No vulnerabilities were detected in the submitted Solidity source code."
      );
    }

    result.findings.forEach(
      (finding, index) => {
        y += 3;

        addHeading(
          `${index + 1}. ${finding.title}`,
          12
        );

        addText(
          `ID: ${finding.id}`
        );

        addText(
          `Severity: ${finding.severity}`
        );

        addText(
          `Confidence: ${finding.confidence}`
        );

        addText(
          `Category: ${finding.category}`
        );

        addText(
          `Function: ${finding.functionName}`
        );

        addText(
          `Line: ${finding.lineNumber}`
        );

        addText(
          `Verification: ${
            finding.verification
              ?.status ||
            "Not Available"
          }`,
          10,
          true
        );

        addText(
          `Description: ${finding.description}`
        );

        addText(
          `Impact: ${finding.impact}`
        );

        addText(
          `Recommendation: ${finding.recommendation}`
        );

        if (
          finding.aiAnalysis
            ?.explanation
        ) {
          addText(
            `AI Explanation: ${finding.aiAnalysis.explanation}`
          );
        }

        if (
          finding.aiAnalysis
            ?.securityPattern
        ) {
          addText(
            `Security Pattern: ${finding.aiAnalysis.securityPattern}`
          );
        }
      }
    );

    y += 4;

    addHeading(
      "Security Disclaimer",
      12
    );

    addText(
      "This report is generated using automated static analysis and AI-assisted reasoning. Verification confirms that proposed code passed the current compiler and analyzer checks, but it does not guarantee that the smart contract is completely secure. Manual security review is recommended before production deployment."
    );

    pdf.save(
      `${contractName}-fixgpt-audit.pdf`
    );
  }

  /*
   * =========================================================
   * RENDER
   * =========================================================
   */

  return (
    <div className="app">

      {/* =====================================================
          HEADER
      ===================================================== */}

      <header className="topbar">

        <div className="brand">

          <div className="brand-icon">
            <ShieldCheck size={25} />
          </div>

          <div>

            <div className="brand-name">
              Smart Contract FixGPT
            </div>

            <div className="brand-subtitle">
              AI-Powered Solidity Security Analyzer
            </div>

          </div>

        </div>

        <div className="topbar-actions">

          <div className="status">
            <span className="status-dot" />
            Analyzer Online
          </div>

          <button
            className="top-new-audit"
            onClick={
              startNewAudit
            }
          >
            <Plus size={15} />
            New Audit
          </button>

        </div>

      </header>

      <main className="container">

        {/* =====================================================
            DASHBOARD
        ===================================================== */}

        <section className="dashboard">

          <div className="dashboard-header">

            <div>

              <div className="dashboard-eyebrow">
                <LayoutDashboard
                  size={14}
                />
                SECURITY DASHBOARD
              </div>

              <h1>
                Smart Contract
                <span>
                  {" "}Security Overview
                </span>
              </h1>

              <p>
                Monitor your audit activity,
                vulnerabilities and remediation
                progress from one place.
              </p>

            </div>

            <button
              className="dashboard-refresh"
              onClick={() => {
                const saved =
                  localStorage.getItem(
                    HISTORY_STORAGE_KEY
                  );

                if (saved) {
                  try {
                    setAuditHistory(
                      JSON.parse(
                        saved
                      )
                    );
                  } catch {
                    setAuditHistory([]);
                  }
                }
              }}
            >
              <RefreshCw
                size={15}
              />
              Refresh
            </button>

          </div>

          {/* DASHBOARD CARDS */}

          <div className="dashboard-cards">

            <div className="dashboard-card">

              <div className="dashboard-card-top">

                <div className="dashboard-card-icon purple">
                  <ScanSearch
                    size={18}
                  />
                </div>

                <span>
                  AUDITS
                </span>

              </div>

              <strong>
                {
                  dashboardStats.totalAudits
                }
              </strong>

              <p>
                Total audits completed
              </p>

            </div>

            <div className="dashboard-card">

              <div className="dashboard-card-top">

                <div className="dashboard-card-icon blue">
                  <FileCode2
                    size={18}
                  />
                </div>

                <span>
                  CONTRACTS
                </span>

              </div>

              <strong>
                {
                  dashboardStats.contractsScanned
                }
              </strong>

              <p>
                Unique contracts scanned
              </p>

            </div>

            <div className="dashboard-card">

              <div className="dashboard-card-top">

                <div className="dashboard-card-icon red">
                  <ShieldAlert
                    size={18}
                  />
                </div>

                <span>
                  VULNERABILITIES
                </span>

              </div>

              <strong>
                {
                  dashboardStats.vulnerabilities
                }
              </strong>

              <p>
                Issues detected
              </p>

            </div>

            <div className="dashboard-card">

              <div className="dashboard-card-top">

                <div className="dashboard-card-icon green">
                  <CheckCircle2
                    size={18}
                  />
                </div>

                <span>
                  AUTO FIXED
                </span>

              </div>

              <strong>
                {
                  dashboardStats.autoFixed
                }
              </strong>

              <p>
                Findings verified fixed
              </p>

            </div>

          </div>

          {/* DASHBOARD MAIN GRID */}

          <div className="dashboard-grid">

            {/* AVERAGE SCORE */}

            <div className="dashboard-panel score-panel">

              <div className="panel-heading">

                <div>

                  <span>
                    SECURITY HEALTH
                  </span>

                  <h2>
                    Average Security Score
                  </h2>

                </div>

                <Activity
                  size={18}
                />

              </div>

              <div className="average-score">

                <div
                  className={`score-circle ${getScoreClass(
                    dashboardStats.averageScore
                  )}`}
                >

                  <strong>
                    {
                      dashboardStats.averageScore
                    }
                  </strong>

                  <span>
                    /100
                  </span>

                </div>

                <div className="score-description">

                  <strong>
                    {
                      dashboardStats.totalAudits ===
                      0
                        ? "No audits yet"
                        : getScoreLabel(
                            dashboardStats.averageScore
                          )
                    }
                  </strong>

                  <p>
                    Based on all completed audits
                    currently saved in FixGPT history.
                  </p>

                </div>

              </div>

              <div className="score-progress">

                <div
                  style={{
                    width: `${dashboardStats.averageScore}%`
                  }}
                />

              </div>

            </div>

            {/* SEVERITY DISTRIBUTION */}

            <div className="dashboard-panel">

              <div className="panel-heading">

                <div>

                  <span>
                    FINDINGS
                  </span>

                  <h2>
                    Severity Distribution
                  </h2>

                </div>

                <ShieldAlert
                  size={18}
                />

              </div>

              <div className="severity-chart">

                <div className="severity-row">

                  <div className="severity-row-label">

                    <span className="severity-dot critical" />

                    <span>
                      Critical
                    </span>

                  </div>

                  <div className="severity-bar">

                    <div
                      className="critical-bar"
                      style={{
                        width: `${(dashboardStats.critical /
                          maxSeverityCount) *
                          100}%`
                      }}
                    />

                  </div>

                  <strong>
                    {
                      dashboardStats.critical
                    }
                  </strong>

                </div>

                <div className="severity-row">

                  <div className="severity-row-label">

                    <span className="severity-dot high" />

                    <span>
                      High
                    </span>

                  </div>

                  <div className="severity-bar">

                    <div
                      className="high-bar"
                      style={{
                        width: `${(dashboardStats.high /
                          maxSeverityCount) *
                          100}%`
                      }}
                    />

                  </div>

                  <strong>
                    {
                      dashboardStats.high
                    }
                  </strong>

                </div>

                <div className="severity-row">

                  <div className="severity-row-label">

                    <span className="severity-dot medium" />

                    <span>
                      Medium
                    </span>

                  </div>

                  <div className="severity-bar">

                    <div
                      className="medium-bar"
                      style={{
                        width: `${(dashboardStats.medium /
                          maxSeverityCount) *
                          100}%`
                      }}
                    />

                  </div>

                  <strong>
                    {
                      dashboardStats.medium
                    }
                  </strong>

                </div>

                <div className="severity-row">

                  <div className="severity-row-label">

                    <span className="severity-dot low" />

                    <span>
                      Low
                    </span>

                  </div>

                  <div className="severity-bar">

                    <div
                      className="low-bar"
                      style={{
                        width: `${(dashboardStats.low /
                          maxSeverityCount) *
                          100}%`
                      }}
                    />

                  </div>

                  <strong>
                    {
                      dashboardStats.low
                    }
                  </strong>

                </div>

                <div className="severity-row">

                  <div className="severity-row-label">

                    <span className="severity-dot info" />

                    <span>
                      Informational
                    </span>

                  </div>

                  <div className="severity-bar">

                    <div
                      className="info-bar"
                      style={{
                        width: `${(dashboardStats.informational /
                          maxSeverityCount) *
                          100}%`
                      }}
                    />

                  </div>

                  <strong>
                    {
                      dashboardStats.informational
                    }
                  </strong>

                </div>

              </div>

            </div>

          </div>

          {/* DASHBOARD QUICK ACTIONS */}

          <div className="quick-actions">

            <div>

              <span>
                QUICK ACTION
              </span>

              <h2>
                Start a new security audit
              </h2>

              <p>
                Analyze another Solidity contract
                using the FixGPT security pipeline.
              </p>

            </div>

            <button
              onClick={
                startNewAudit
              }
            >
              <ScanSearch
                size={16}
              />
              New Contract Audit
              <ArrowUpRight
                size={15}
              />
            </button>

          </div>

        </section>

        {/* =====================================================
            AUDIT INPUT
        ===================================================== */}

        <section
          className="audit-card"
          id="new-audit"
        >

          <div className="card-header">

            <div>

              <h2>
                <FileCode2 size={21} />
                Contract Analysis
              </h2>

              <p>
                Provide your Solidity contract to begin
                the security audit.
              </p>

            </div>

            <div className="mvp-badge">
              MVP
            </div>

          </div>

          {/* CONTRACT INFORMATION */}

          <div className="form-row">

            <div className="field">

              <label>
                Contract Name
              </label>

              <input
                value={contractName}
                onChange={(event) =>
                  setContractName(
                    event.target.value
                  )
                }
                placeholder="MyContract"
              />

            </div>

            <div className="field">

              <label>
                Solidity Version
              </label>

              <input
                value={solidityVersion}
                onChange={(event) =>
                  setSolidityVersion(
                    event.target.value
                  )
                }
                placeholder="0.8.20"
              />

            </div>

          </div>

          {/* FILE UPLOAD */}

          <div className="file-upload">

            <div className="upload-header">

              <div className="upload-title">

                <div className="upload-icon">
                  <FileCode2 size={20} />
                </div>

                <div>

                  <strong>
                    Upload Solidity File
                  </strong>

                  <span>
                    Analyze a .sol smart contract directly
                  </span>

                </div>

              </div>

              {selectedFileName && (
                <button
                  type="button"
                  className="clear-file-button"
                  onClick={
                    startNewAudit
                  }
                >
                  <X size={15} />
                  Clear
                </button>
              )}

            </div>

            <label
              htmlFor="solidity-file"
              className={`upload-dropzone ${
                isDragging
                  ? "dragging"
                  : ""
              } ${
                selectedFileName
                  ? "file-selected"
                  : ""
              }`}
              onDragOver={
                handleDragOver
              }
              onDragLeave={
                handleDragLeave
              }
              onDrop={
                handleDrop
              }
            >

              <div className="upload-cloud-icon">

                {selectedFileName ? (
                  <CheckCircle2
                    size={30}
                  />
                ) : (
                  <Upload
                    size={30}
                  />
                )}

              </div>

              <div className="upload-main-text">

                <strong>
                  {selectedFileName
                    ? selectedFileName
                    : "Choose a Solidity contract"}
                </strong>

                <span>
                  {selectedFileName
                    ? "File loaded successfully"
                    : "Drag & drop your .sol file here or click to browse"}
                </span>

              </div>

              <div className="upload-button">
                Browse Files
              </div>

            </label>

            <input
              id="solidity-file"
              className="hidden-file-input"
              type="file"
              accept=".sol"
              onChange={
                handleFileUpload
              }
            />

            <div className="upload-footer">

              <span>
                Supported format:{" "}
                <strong>.sol</strong>
              </span>

              <span>
                Maximum recommended size: 2 MB
              </span>

              <span>
                Or paste your code below
              </span>

            </div>

          </div>

          {/* SOURCE CODE */}

          <div className="field">

            <div className="code-label">

              <label>
                Solidity Source Code
              </label>

              <span>
                {
                  sourceCode.split(
                    "\n"
                  ).length
                } lines
              </span>

            </div>

            <textarea
              className="code-editor"
              value={sourceCode}
              onChange={(event) =>
                setSourceCode(
                  event.target.value
                )
              }
              spellCheck={false}
            />

          </div>

          {/* ERROR */}

          {error && (
            <div className="error-box">

              <AlertTriangle size={18} />

              <span>
                {error}
              </span>

            </div>
          )}

          {/* ANALYZE */}

          <button
            className="analyze-button"
            onClick={
              analyzeContract
            }
            disabled={loading}
          >

            {loading ? (
              <>
                <Loader2
                  size={19}
                  className="spin"
                />

                Analyzing Contract...
              </>
            ) : (
              <>
                <ScanSearch size={19} />

                Analyze Contract
              </>
            )}

          </button>

        </section>

        {/* =====================================================
            AUDIT HISTORY
        ===================================================== */}

        <section className="history-section">

          <div className="history-header">

            <div>

              <span className="section-eyebrow">
                HISTORY
              </span>

              <h2>
                Recent Audits
              </h2>

              <p>
                Review previously completed security audits.
              </p>

            </div>

            {auditHistory.length > 0 && (
              <button
                type="button"
                className="clear-history-button"
                onClick={
                  clearAuditHistory
                }
              >
                <Trash2 size={15} />
                Clear History
              </button>
            )}

          </div>

          {auditHistory.length === 0 ? (

            <div className="empty-history">

              <History size={30} />

              <strong>
                No audit history yet
              </strong>

              <span>
                Completed audits will appear here.
              </span>

            </div>

          ) : (

            <div className="history-list">

              {auditHistory.map(
                (historyItem) => {

                  const historyDate =
                    new Date(
                      historyItem.createdAt
                    );

                  return (
                    <div
                      className="history-item"
                      key={
                        historyItem.id
                      }
                    >

                      <div className="history-main">

                        <div className="history-contract-icon">
                          <FileCode2
                            size={18}
                          />
                        </div>

                        <div>

                          <strong>
                            {
                              historyItem.contractName
                            }
                          </strong>

                          <span>
                            {
                              historyDate.toLocaleString()
                            }
                          </span>

                        </div>

                      </div>

                      <div className="history-stats">

                        <div>

                          <span>
                            Score
                          </span>

                          <strong
                            className={
                              historyItem.score >=
                              80
                                ? "history-good"
                                : historyItem.score >=
                                    60
                                  ? "history-warning"
                                  : "history-danger"
                            }
                          >
                            {
                              historyItem.score
                            }
                            /100
                          </strong>

                        </div>

                        <div>

                          <span>
                            Findings
                          </span>

                          <strong>
                            {
                              historyItem.findingsCount
                            }
                          </strong>

                        </div>

                        <div>

                          <span>
                            Fixed
                          </span>

                          <strong>
                            {
                              historyItem.fixedCount
                            }
                          </strong>

                        </div>

                      </div>

                      <div className="history-actions">

                        <button
                          type="button"
                          className="history-open-button"
                          onClick={() =>
                            openHistoryAudit(
                              historyItem
                            )
                          }
                        >
                          <Eye size={14} />
                          View Audit
                        </button>

                        <button
                          type="button"
                          className="history-delete-button"
                          onClick={() =>
                            deleteHistoryAudit(
                              historyItem.id
                            )
                          }
                          aria-label="Delete audit"
                        >
                          <X size={16} />
                        </button>

                      </div>

                    </div>
                  );
                }
              )}

            </div>

          )}

        </section>

        {/* =====================================================
            RESULTS
        ===================================================== */}

        {result && (

          <section
            className="results"
            id="results"
          >

            <div className="results-header">

              <div>

                <div className="section-label">
                  AUDIT COMPLETE
                </div>

                <h2>
                  Security Analysis
                </h2>

                <p>
                  Audit ID: {result.auditId}
                </p>

              </div>

              <div className="score-card">

                <div className="score-number">
                  {result.score}
                </div>

                <div className="score-total">
                  /100
                </div>

                <div className="score-label">
                  {getScoreLabel(
                    result.score
                  )}
                </div>

              </div>

            </div>

            {/* STATS */}

            <div className="stats">

              <div className="stat">
                <span>
                  Total Findings
                </span>

                <strong>
                  {result.findings.length}
                </strong>
              </div>

              <div className="stat">
                <span>
                  High Risk
                </span>

                <strong>
                  {highRiskCount}
                </strong>
              </div>

              <div className="stat">
                <span>
                  Auto Fixed
                </span>

                <strong>
                  {fixedCount}
                </strong>
              </div>

              <div className="stat">
                <span>
                  Partially Fixed
                </span>

                <strong>
                  {partiallyFixedCount}
                </strong>
              </div>

              <div className="stat">
                <span>
                  Manual Review
                </span>

                <strong>
                  {manualReviewCount}
                </strong>
              </div>

            </div>

            {/* FINDINGS HEADER */}

            <div className="findings-header">

              <div>

                <h2>
                  Security Findings
                </h2>

                <p>
                  Vulnerabilities detected by FixGPT
                </p>

              </div>

            </div>

            {/* FINDINGS */}

            <div className="findings-list">

              {result.findings.length ===
              0 ? (

                <div className="no-findings">

                  <CheckCircle2
                    size={42}
                  />

                  <h3>
                    No vulnerabilities detected
                  </h3>

                  <p>
                    FixGPT did not detect any
                    vulnerabilities in the submitted
                    Solidity source code.
                  </p>

                </div>

              ) : (

                result.findings.map(
                  (
                    finding,
                    index
                  ) => {

                    const isOpen =
                      openFixes[
                        index
                      ] === true;

                    const hasAI =
                      Boolean(
                        finding.aiAnalysis
                      );

                    return (

                      <div
                        className="finding"
                        key={`${finding.id}-${index}`}
                      >

                        <div className="finding-top">

                          <div className="finding-title">

                            <div className="finding-icon">

                              <AlertTriangle
                                size={18}
                              />

                            </div>

                            <div>

                              <h3>
                                {
                                  finding.title
                                }
                              </h3>

                              <span>
                                {
                                  finding.id
                                }
                                {" · "}
                                {
                                  finding.category
                                }
                              </span>

                            </div>

                          </div>

                          <div className="finding-meta">

                            <span
                              className={`severity ${getSeverityClass(
                                finding.severity
                              )}`}
                            >
                              {
                                finding.severity
                              }
                            </span>

                            <span
                              className={getVerificationClass(
                                finding
                                  .verification
                                  ?.status
                              )}
                            >

                              {finding.verification?.status ===
                              "Fixed" ? (
                                <>
                                  <CheckCircle2 size={15} />
                                  Fixed
                                </>
                              ) : finding.verification?.status ===
                                "Partially Fixed" ? (
                                <>
                                  <AlertTriangle size={15} />
                                  Partially Fixed
                                </>
                              ) : finding.verification?.status ===
                                "Verification Failed" ? (
                                <>
                                  <AlertTriangle size={15} />
                                  Verification Failed
                                </>
                              ) : finding.verification?.status ===
                                "Not Fixed" ? (
                                <>
                                  <AlertTriangle size={15} />
                                  Not Fixed
                                </>
                              ) : (
                                <>
                                  <AlertTriangle size={15} />
                                  Pending
                                </>
                              )}

                            </span>

                          </div>

                        </div>

                        <div className="finding-details">

                          <div>

                            <strong>
                              Function
                            </strong>

                            <code>
                              {
                                finding.functionName
                              }()
                            </code>

                          </div>

                          <div>

                            <strong>
                              Line
                            </strong>

                            <span>
                              {
                                finding.lineNumber
                              }
                            </span>

                          </div>

                          <div>

                            <strong>
                              Confidence
                            </strong>

                            <span>
                              {
                                finding.confidence
                              }
                            </span>

                          </div>

                        </div>

                        <p className="finding-description">
                          {
                            finding.description
                          }
                        </p>

                        <div className="impact-box">

                          <strong>
                            Impact
                          </strong>

                          <p>
                            {
                              finding.impact
                            }
                          </p>

                        </div>

                        {finding.aiAnalysis && (

                          <div className="fix-box">

                            <div className="fix-header">

                              <CheckCircle2
                                size={18}
                              />

                              <strong>
                                FixGPT Recommendation
                              </strong>

                            </div>

                            <p>
                              {
                                finding
                                  .aiAnalysis
                                  .fix
                              }
                            </p>

                            <div className="pattern">

                              Security Pattern:
                              {" "}

                              <strong>
                                {
                                  finding
                                    .aiAnalysis
                                    .securityPattern
                                }
                              </strong>

                            </div>

                          </div>

                        )}

                        {hasAI && (

                          <button
                            className="view-fix-button"
                            onClick={() =>
                              toggleFix(
                                index
                              )
                            }
                          >

                            <Code2
                              size={17}
                            />

                            {isOpen
                              ? "Hide AI Fix"
                              : "View AI Fix"}

                            {isOpen ? (
                              <ChevronUp
                                size={
                                  17
                                }
                              />
                            ) : (
                              <ChevronDown
                                size={
                                  17
                                }
                              />
                            )}

                          </button>

                        )}

                        {isOpen &&
                          finding.aiAnalysis && (

                            <div className="ai-fix-panel">

                              <div className="ai-fix-header">

                                <div>

                                  <h3>
                                    AI Generated Fix
                                  </h3>

                                  <p>
                                    Review the proposed
                                    remediation before
                                    applying it.
                                  </p>

                                </div>

                                <div
                                  className={
                                    finding
                                      .verification
                                      ?.status ===
                                    "Fixed"
                                      ? "fix-status success"
                                      : "fix-status warning"
                                  }
                                >

                                  {finding.verification?.status ===
                                  "Fixed" ? (
                                    <>
                                      <CheckCircle2 size={16} />
                                      Verified
                                    </>
                                  ) : finding.verification?.status ===
                                    "Partially Fixed" ? (
                                    <>
                                      <AlertTriangle size={16} />
                                      Partially Fixed
                                    </>
                                  ) : finding.verification?.status ===
                                    "Verification Failed" ? (
                                    <>
                                      <AlertTriangle size={16} />
                                      Verification Failed
                                    </>
                                  ) : finding.verification?.status ===
                                    "Not Fixed" ? (
                                    <>
                                      <AlertTriangle size={16} />
                                      Not Fixed
                                    </>
                                  ) : (
                                    <>
                                      <AlertTriangle size={16} />
                                      Pending
                                    </>
                                  )}

                                </div>

                              </div>

                              <div className="code-comparison">

                                <div className="code-panel">

                                  <div className="code-panel-header">

                                    <span>
                                      Vulnerable Code
                                    </span>

                                    <span className="code-label-danger">
                                      Original
                                    </span>

                                  </div>

                                  <pre>
                                    <code>
                                      {
                                        finding.vulnerableCode ||
                                        sourceCode
                                      }
                                    </code>
                                  </pre>

                                </div>

                                <div className="code-panel">

                                  <div className="code-panel-header">

                                    <span>
                                      Fixed Solidity
                                    </span>

                                    <button
                                      className="copy-button"
                                      onClick={() =>
                                        copyFixedCode(
                                          finding
                                            .aiAnalysis!
                                            .fixedCode,
                                          index
                                        )
                                      }
                                    >

                                      {copied ===
                                      index ? (
                                        <>
                                          <Check
                                            size={
                                              15
                                            }
                                          />
                                          Copied
                                        </>
                                      ) : (
                                        <>
                                          <Copy
                                            size={
                                              15
                                            }
                                          />
                                          Copy
                                        </>
                                      )}

                                    </button>

                                  </div>

                                  <pre>
                                    <code>
                                      {
                                        finding
                                          .aiAnalysis
                                          .fixedCode
                                      }
                                    </code>
                                  </pre>

                                </div>

                              </div>

                              <div className="ai-explanation">

                                <h4>
                                  Why this fix?
                                </h4>

                                <p>
                                  {
                                    finding
                                      .aiAnalysis
                                      .explanation
                                  }
                                </p>

                              </div>

                              {finding
                                .aiAnalysis
                                .sideEffects
                                ?.length >
                                0 && (

                                <div className="side-effects">

                                  <h4>
                                    Review Before Deployment
                                  </h4>

                                  <ul>

                                    {
                                      finding
                                        .aiAnalysis
                                        .sideEffects
                                        .map(
                                          (
                                            effect,
                                            effectIndex
                                          ) => (
                                            <li
                                              key={
                                                effectIndex
                                              }
                                            >
                                              {
                                                effect
                                              }
                                            </li>
                                          )
                                        )
                                    }

                                  </ul>

                                </div>

                              )}

                              {finding.verification && (

                                <div className="verification-panel">

                                  <div className="verification-title">

                                    {
                                      finding
                                        .verification
                                        .status ===
                                      "Fixed" ? (
                                        <CheckCircle2
                                          size={
                                            20
                                          }
                                        />
                                      ) : (
                                        <AlertTriangle
                                          size={
                                            20
                                          }
                                        />
                                      )}

                                    <div>

                                      <h4>
                                        Fix Verification
                                      </h4>

                                      <span>
                                        {
                                          finding
                                            .verification
                                            .status
                                        }
                                      </span>

                                    </div>

                                  </div>

                                  {finding
                                    .verification
                                    .compilerErrors
                                    ?.length >
                                    0 && (

                                    <div className="compiler-errors">

                                      <strong>
                                        Compiler Errors
                                      </strong>

                                      {
                                        finding
                                          .verification
                                          .compilerErrors
                                          .map(
                                            (
                                              compilerError,
                                              errorIndex
                                            ) => (
                                              <pre
                                                key={
                                                  errorIndex
                                                }
                                              >
                                                {
                                                  compilerError
                                                }
                                              </pre>
                                            )
                                          )
                                      }

                                    </div>

                                  )}

                                  {finding
                                    .verification
                                    .compilerWarnings
                                    ?.length >
                                    0 && (

                                    <div className="compiler-warnings">

                                      <strong>
                                        Compiler Warnings
                                      </strong>

                                      {
                                        finding
                                          .verification
                                          .compilerWarnings
                                          .map(
                                            (
                                              warning,
                                              warningIndex
                                            ) => (
                                              <pre
                                                key={
                                                  warningIndex
                                                }
                                              >
                                                {
                                                  warning
                                                }
                                              </pre>
                                            )
                                          )
                                      }

                                    </div>

                                  )}

                                </div>

                              )}

                              <div className="security-disclaimer">

                                <AlertTriangle
                                  size={16}
                                />

                                <span>
                                  Verification confirms that
                                  the proposed code passed the
                                  current compiler and analyzer
                                  checks. It does not guarantee
                                  that the smart contract is
                                  completely secure.
                                </span>

                              </div>

                            </div>

                          )}

                      </div>

                    );
                  }
                )

              )}

            </div>

            {/* =================================================
                AUDIT REPORT
            ================================================= */}

            <div className="audit-report-section">

              <div className="audit-report-header">

                <div>

                  <span className="section-eyebrow">
                    EXPORT
                  </span>

                  <h2>
                    Security Audit Report
                  </h2>

                  <p>
                    Export this audit for documentation,
                    review, or sharing.
                  </p>

                </div>

                <div className="report-icon">
                  <FileCode2 size={22} />
                </div>

              </div>

              <div className="report-summary">

                <div>
                  <span>
                    Contract
                  </span>

                  <strong>
                    {contractName}
                  </strong>
                </div>

                <div>
                  <span>
                    Score
                  </span>

                  <strong>
                    {result.score}/100
                  </strong>
                </div>

                <div>
                  <span>
                    Findings
                  </span>

                  <strong>
                    {
                      result.findings.length
                    }
                  </strong>
                </div>

                <div>
                  <span>
                    Audit ID
                  </span>

                  <strong>
                    {result.auditId}
                  </strong>
                </div>

              </div>

              <div className="report-actions">

                <button
                  type="button"
                  onClick={
                    exportPDF
                  }
                  className="report-button primary"
                >
                  <FileText
                    size={17}
                  />
                  Download PDF
                </button>

                <button
                  type="button"
                  onClick={
                    exportJSON
                  }
                  className="report-button"
                >
                  <FileJson
                    size={17}
                  />
                  Export JSON
                </button>

                <button
                  type="button"
                  onClick={
                    exportMarkdown
                  }
                  className="report-button"
                >
                  <Code2
                    size={17}
                  />
                  Export Markdown
                </button>

              </div>

            </div>

            {/* DISCLAIMER */}

            <div className="security-disclaimer">

              <AlertTriangle
                size={16}
              />

              <span>
                Smart Contract FixGPT provides
                automated static analysis and
                AI-assisted remediation. Results
                should be reviewed by a qualified
                security professional before production
                deployment.
              </span>

            </div>

          </section>

        )}

      </main>

      <footer>
        Smart Contract FixGPT · AI-assisted security
        analysis · Not a guarantee of contract security
      </footer>

    </div>
  );
}

export default App;