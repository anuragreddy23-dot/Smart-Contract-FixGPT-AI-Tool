SMART CONTRACT FIXGPT AI TOOL
==============================

AI-Assisted Smart Contract Security Analysis, Vulnerability Detection,
Remediation and Verification Platform


1. PROJECT OVERVIEW
-------------------

Smart Contract FixGPT is a full-stack Web3 security platform designed to
analyze Solidity smart contracts, detect potential security vulnerabilities,
explain their security impact, generate remediation suggestions, and
re-analyze proposed fixes.

The project combines AST-based Solidity analysis, custom security detectors,
backend audit services, AI-assisted remediation, fix verification, and a
React-based security interface into a single workflow.

Core workflow:

    DETECT -> EXPLAIN -> FIX -> RE-ANALYZE -> REPORT


2. PROBLEM STATEMENT
--------------------

Smart contracts are immutable programs that can control digital assets and
execute critical blockchain logic. A small implementation mistake can lead
to unauthorized access, financial loss, denial of service, or other security
issues.

Traditional smart contract security auditing requires specialized knowledge
and significant manual effort.

Smart Contract FixGPT explores an automated workflow in which static analysis
and AI-assisted reasoning work together to help developers identify and
understand potential vulnerabilities before deploying contracts.

The platform is designed to:

    1. Accept Solidity source code.
    2. Parse the contract structure.
    3. Perform static security analysis.
    4. Detect potential vulnerabilities.
    5. Assign severity and confidence.
    6. Explain the security impact.
    7. Recommend remediation.
    8. Generate proposed fixed Solidity code.
    9. Re-analyze the proposed fix.
   10. Determine a verification status.
   11. Calculate a security score.
   12. Present the results through a web interface.


3. PROJECT OBJECTIVES
---------------------

The main objectives of Smart Contract FixGPT are:

- Build an automated Solidity security-analysis system.
- Detect common smart contract vulnerability patterns.
- Provide structured and understandable security findings.
- Explain the potential impact of detected vulnerabilities.
- Provide actionable remediation recommendations.
- Generate AI-assisted fixed Solidity code.
- Re-analyze proposed fixes instead of automatically trusting them.
- Provide verification status for proposed remediation.
- Calculate a security score from detected findings.
- Provide a developer-friendly security interface.
- Create a foundation for future AI-assisted smart contract auditing.


4. CORE WORKFLOW
----------------

DETECT
    The analyzer parses the submitted Solidity source code and examines
    security-sensitive structures and operations.

EXPLAIN
    Detected issues are converted into structured findings containing the
    vulnerability, severity, confidence, location, impact and recommendation.

FIX
    For supported findings, the remediation layer generates proposed fixes,
    explanations and recommended security patterns.

RE-ANALYZE
    Proposed fixed code is analyzed again to determine whether relevant
    findings remain.

REPORT
    The final audit result contains the audit ID, security score, findings,
    remediation information and verification results.


5. SYSTEM ARCHITECTURE
----------------------

The application is divided into three major layers.

    +--------------------------------------------------+
    |                    FRONTEND                      |
    |              React + TypeScript                  |
    |                                                  |
    |  Contract Input | Audit Results | Findings       |
    |  Fix Comparison | History | Security Dashboard   |
    +-------------------------+------------------------+
                              |
                              | HTTP / REST API
                              v
    +--------------------------------------------------+
    |                    BACKEND                       |
    |                Node.js + Express                 |
    |                                                  |
    |  Audit Routes | Audit Service | Compiler Service |
    |  AI Service   | Fix Generator | Verification     |
    +-------------------------+------------------------+
                              |
                              v
    +--------------------------------------------------+
    |              SECURITY ANALYZER                   |
    |                                                  |
    |  Solidity Parser | AST Analysis | Detectors      |
    |  Finding Normalization | Security Heuristics     |
    +--------------------------------------------------+


6. TECHNOLOGY STACK
-------------------

FRONTEND
- React
- TypeScript
- Vite
- Axios
- React Router
- CSS
- Monaco Editor
- Lucide Icons
- Framer Motion

BACKEND
- Node.js
- Express
- TypeScript
- Axios
- Zod
- tsx / TypeScript development tooling

SMART CONTRACT ANALYSIS
- Solidity
- @solidity-parser/parser
- Solidity Abstract Syntax Tree (AST)
- Custom security detectors
- Static security analysis
- Pattern-based security heuristics

DEVELOPMENT TOOLS
- Git
- GitHub
- VS Code
- WSL Ubuntu
- Remix IDE
- Foundry
- MetaMask
- Ethereum-compatible development environments


7. SECURITY ANALYSIS ENGINE
---------------------------

The analyzer is the core security component of Smart Contract FixGPT.

It parses Solidity source code into an Abstract Syntax Tree (AST), extracts
contract information, and executes multiple security detectors.

The parser/analyzer can inspect information including:

- Solidity version
- Contracts
- Functions
- Modifiers
- State variables
- Events
- Constructors
- Inheritance
- Interfaces
- Libraries
- External calls
- ETH transfers
- Token interactions
- Security-sensitive operations


8. VULNERABILITY DETECTION MODULES
----------------------------------

The current analyzer contains detectors covering twenty security patterns.

SCF-001  Reentrancy
         Detects potentially unsafe external interactions occurring before
         relevant state updates.

SCF-002  Missing Access Control
         Detects security-sensitive functions that may lack authorization
         controls.

SCF-003  Unchecked Arithmetic
         Detects arithmetic operations inside Solidity unchecked blocks.

SCF-004  Unsafe External Calls
         Detects potentially unsafe low-level external calls and interaction
         patterns.

SCF-005  Denial of Service
         Detects potentially unbounded loops over dynamic collections.

SCF-006  Weak Randomness
         Detects predictable blockchain-derived randomness patterns.

SCF-007  Unchecked Return Values
         Detects low-level calls whose return values may not be checked.

SCF-008  tx.origin Authentication
         Detects authentication logic based on tx.origin.

SCF-009  selfdestruct Usage
         Detects use of the contract destruction mechanism.

SCF-010  Unprotected Initializer
         Detects initializer functions that may be callable without
         sufficient protection.

SCF-011  Unsafe delegatecall
         Detects potentially dangerous delegatecall usage.

SCF-012  Zero Address Validation
         Detects security-sensitive address assignments without zero-address
         validation.

SCF-013  Token Approval
         Detects potentially unsafe ERC-20 approval patterns.

SCF-014  Oracle Manipulation
         Detects heuristic patterns involving on-chain reserve or price data.

SCF-015  Flash Loan Risk
         Detects flash-loan-related interaction patterns.

SCF-016  Signature Replay
         Detects signature verification patterns that may lack replay
         protection.

SCF-017  Signature Malleability
         Detects potentially unsafe ECDSA signature handling patterns.

SCF-018  Upgrade Authorization
         Detects upgrade-related functions without recognized authorization
         controls.

SCF-019  Storage Collision
         Detects potential state-variable naming collisions across contract
         structures.

SCF-020  Unsafe ETH Transfer
         Detects usage of transfer() and send() for ETH transfers.

IMPORTANT:
Some detectors are intentionally heuristic. Detection of a pattern does not
automatically prove that a contract is exploitable.


9. STRUCTURED SECURITY FINDINGS
-------------------------------

Each security finding follows a consistent structure.

Example:

{
  "id": "SCF-001",
  "title": "Potential Reentrancy Vulnerability",
  "severity": "High",
  "confidence": "High",
  "category": "Reentrancy",
  "contractName": "VulnerableVault",
  "functionName": "withdraw",
  "lineNumber": 8,
  "description": "An external call occurs before a relevant state update.",
  "impact": "An attacker may potentially re-enter the function before the state is updated.",
  "recommendation": "Apply checks-effects-interactions and update state before the external call."
}

Findings can contain:

- Finding ID
- Vulnerability title
- Severity
- Confidence
- Category
- Contract name
- Function name
- Line number
- Description
- Impact
- Recommendation
- Vulnerable code
- AI analysis
- Verification result


10. SEVERITY CLASSIFICATION
---------------------------

Findings use the following severity levels:

- Critical
- High
- Medium
- Low
- Informational

Severity represents the potential security importance of a finding.


11. CONFIDENCE CLASSIFICATION
-----------------------------

The analyzer records:

- High
- Medium
- Low

Confidence indicates how strongly the detector evidence supports the
reported pattern.

This is especially important for heuristic security checks because a detected
pattern may require additional manual validation.


12. AI-ASSISTED REMEDIATION
---------------------------

Smart Contract FixGPT includes an AI-assisted remediation layer designed to
transform vulnerability findings into actionable remediation guidance.

For supported findings, the remediation workflow can provide:

- Vulnerable code
- Fixed code
- Security explanation
- Recommended security pattern
- Potential side effects
- Verification status
- Remaining findings after re-analysis

The generated fix is treated as a proposed remediation and is not considered
proof that the contract is secure.


13. FIX VERIFICATION
--------------------

A major part of the project is the verification of generated fixes.

The system does not automatically assume that AI-generated code is correct.

The proposed fixed code is re-analyzed to determine whether the original
security issue is still detected.

Verification statuses:

FIXED
    The original vulnerability is no longer detected and no relevant
    remaining findings are reported by the verification workflow.

PARTIALLY FIXED
    The remediation mitigates part of the original issue, but relevant
    findings remain.

NOT FIXED
    The original security issue remains after remediation.

VERIFICATION FAILED
    The proposed code could not be successfully verified, for example because
    of compilation or verification errors.


14. SECURITY SCORE
------------------

Smart Contract FixGPT calculates a security score from 0 to 100.

Current presentation:

    80 - 100    Good
    40 - 79     Risky
     0 - 39     Critical

The score is intended to provide a quick summary of the findings detected by
the analyzer.

IMPORTANT:
The security score is an analysis indicator. It is not a guarantee that a
smart contract is secure and it is not a replacement for a professional
security audit.


15. BACKEND ARCHITECTURE
------------------------

The backend provides the REST API connecting the frontend with the security
analysis and remediation services.

Current structure:

backend/
    src/
        ai/
            ai.service.ts
            fix.generator.ts

        routes/
            audit.routes.ts

        services/
            audit.service.ts
            solidity.compiler.ts

        types/
            audit.ts
            fixgpt-analyzer.d.ts

        server.ts

Backend responsibilities include:

- Receiving audit requests
- Validating input
- Running contract analysis
- Processing findings
- Handling AI remediation
- Verifying proposed fixes
- Returning structured audit results
- Handling errors
- Providing a health endpoint


16. API
-------

HEALTH CHECK

GET /api/health

Example response:

{
  "status": "ok",
  "service": "Smart Contract FixGPT API",
  "version": "0.1.0"
}


AUDIT CONTRACT

POST /api/audit

Example request:

{
  "contractName": "VulnerableVault",
  "solidityVersion": "0.8.20",
  "sourceCode": "pragma solidity ^0.8.20; contract VulnerableVault {}"
}

Example response:

{
  "auditId": "audit_xxxxxxxxx",
  "status": "completed",
  "score": 70,
  "findings": []
}


INVALID INPUT HANDLING

If the Solidity source cannot be analyzed, the backend returns a failed
audit status rather than treating invalid Solidity as a successful
zero-finding audit.

This distinction prevents malformed source code from being incorrectly
presented as secure.


17. FRONTEND
------------

The React frontend provides the user-facing security-analysis experience.

Frontend responsibilities include:

- Solidity source input
- Solidity file upload
- Contract analysis
- Loading states
- Error handling
- Security score display
- Finding summaries
- Detailed vulnerability information
- AI remediation results
- Fix verification
- Audit history
- Security-focused user interface

The frontend communicates with the backend through the /api routes.

Development server:

    http://localhost:5173


18. FRONTEND STRUCTURE
----------------------

frontend/
    src/
        App.tsx
        App.css
        index.css
        main.tsx

    public/
    package.json
    tsconfig.json
    vite.config.ts


19. EXAMPLE VULNERABLE CONTRACT
-------------------------------

pragma solidity ^0.8.20;

contract VulnerableVault {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);

        balances[msg.sender] -= amount;
    }
}

This contract demonstrates a reentrancy-related interaction pattern because
the external call occurs before the balance update.

A safer implementation can follow the checks-effects-interactions pattern:

pragma solidity ^0.8.20;

contract SaferVault {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount;

        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
    }
}

The proposed remediation is then re-analyzed by the verification workflow.


20. ERROR HANDLING
------------------

The platform separates successful audit results from analysis failures.

Examples of frontend behavior include:

- Loading indicator during analysis
- Disabled analyze button while processing
- User-facing error messages
- Recovery after failed analysis
- Invalid Solidity error handling

Malformed Solidity should not appear as a successful audit with zero findings.


21. TESTING
-----------

ANALYZER TESTS

From the analyzer directory:

    cd analyzer
    npm test

The analyzer test suite validates representative vulnerability detectors,
Solidity parsing, and structured security findings.


BACKEND TYPE CHECKING

    cd backend
    npx tsc --noEmit


FRONTEND PRODUCTION BUILD

    cd frontend
    npm run build


22. INSTALLATION
----------------

PREREQUISITES

Install:

- Node.js
- npm
- Git
- WSL Ubuntu (recommended for the development environment)


CLONE REPOSITORY

    git clone https://github.com/anuragreddy23-dot/Smart-Contract-FixGPT-AI-Tool.git
    cd Smart-Contract-FixGPT-AI-Tool


INSTALL ANALYZER

    cd analyzer
    npm install
    cd ..


INSTALL BACKEND

    cd backend
    npm install
    cd ..


INSTALL FRONTEND

    cd frontend
    npm install
    cd ..


23. RUNNING THE PROJECT
-----------------------

START BACKEND

    cd backend
    npm run dev

Backend:

    http://127.0.0.1:5000

Health endpoint:

    http://127.0.0.1:5000/api/health


START FRONTEND

Open a second terminal:

    cd frontend
    npm run dev

Frontend:

    http://localhost:5173


24. COMPLETE PROJECT STRUCTURE
------------------------------

smart-contract-fixgpt/
|
+-- analyzer/
|   +-- detectors/
|   +-- parsers/
|   +-- tests/
|   +-- analyzer.js
|   +-- index.js
|   +-- utils.js
|   +-- package.json
|
+-- backend/
|   +-- src/
|       +-- ai/
|       +-- routes/
|       +-- services/
|       +-- types/
|       +-- server.ts
|   +-- package.json
|
+-- frontend/
|   +-- src/
|       +-- App.tsx
|       +-- App.css
|       +-- index.css
|       +-- main.tsx
|   +-- package.json
|
+-- contracts/
+-- prisma/
+-- reports/
+-- tests/
+-- .gitignore
+-- README.txt


25. DESIGN PRINCIPLES
---------------------

DEFENSE IN DEPTH

Multiple detectors analyze different classes of security patterns instead of
relying on a single detection mechanism.

EXPLAINABILITY

Findings contain descriptions, impact information and recommendations so
users can understand why an issue was reported.

VERIFICATION

AI-generated remediation is re-analyzed instead of being automatically
trusted.

SEPARATION OF RESPONSIBILITIES

The frontend, backend, analyzer and AI remediation components are separated
into distinct layers.

HUMAN REVIEW

Automated analysis is intended to assist developers and security researchers.
Security-critical code still requires appropriate manual review and testing.


26. CURRENT PROJECT SCOPE
-------------------------

The current implementation focuses on:

- Solidity source-code analysis
- AST parsing
- Custom vulnerability detectors
- Structured security findings
- Severity and confidence classification
- AI-assisted remediation
- Fixed-code generation
- Re-analysis
- Fix verification
- Security scoring
- React-based frontend
- REST backend
- Audit history
- Error handling
- Loading states


27. LIMITATIONS
---------------

Smart Contract FixGPT is an internship and research-oriented project.

The analyzer combines static analysis, security heuristics and AI-assisted
reasoning. Therefore, it may produce:

- False positives
- False negatives
- Heuristic findings
- Incomplete vulnerability coverage
- Incorrect remediation suggestions
- Findings requiring manual validation

The current detector implementations should not be interpreted as complete
formal verification of smart contract security.

The security score is an indicator of detected issues and does not guarantee
that a contract is secure.

For production deployments involving significant value, independent
professional security review remains important.


28. FUTURE SCOPE
----------------

ADVANCED STATIC ANALYSIS

- Slither integration
- Solhint integration
- Solidity compiler integration
- Symbolic execution
- Control-flow analysis
- Data-flow analysis

ADVANCED AI SECURITY ANALYSIS

- LLM-assisted vulnerability reasoning
- Context-aware remediation
- Multi-file contract analysis
- Cross-contract vulnerability reasoning
- False-positive reduction
- Security-aware code generation

ADVANCED VERIFICATION

- Automated compilation of generated fixes
- Unit-test generation
- Foundry test generation
- Fuzz testing
- Invariant testing
- Differential analysis between vulnerable and fixed versions

ADDITIONAL INPUT SOURCES

- ZIP project uploads
- GitHub repositories
- Contract addresses
- Multi-contract projects
- Deployed contract source code

REPORTING

- PDF security reports
- Markdown reports
- JSON export
- Detailed audit history
- Vulnerability trend tracking

SECURITY INTELLIGENCE

- DeFi-specific detectors
- Advanced oracle analysis
- Upgradeability analysis
- Cross-contract dependency analysis
- Known vulnerability pattern databases


29. SECURITY DISCLAIMER
-----------------------

Smart Contract FixGPT is an automated security-assistance tool.

It should not be considered a replacement for:

- Professional smart contract audits
- Formal verification
- Comprehensive testing
- Manual security review
- Economic and protocol-level analysis

Generated remediation code should be reviewed, compiled, tested and
independently validated before being deployed to a production blockchain
environment.


30. PROJECT OUTCOME
-------------------

Smart Contract FixGPT demonstrates how a full-stack Web3 security
application can combine:

    Solidity
        +
    AST Analysis
        +
    Security Detectors
        +
    Backend Services
        +
    AI-Assisted Remediation
        +
    Fix Verification
        +
    React Dashboard

The resulting workflow helps developers identify potential vulnerabilities,
understand their security impact, explore remediation options, and verify
proposed fixes through re-analysis.


31. INTERNSHIP PROJECT INFORMATION
----------------------------------

Project Name:
    Smart Contract FixGPT AI Tool

Domain:
    Web3 / Blockchain Security

Project Type:
    Full-Stack Web3 Security Application

Focus:
    Smart Contract Security Analysis and AI-Assisted Remediation

Primary Technologies:
    Solidity, JavaScript, TypeScript, React, Node.js, Express,
    AST-based Static Analysis

Core Concept:
    Detect -> Explain -> Fix -> Re-Analyze -> Report

Developed as part of a Web3 and Blockchain Development internship.


32. AUTHOR
----------

Anurag Reddy

B.Tech - Computer Science and Engineering

Areas of Interest:
- Web3
- Blockchain Security
- Solidity
- Smart Contract Development
- Smart Contract Auditing


LICENSE
-------

This project is intended for educational, research and internship purposes.
