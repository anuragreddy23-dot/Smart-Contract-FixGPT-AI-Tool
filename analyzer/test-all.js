import fs from "fs";
import { analyzeSolidity } from "./analyzer.js";

const source = fs.readFileSync(
  "./test-security.sol",
  "utf8"
);

const result = analyzeSolidity(source);

console.log("");
console.log("========== SECURITY FINDINGS ==========");
console.log("");

for (const finding of result.findings) {
  console.log(
    `${finding.id} => ${finding.title} | ${finding.severity} | ${finding.confidence}`
  );
}

console.log("");
console.log("========== TOTAL ==========");
console.log("");

console.log(
  `Total findings: ${result.findings.length}`
);

console.log("");
console.log("========== FINDING IDs ==========");
console.log("");

console.log(
  [...new Set(result.findings.map(f => f.id))]
    .sort()
    .join(", ")
);