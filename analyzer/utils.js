export function getSourceLine(sourceCode, lineNumber) {
  if (!sourceCode || !lineNumber) {
    return "";
  }

  const lines = sourceCode.split(/\r?\n/);

  return lines[lineNumber - 1] || "";
}

export function getSourceSnippet(
  sourceCode,
  startLine,
  endLine = startLine
) {
  if (!sourceCode || !startLine) {
    return "";
  }

  const lines = sourceCode.split(/\r?\n/);

  const start = Math.max(1, startLine);
  const end = Math.min(lines.length, endLine);

  return lines
    .slice(start - 1, end)
    .join("\n");
}

export function getContextSnippet(
  sourceCode,
  lineNumber,
  before = 2,
  after = 3
) {
  if (!sourceCode || !lineNumber) {
    return "";
  }

  const lines = sourceCode.split(/\r?\n/);

  const start = Math.max(1, lineNumber - before);
  const end = Math.min(lines.length, lineNumber + after);

  return lines
    .slice(start - 1, end)
    .join("\n");
}