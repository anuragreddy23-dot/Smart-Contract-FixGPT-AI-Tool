import parser from "@solidity-parser/parser";

export function parseSolidity(sourceCode) {
  try {
    const ast = parser.parse(sourceCode, {
      loc: true,
      range: true
    });

    return {
      success: true,
      ast,
      errors: []
    };
  } catch (error) {
    return {
      success: false,
      ast: null,
      errors: [
        error instanceof Error
          ? error.message
          : "Unable to parse Solidity source code"
      ]
    };
  }
}