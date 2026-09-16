import solc from "solc";

export interface SolidityCompileResult {
  success: boolean;
  errors: string[];
  warnings: string[];
  contractNames?: string[];
}

export function compileSolidity(
  sourceCode: string,
  contractName: string
): SolidityCompileResult {
  const input = {
    language: "Solidity",

    sources: {
      "Contract.sol": {
        content: sourceCode
      }
    },

    settings: {
      optimizer: {
        enabled: false
      },

      outputSelection: {
        "*": {
          "*": [
            "abi",
            "evm.bytecode"
          ]
        }
      }
    }
  };

  try {
    const output = JSON.parse(
      solc.compile(JSON.stringify(input))
    );

    const errors: string[] = [];
    const warnings: string[] = [];

    for (const item of output.errors || []) {
      const message =
        item.formattedMessage ||
        item.message ||
        "Unknown Solidity compiler message";

      if (item.severity === "error") {
        errors.push(message);
      } else {
        warnings.push(message);
      }
    }

    if (errors.length > 0) {
      return {
        success: false,
        errors,
        warnings
      };
    }

    const compiledContracts =
      output.contracts?.["Contract.sol"];

    if (!compiledContracts) {
      return {
        success: false,
        errors: [
          "Solidity compiler did not produce contract output."
        ],
        warnings
      };
    }

    const contractNames =
      Object.keys(compiledContracts);

    if (contractNames.length === 0) {
      return {
        success: false,
        errors: [
          "Solidity compiler produced no contracts."
        ],
        warnings
      };
    }

    /*
     * The UI contract name is user-provided and may not
     * match the Solidity contract declaration.
     *
     * If the requested name exists, use it.
     * Otherwise, when there is exactly one compiled
     * contract, accept that contract.
     */
    if (!compiledContracts[contractName]) {
      if (contractNames.length === 1) {
        console.warn(
          `Requested contract "${contractName}" was not found. ` +
          `Using compiled contract "${contractNames[0]}" instead.`
        );

        return {
          success: true,
          errors: [],
          warnings,
          contractNames
        };
      }

      return {
        success: false,
        errors: [
          `Contract "${contractName}" was not found in compiler output. ` +
          `Available contracts: ${contractNames.join(", ")}`
        ],
        warnings,
        contractNames
      };
    }

    return {
      success: true,
      errors: [],
      warnings,
      contractNames
    };

  } catch (error) {
    return {
      success: false,
      errors: [
        error instanceof Error
          ? error.message
          : "Unable to compile Solidity source code."
      ],
      warnings: []
    };
  }
}