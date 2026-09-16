import { Router, Request, Response } from "express";
import {
  AuditRequest,
  AuditResponse
} from "../types/audit.js";
import { analyzeContract } from "../services/audit.service.js";

const router = Router();

router.post(
  "/",
  async (
    req: Request<{}, {}, AuditRequest>,
    res: Response<AuditResponse>
  ) => {
    const {
      contractName,
      solidityVersion,
      sourceCode
    } = req.body;

    if (!contractName || !solidityVersion || !sourceCode) {
      return res.status(400).json({
        auditId: "",
        status: "failed",
        score: 0,
        findings: []
      });
    }

    try {
      const result = await analyzeContract({
        contractName,
        solidityVersion,
        sourceCode
      });

      return res.status(200).json(result);
    } catch (error) {
      console.error("Audit error:", error);

      return res.status(500).json({
        auditId: "",
        status: "failed",
        score: 0,
        findings: []
      });
    }
  }
);

export default router;