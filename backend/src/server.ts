import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import auditRouter from "./routes/audit.routes.js";

dotenv.config();

const app = express();

const PORT = process.env.PORT || 5000;

app.use(cors());

app.use(express.json({ limit: "2mb" }));

app.get("/api/health", (_req, res) => {
  res.json({
    status: "ok",
    service: "Smart Contract FixGPT API",
    version: "0.1.0"
  });
});

app.use("/api/audit", auditRouter);

app.listen(PORT, () => {
  console.log(`FixGPT backend running on http://localhost:${PORT}`);
});