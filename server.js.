
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();

app.use(helmet());
app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === "true"
    ? { rejectUnauthorized: false }
    : undefined
});

const PORT = process.env.PORT || 3000;

const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

const otpStore = new Map();

function generateOtp() {
  return crypto.randomInt(100000, 1000000).toString();
}

function validPhone(phone) {
  return /^\+?[1-9]\d{9,14}$/.test(phone);
}

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS customers (
      id BIGSERIAL PRIMARY KEY,
      full_name VARCHAR(120) NOT NULL,
      email VARCHAR(254),
      phone VARCHAR(20) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      phone_verified BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS loan_applications (
      id BIGSERIAL PRIMARY KEY,
      customer_id BIGINT NOT NULL REFERENCES customers(id),
      amount NUMERIC(15,2) NOT NULL,
      purpose TEXT NOT NULL,
      monthly_income NUMERIC(15,2) NOT NULL,
      repayment_months INTEGER NOT NULL,
      status VARCHAR(20) DEFAULT 'pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
}

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    application: "LoanGrant",
    status: "running"
  });
});

// Temporary development OTP endpoint.
// Never expose OTPs through an API in production.
app.post("/api/auth/request-otp", otpLimiter, async (req, res) => {
  try {
    const { phone } = req.body;

    if (!validPhone(phone || "")) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid phone number."
      });
    }

    const otp = generateOtp();
    const otpHash = await bcrypt.hash(otp, 10);

    otpStore.set(phone, {
      hash: otpHash,
      expires: Date.now() + 5 * 60 * 1000,
      attempts: 0
    });

    if (process.env.NODE_ENV !== "production") {
      return res.json({
        success: true,
        message: "Development OTP generated.",
        developmentOtp: otp
      });
    }

    return res.status(503).json({
      success: false,
      message: "SMS verification is not configured yet."
    });
  } catch (error) {
    console.error("OTP error:", error.message);
    res.status(500).json({
      success: false,
      message: "Unable to process request."
    });
  }
});

app.post("/api/auth/verify-otp", otpLimiter, async (req, res) => {
  try {
    const { phone, otp } = req.body;
    const record = otpStore.get(phone);

    if (!record || !/^\d{6}$/.test(otp || "")) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired OTP."
      });
    }

    if (Date.now() > record.expires || record.attempts >= 5) {
      otpStore.delete(phone);
      return res.status(400).json({
        success: false,
        message: "OTP expired. Request a new one."
      });
    }

    record.attempts++;

    if (!(await bcrypt.compare(otp, record.hash))) {
      return res.status(400).json({
        success: false,
        message: "Incorrect OTP."
      });
    }

    otpStore.delete(phone);

    res.json({
      success: true,
      message: "Phone number verified."
    });
  } catch (error) {
    console.error("Verification error:", error.message);
    res.status(500).json({
      success: false,
      message: "Verification failed."
    });
  }
});

app.get("/", (req, res) => {
  res.sendFile(require("path").join(__dirname, "public", "index.html"));
});

app.use(express.static("public"));

async function startServer() {
  try {
    await initializeDatabase();
    app.listen(PORT, () => {
      console.log(`LoanGrant running on port ${PORT}`);
    });
  } catch (error) {
    console.error("Startup failed:", error.message);
    process.exit(1);
  }
}

startServer();
