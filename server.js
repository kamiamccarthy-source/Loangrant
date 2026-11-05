
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

// CUSTOMER AUTHENTICATION

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

function createToken(customerId) {
  const secret = process.env.JWT_SECRET;

  if (!secret || secret.length < 32) {
    throw new Error("JWT_SECRET must contain at least 32 characters.");
  }

  const payload = Buffer.from(JSON.stringify({
    id: customerId,
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7
  })).toString("base64url");

  const signature = crypto
    .createHmac("sha256", secret)
    .update(payload)
    .digest("base64url");

  return payload + "." + signature;
}

function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ")
      ? header.slice(7)
      : "";

    const parts = token.split(".");

    if (parts.length !== 2) {
      return res.status(401).json({
        success: false,
        message: "Please log in."
      });
    }

    const secret = process.env.JWT_SECRET;

    if (!secret || secret.length < 32) {
      return res.status(500).json({
        success: false,
        message: "Authentication is not configured."
      });
    }

    const expected = crypto
      .createHmac("sha256", secret)
      .update(parts[0])
      .digest();

    const received = Buffer.from(parts[1], "base64url");

    if (
      received.length !== expected.length ||
      !crypto.timingSafeEqual(received, expected)
    ) {
      return res.status(401).json({
        success: false,
        message: "Invalid login session."
      });
    }

    const payload = JSON.parse(
      Buffer.from(parts[0], "base64url").toString()
    );

    if (
      !Number.isSafeInteger(payload.id) ||
      payload.id < 1 ||
      payload.exp < Math.floor(Date.now() / 1000)
    ) {
      return res.status(401).json({
        success: false,
        message: "Your session has expired."
      });
    }

    req.customerId = payload.id;
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid login session."
    });
  }
}

// CUSTOMER REGISTRATION

app.post("/api/auth/register", authLimiter, async (req, res) => {
  try {
    const {
      full_name,
      phone,
      email,
      password
    } = req.body;

    if (
      typeof full_name !== "string" ||
      full_name.trim().length < 2 ||
      full_name.trim().length > 120
    ) {
      return res.status(400).json({
        success: false,
        message: "Enter your full name."
      });
    }

    if (!validPhone(phone || "")) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid phone number with country code."
      });
    }

    if (
      typeof password !== "string" ||
      password.length < 10 ||
      password.length > 72
    ) {
      return res.status(400).json({
        success: false,
        message: "Password must contain 10 to 72 characters."
      });
    }

    const normalizedEmail = email
      ? String(email).trim().toLowerCase()
      : null;

    if (
      normalizedEmail &&
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)
    ) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid email address."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO customers
       (full_name, email, phone, password_hash)
       VALUES ($1, $2, $3, $4)
       RETURNING id, full_name, email, phone, phone_verified`,
      [
        full_name.trim(),
        normalizedEmail,
        phone,
        passwordHash
      ]
    );

    const customer = result.rows[0];
    const token = createToken(customer.id);

    res.status(201).json({
      success: true,
      message: "Account created successfully.",
      token,
      customer
    });

  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        success: false,
        message: "This phone number is already registered."
      });
    }

    console.error("Registration error:", error.message);

    res.status(500).json({
      success: false,
      message: "Unable to create your account."
    });
  }
});

// CUSTOMER LOGIN

app.post("/api/auth/login", authLimiter, async (req, res) => {
  try {
    const { phone, password } = req.body;

    if (
      !validPhone(phone || "") ||
      typeof password !== "string" ||
      password.length > 72
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid phone number or password."
      });
    }

    const result = await pool.query(
      `SELECT id, full_name, email, phone,
              phone_verified, password_hash
       FROM customers
       WHERE phone = $1`,
      [phone]
    );

    if (
      result.rows.length === 0 ||
      !(await bcrypt.compare(
        password,
        result.rows[0].password_hash
      ))
    ) {
      return res.status(401).json({
        success: false,
        message: "Incorrect phone number or password."
      });
    }

    const customer = result.rows[0];
    const token = createToken(customer.id);

    delete customer.password_hash;

    res.json({
      success: true,
      message: "Login successful.",
      token,
      customer
    });

  } catch (error) {
    console.error("Login error:", error.message);

    res.status(500).json({
      success: false,
      message: "Unable to log in."
    });
  }
});

// CUSTOMER PROFILE

app.get("/api/auth/me", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, full_name, email, phone,
              phone_verified, created_at
       FROM customers
       WHERE id = $1`,
      [req.customerId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Customer account not found."
      });
    }

    res.json({
      success: true,
      customer: result.rows[0]
    });

  } catch (error) {
    console.error("Profile error:", error.message);

    res.status(500).json({
      success: false,
      message: "Unable to load customer profile."
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
