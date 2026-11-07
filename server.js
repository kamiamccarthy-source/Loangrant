
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();
app.set("trust proxy", 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
scriptSrcAttr: ["'unsafe-inline'"],
styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"]
    }
  }
}));
app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
    connectionTimeoutMillis: 10000,
  ssl: process.env.PGSSL === "true"
    ? { rejectUnauthorized: false }
    : undefined
});

const PORT = process.env.PORT || 3000;
// CUSTOMER KYC ENCRYPTION
function getCustomerDataKey() {
  const key = process.env.CUSTOMER_DATA_KEY;

  if (!key || !/^[a-fA-F0-9]{64}$/.test(key)) {
    throw new Error(
      "CUSTOMER_DATA_KEY must be exactly 64 hexadecimal characters."
    );
  }

  return Buffer.from(key, "hex");
}

function encryptCustomerData(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    getCustomerDataKey(),
    iv
  );

  const encrypted = Buffer.concat([
    cipher.update(value, "utf8"),
    cipher.final()
  ]);

  const tag = cipher.getAuthTag();

  return [
    iv.toString("base64"),
    tag.toString("base64"),
    encrypted.toString("base64")
  ].join(".");
}

function decryptCustomerData(value) {
  const parts = value.split(".");

  if (parts.length !== 3) {
    throw new Error("Invalid encrypted customer data.");
  }

  const [iv, tag, encrypted] = parts;

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    getCustomerDataKey(),
    Buffer.from(iv, "base64")
  );

  decipher.setAuthTag(Buffer.from(tag, "base64"));

  return Buffer.concat([
    decipher.update(Buffer.from(encrypted, "base64")),
    decipher.final()
  ]).toString("utf8");
}
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

  await pool.query(`
    CREATE TABLE IF NOT EXISTS customer_kyc (
      id BIGSERIAL PRIMARY KEY,
      customer_id BIGINT NOT NULL REFERENCES customers(id),
      loan_application_id BIGINT REFERENCES loan_applications(id),
      bvn_encrypted TEXT NOT NULL,
      bank_name_encrypted TEXT NOT NULL,
      account_number_encrypted TEXT NOT NULL,
      account_name_encrypted TEXT NOT NULL,
      consent_given BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (loan_application_id)
    )
  `);



  await pool.query(`
    CREATE TABLE IF NOT EXISTS admin_kyc_access_logs (
      id BIGSERIAL PRIMARY KEY,
      admin_username VARCHAR(120) NOT NULL,
      customer_kyc_id BIGINT NOT NULL
        REFERENCES customer_kyc(id),
      action VARCHAR(30) NOT NULL,
      accessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
function createAdminToken() {
  const secret = process.env.JWT_SECRET;

  if (!secret || secret.length < 32) {
    throw new Error("JWT_SECRET is not configured.");
  }

  const payload = Buffer.from(JSON.stringify({
    role: "admin",
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 8
  })).toString("base64url");

  const signature = crypto
    .createHmac("sha256", secret)
    .update(payload)
    .digest("base64url");

  return payload + "." + signature;
}

function requireAdmin(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ")
      ? header.slice(7)
      : "";

    const parts = token.split(".");
    const secret = process.env.JWT_SECRET;

    if (
      parts.length !== 2 ||
      !secret ||
      secret.length < 32
    ) {
      return res.status(401).json({
        success: false,
        message: "Administrator login required."
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
        message: "Invalid administrator session."
      });
    }

    const payload = JSON.parse(
      Buffer.from(parts[0], "base64url").toString()
    );

    if (
      payload.role !== "admin" ||
      !Number.isSafeInteger(payload.exp) ||
      payload.exp <= Math.floor(Date.now() / 1000)
    ) {
      return res.status(403).json({
        success: false,
        message: "Administrator access denied."
      });
    }

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid administrator session."
    });
  }
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
  typeof payload.id !== "string" ||
  !/^[1-9]\d*$/.test(payload.id) ||
  !Number.isSafeInteger(payload.exp) ||
  payload.exp <= Math.floor(Date.now() / 1000)
)
     {
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
// ADMINISTRATOR LOGIN

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

function safeCompare(a, b) {
  const first = Buffer.from(String(a));
  const second = Buffer.from(String(b));

  return first.length === second.length &&
    crypto.timingSafeEqual(first, second);
}

app.post("/api/admin/login", adminLimiter, (req, res) => {
  const username = process.env.ADMIN_USERNAME;
  const password = process.env.ADMIN_PASSWORD;

  if (
    !username ||
    !password ||
    password.length < 16
  ) {
    return res.status(503).json({
      success: false,
      message: "Administrator credentials are not configured."
    });
  }

  const suppliedUsername =
    typeof req.body.username === "string"
      ? req.body.username
      : "";

  const suppliedPassword =
    typeof req.body.password === "string"
      ? req.body.password
      : "";

  if (
    !safeCompare(suppliedUsername, username) ||
    !safeCompare(suppliedPassword, password)
  ) {
    return res.status(401).json({
      success: false,
      message: "Incorrect administrator credentials."
    });
  }

  res.json({
    success: true,
    message: "Administrator login successful.",
    token: createAdminToken()
  });
});
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

// SUBMIT LOAN APPLICATION

app.post("/api/loans/apply", requireAuth, authLimiter, async (req, res) => {
  try {
    const {
      amount,
      purpose,
      monthly_income,
      repayment_months
    } = req.body;

    const loanAmount = Number(amount);
    const income = Number(monthly_income);
    const months = Number(repayment_months);

    if (
      !Number.isFinite(loanAmount) ||
      loanAmount < 1000 ||
      loanAmount > 5000000
    ) {
      return res.status(400).json({
        success: false,
        message: "Loan amount must be between ₦1,000 and ₦5,000,000."
      });
    }

    if (
      typeof purpose !== "string" ||
      purpose.trim().length < 10 ||
      purpose.trim().length > 1000
    ) {
      return res.status(400).json({
        success: false,
        message: "Please explain your loan purpose (10–1000 characters)."
      });
    }

    if (
      !Number.isFinite(income) ||
      income <= 0 ||
      income > 100000000
    ) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid monthly income."
      });
    }

    if (
      !Number.isInteger(months) ||
      months < 1 ||
      months > 36
    ) {
      return res.status(400).json({
        success: false,
        message: "Repayment period must be between 1 and 36 months."
      });
    }

    const existing = await pool.query(
      `SELECT id FROM loan_applications
       WHERE customer_id = $1 AND status = 'pending'
       LIMIT 1`,
      [req.customerId]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({
        success: false,
        message: "You already have an application awaiting review."
      });
    }

    const result = await pool.query(
      `INSERT INTO loan_applications
       (customer_id, amount, purpose, monthly_income, repayment_months)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, amount, purpose, monthly_income,
                 repayment_months, status, created_at`,
      [
        req.customerId,
        loanAmount,
        purpose.trim(),
        income,
        months
      ]
    );

    res.status(201).json({
      success: true,
      message: "Your loan application has been submitted for review.",
      application: result.rows[0]
    });

  } catch (error) {
    console.error("Loan application error:", error.message);

    res.status(500).json({
      success: false,
      message: "Unable to submit your application."
    });
  }
});

// VIEW CUSTOMER LOAN APPLICATIONS

app.get("/api/loans/my-applications", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, amount, purpose, monthly_income,
              repayment_months, status, created_at
       FROM loan_applications
       WHERE customer_id = $1
       ORDER BY created_at DESC`,
      [req.customerId]
    );

    res.json({
      success: true,
      applications: result.rows
    });

  } catch (error) {
    console.error("Applications error:", error.message);

    res.status(500).json({
      success: false,
      message: "Unable to retrieve your applications."
    });
  }
});
// ADMINISTRATOR DASHBOARD APIs

app.get("/api/admin/summary", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM customers) AS total_customers,
        (SELECT COUNT(*) FROM loan_applications) AS total_applications,
        (SELECT COUNT(*) FROM loan_applications
          WHERE status = 'pending') AS pending_applications,
        (SELECT COUNT(*) FROM loan_applications
          WHERE status = 'approved') AS approved_applications,
        (SELECT COUNT(*) FROM loan_applications
          WHERE status = 'rejected') AS rejected_applications
    `);

    res.json({
      success: true,
      summary: result.rows[0]
    });
  } catch (error) {
    console.error("Admin summary error:", error.message);
    res.status(500).json({
      success: false,
      message: "Unable to load dashboard summary."
    });
  }
});

app.get("/api/admin/customers", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, full_name, email, phone,
             phone_verified, created_at
      FROM customers
      ORDER BY created_at DESC
      LIMIT 100
    `);

    res.json({
      success: true,
      customers: result.rows
    });
  } catch (error) {
    console.error("Admin customers error:", error.message);
    res.status(500).json({
      success: false,
      message: "Unable to retrieve customers."
    });
  }
});

app.get("/api/admin/applications", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        l.id,
        l.customer_id,
        c.full_name,
        c.phone,
        l.amount,
        l.purpose,
        l.monthly_income,
        l.repayment_months,
        l.status,
        l.created_at
      FROM loan_applications l
      JOIN customers c ON c.id = l.customer_id
      ORDER BY l.created_at DESC
      LIMIT 100
    `);

    res.json({
      success: true,
      applications: result.rows
    });
  } catch (error) {
    console.error("Admin applications error:", error.message);
    res.status(500).json({
      success: false,
      message: "Unable to retrieve applications."
    });
  }
});

app.patch(
  "/api/admin/applications/:id/status",
  requireAdmin,
  async (req, res) => {
    try {
      const id = req.params.id;
      const status = req.body.status;

      if (
        !/^[1-9]\d*$/.test(id) ||
        !["approved", "rejected"].includes(status)
      ) {
        return res.status(400).json({
          success: false,
          message: "Invalid application ID or status."
        });
      }

      const result = await pool.query(
        `UPDATE loan_applications
         SET status = $1
         WHERE id = $2
         RETURNING id, status`,
        [status, id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: "Application not found."
        });
      }

      res.json({
        success: true,
        message: "Application status updated.",
        application: result.rows[0],
        funds_disbursed: false
      });
    } catch (error) {
      console.error("Admin status update error:", error.message);
      res.status(500).json({
        success: false,
        message: "Unable to update application status."
      });
    }
  }
);
app.get("/", (req, res) => {
  res.sendFile(require("path").join(__dirname, "public", "index.html"));
});

app.use(express.static(require("path").join(__dirname, "public")));

const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`LoanGrant listening on port ${PORT}`);
});

initializeDatabase()
  .then(() => {
    console.log("LoanGrant database initialized successfully.");
  })
  .catch((error) => {
    console.error(
      "LoanGrant database initialization failed:",
      error.message
    );
  });

