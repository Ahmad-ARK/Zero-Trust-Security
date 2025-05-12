require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const { spawn } = require("child_process");
const User = require("./models/User");
const geoip = require("geoip-lite");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const app = express();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

// Session setup
app.use(
  session({
    name: "sessionId",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
    },
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
  })
);

// Rate limiting
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: "Too many login attempts. Try again in 15 minutes.",
});

// Connect MongoDB
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// Middleware to protect routes
const requireAuth = async (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.redirect("/login");

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) return res.redirect("/login");
    req.user = user;
    next();
  } catch (err) {
    console.error("JWT Error:", err.message);
    res.redirect("/login");
  }
};

// Routes
app.get("/", (req, res) => res.redirect("/login"));

app.get("/login", (req, res) => res.render("login"));
app.get("/signup", (req, res) => res.render("signup"));

app.post("/signup", async (req, res) => {
  const { username, password, email } = req.body;

  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) return res.send("User already exists.");

    const hash = await bcrypt.hash(password, 10);
    await User.create({ username, password: hash, email });

    res.redirect("/login");
  } catch (error) {
    console.error("Signup error:", error);
    res.send("An error occurred.");
  }
});

app.post("/login", loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });

  const currentIP = req.headers["x-forwarded-for"]
    ? req.headers["x-forwarded-for"].split(",")[0]
    : req.socket.remoteAddress;
  const formattedIP = currentIP.replace(/^.*:/, "");

  if (formattedIP !== "127.0.0.1" && formattedIP !== "::1") {
    const geo = geoip.lookup(formattedIP);
    if (geo?.country === "IN") {
      return res.status(403).send("Access denied from your region.");
    }
  }

  const userAgent = req.get("User-Agent");

  if (user && (await bcrypt.compare(password, user.password))) {
    const isNewDevice =
      user.lastLoginIP !== currentIP || user.lastUserAgent !== userAgent;

    user.lastLoginIP = currentIP;
    user.lastUserAgent = userAgent;
    await user.save();

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
    });

    return res.redirect(isNewDevice ? "/dashboard?warn=1" : "/dashboard");
  }

  res.send("Invalid credentials");
});

app.get("/dashboard", requireAuth, (req, res) => {
  const warning = req.query.warn === "1";
  res.render("index", { warning });
});

app.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/login");
});

app.post("/analyze", requireAuth, (req, res) => {
  let text = req.body.text;
  const maxWords = 512;
  text = text.split(" ").slice(0, maxWords).join(" ");

  const python = spawn("python", ["sentiment.py", text]);

  let result = "";
  let errorOutput = "";

  python.stdout.on("data", (data) => {
    result += data.toString();
  });

  python.stderr.on("data", (data) => {
    errorOutput += data.toString();
  });

  python.on("close", (code) => {
    if (code !== 0) {
      console.error("Python error:", errorOutput);
      return res.status(500).send("Sentiment analysis failed.");
    }

    try {
      const parsedResult = JSON.parse(result.trim());
      res.render("result", { result: parsedResult });
    } catch (e) {
      console.error("Parsing error:", e);
      res.status(500).send("Invalid sentiment result format.");
    }
  });
});

app.listen(3000, () =>
  console.log("🚀 Server running on http://localhost:3000")
);
