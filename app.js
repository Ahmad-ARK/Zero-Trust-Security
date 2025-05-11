const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const dotenv = require("dotenv");
const { spawn } = require("child_process");
const User = require("./models/User");

dotenv.config();
const app = express();

app.use(express.urlencoded({ extended: true })); // <-- Add this
app.use(express.json()); // Good for JSON-based APIs

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
  })
);

// Middleware to protect routes
const requireAuth = (req, res, next) => {
  if (!req.session.userId) return res.redirect("/login");
  next();
};

// Routes
app.get("/", (req, res) => res.redirect("/login"));

app.get("/login", (req, res) => res.render("login"));
app.get("/signup", (req, res) => res.render("signup"));

app.post("/signup", async (req, res) => {
  const { username, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  try {
    await User.create({ username, password: hash });
    res.redirect("/login");
  } catch {
    res.send("User already exists or error occurred.");
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (user && (await bcrypt.compare(password, user.password))) {
    req.session.userId = user._id;
    res.redirect("/dashboard");
  } else {
    res.send("Invalid credentials");
  }
});

app.get("/dashboard", requireAuth, (req, res) => {
  res.render("index");
});


app.post("/analyze", requireAuth, (req, res) => {
  const text = req.body.text;
  console.log("Received text:", text);

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
      console.error("Python script error:", errorOutput);
      return res.status(500).send("Error analyzing sentiment");
    }

    console.log("Sentiment result:", result);
    res.render("result", { result: result.trim() }); // Trim just in case
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

app.listen(3000, () => console.log("Server running on http://localhost:3000"));
