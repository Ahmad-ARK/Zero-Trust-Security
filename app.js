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
app.use(express.static("public"));


app.use(
    session({
        name: 'sessionId',
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax', // or 'strict' depending on your use case
        },
        store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
    })
);


mongoose.connect(process.env.MONGO_URI);


app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));



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

    const currentIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const userAgent = req.get("User-Agent");

    if (user && (await bcrypt.compare(password, user.password))) {
        const isNewDevice =
            user.lastLoginIP !== currentIP || user.lastUserAgent !== userAgent;

        req.session.regenerate(async (err) => {
            if (err) return res.send("Session error");

            req.session.userId = user._id;

            // Update IP and device info
            user.lastLoginIP = currentIP;
            user.lastUserAgent = userAgent;
            await user.save();

            if (isNewDevice) {
                // Optionally log or send alert
                console.log("New device/IP detected for user:", username);
                req.session.deviceWarning = true;
            }

            res.redirect("/dashboard");
        });
    } else {
        res.send("Invalid credentials");
    }
});



app.get("/dashboard", requireAuth, (req, res) => {
    const warning = req.session.deviceWarning || false;
    delete req.session.deviceWarning;
    res.render("index", { warning });
});



app.post("/analyze", requireAuth, (req, res) => {
    let text = req.body.text;
    console.log("Received text:", text);

    // ✅ Truncate input to prevent model errors
    const maxWords = 512;
    text = text.split(" ").slice(0, maxWords).join(" ");

    const python = spawn("python", ["sentiment.py", text]);

    let result = "";
    let errorOutput = "";

    python.stdout.on("data", (data) => {
        result += data.toString();
        console.log(`This is raw resuly ${result}`);
    });

    python.stderr.on("data", (data) => {
        errorOutput += data.toString();
    });

    python.on("close", (code) => {
        if (code !== 0) {
            console.error("Python script error:", errorOutput);
            return res.status(500).send("Error analyzing sentiment");
        }

        try {
            
            const parsedResult = JSON.parse(result.trim()); // ✅ Fix here
            console.log("Sentiment result:", parsedResult);
            res.render("result", { result: parsedResult }); // ✅ Send object
        } catch (e) {
            console.error("Result parsing failed:", e);
            res.status(500).send("Invalid sentiment result format");
        }
    });

});



app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/login");
    });
});

app.listen(3000, () => console.log("Server running on http://localhost:3000"));
