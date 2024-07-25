const express = require("express");
const app = express();
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const path = require("path");

app.use(cors());
app.use(express.json());

const secretKey = "abcdef";
const dbPath = path.join(__dirname, "nxtrendz.db");
let db = null;

const initializeDbAndServer = async () => {
    try {
        db = await open({
            filename: dbPath,
            driver: sqlite3.Database
        });

        await db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        `);

        app.listen(3000, () => {
            console.log("Server is running on http://localhost:3000");
        });
    } catch (error) {
        console.log(`DBError: ${error.message}`);
        process.exit(1);
    }
};

initializeDbAndServer();

const verifyToken = (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) return res.status(401).send("Request Denied");

    try {
        const verified = jwt.verify(token, secretKey);
        req.user = verified;
        next();
    } catch (error) {
        res.status(400).send("Invalid Token");
    }
};

app.post("/signup", async (req, res) => {
    try {
        const { username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);

        await db.run(`
            INSERT INTO users (username, password) VALUES (?, ?)
        `, [username, hashedPassword]);

        res.status(201).send("User created successfully");
    } catch (error) {
        res.status(500).send("Error creating user");
    }
});

app.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await db.get(`
            SELECT * FROM users WHERE username = ?
        `, [username]);

        if (!user) return res.status(400).send("User not found");

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).send("Invalid password");

        const token = jwt.sign({ username: user.username }, secretKey);
        res.send({ token });
    } catch (error) {
        res.status(500).send(`Error logging in: ${error.message}`);
    }
});

app.get("/profile", verifyToken, async (req, res) => {
    try {
        const user = await db.get(`
            SELECT username FROM users WHERE username = ?
        `, [req.user.username]);

        if (!user) return res.status(404).send("User not found");

        res.send(`Welcome ${user.username}`);
    } catch (error) {
        res.status(500).send("Error fetching profile");
    }
});
