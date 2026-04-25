"use strict";

const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const router = express.Router();

app.use(express.json());

const SECRET_KEY = process.env.JWT_SECRET || "supersecretkey";
const PORT = process.env.PORT || 3000;

const db = new sqlite3.Database("./my.db");


db.run(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT
    )
`);


const findUserByEmail = (email) => {
    return new Promise((resolve, reject) => {
        db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
};

const createUser = (name, email, password) => {
    return new Promise((resolve, reject) => {
        db.run(
            `INSERT INTO users (name, email, password) VALUES (?, ?, ?)`,
            [name, email, password],
            function (err) {
                if (err) reject(err);
                else resolve(this.lastID);
            }
        );
    });
};


const verifyToken = (req, res, next) => {
    const authHeader = req.headers["authorization"];

    if (!authHeader) {
        return res.status(403).json({ message: "No token provided" });
    }

    const token = authHeader.split(" ")[1];

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: "Unauthorized" });
        }
        req.userId = decoded.id;
        next();
    });
};


router.post("/register", async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({
                message: "All fields are required",
            });
        }

        const existingUser = await findUserByEmail(email);
        if (existingUser) {
            return res.status(400).json({
                message: "Email already exists",
            });
        }

        const hashedPassword = bcrypt.hashSync(password, 10);

        const userId = await createUser(name, email, hashedPassword);

        const token = jwt.sign({ id: userId }, SECRET_KEY, {
            expiresIn: "24h",
        });

        res.status(201).json({
            user: { id: userId, name, email },
            access_token: token,
        });
    } catch (err) {
        res.status(500).json({ message: "Server error" });
    }
});


router.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                message: "All fields are required",
            });
        }

        const user = await findUserByEmail(email);

        if (!user) {
            return res.status(404).json({
                message: "User not found",
            });
        }

        const isValid = bcrypt.compareSync(password, user.password);

        if (!isValid) {
            return res.status(401).json({
                message: "Invalid password",
            });
        }

        const token = jwt.sign({ id: user.id }, SECRET_KEY, {
            expiresIn: "24h",
        });

        res.status(200).json({
            user: { id: user.id, name: user.name, email: user.email },
            access_token: token,
        });
    } catch (err) {
        res.status(500).json({ message: "Server error" });
    }
});


router.get("/profile", verifyToken, async (req, res) => {
    try {
        const user = await new Promise((resolve, reject) => {
            db.get(
                `SELECT id, name, email FROM users WHERE id = ?`,
                [req.userId],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                }
            );
        });

        res.json(user);
    } catch (err) {
        res.status(500).json({ message: "Server error" });
    }
});


router.get("/", (req, res) => {
    res.send("Auth server running 🚀");
});

app.use(router);

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});