import 'dotenv/config'; 
import express from "express";
import mysql from "mysql2/promise";
import cors from "cors";
import nodemailer from "nodemailer";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken"; 

const app = express();
app.use(cors());
app.use(express.json());

//  REPLACE with your actual Gmail details and App Password
const transporter = nodemailer.createTransport({
    service: 'gmail', 
    auth: {
        user: 'YOUR_ADMIN_EMAIL@gmail.com', 
        pass: 'YOUR_EMAIL_APP_PASSWORD' 
    }
});

// Database Connection now uses DB_PORT (3306)
const db = await mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    // Use DB_PORT (3306)
    port: process.env.DB_PORT, 
});

console.log("Connected to MySQL Database");

const createTableQuery = `
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    fullname VARCHAR(255),
    email VARCHAR(255),
    username VARCHAR(255) UNIQUE,
    password VARCHAR(255)
);
`;

db.query(createTableQuery)
    .then(() => console.log("Users table ready"))
    .catch((err) => console.log("Table creation failed", err));

// --- JWT Verification Middleware ---
const verifyToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ message: "Access Denied. No token provided." });
    }

    const token = authHeader.split(' ')[1]; 
    
    if (!token) {
        return res.status(401).json({ message: "Access Denied. Token format is invalid." });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next(); 
    } catch (error) {
        return res.status(401).json({ message: "Invalid token or session expired. Please log in again." });
    }
};


// --- Register API ---
app.post("/register", async (req, res) => {
    const { fullname, email, username, password } = req.body;

    if (!fullname || !email || !username || !password) {
        return res.status(400).json({ message: "All fields are required" });
    }

    try {
        const usernameCheckSql = "SELECT username FROM users WHERE username = ?";
        const [userWithSameUsername] = await db.query(usernameCheckSql, [username]);

        if (userWithSameUsername.length > 0) {
            return res.status(409).json({ message: "This username is already taken" });
        }
        
        const emailCheckSql = "SELECT email FROM users WHERE email = ?";
        const [userWithSameEmail] = await db.query(emailCheckSql, [email]);

        if (userWithSameEmail.length > 0) {
            return res.status(409).json({ message: "This email address is already registered" });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const insertSql = "INSERT INTO users (fullname, email, username, password) VALUES (?, ?, ?, ?)";
        await db.query(insertSql, [fullname, email, username, hashedPassword]);

        // Email sending logic here...

        res.json({ message: "Registered Successfully" });

    } catch (err) {
        console.error("Error during registration:", err);
        return res.status(500).json({ message: "Server error during registration." });
    }
});


// --- Login API (Full Name Return) ---
app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    const sql = "SELECT * FROM users WHERE username = ?";
    
    try {
        const [data] = await db.query(sql, [username]);

        if (data.length === 0) {
            return res.status(401).json({ message: "User ID doesn't exist" });
        }

        const user = data[0];
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (passwordMatch) {
            const token = jwt.sign(
                { userId: user.id, username: user.username }, 
                process.env.JWT_SECRET,
                { expiresIn: '1h' } 
            );

            // Send FULL NAME
            return res.json({ 
                message: "Login Successful", 
                token: token, 
                user: { fullname: user.fullname } 
            });

        } else {
            return res.status(401).json({ message: "Password is wrong" });
        }

    } catch (err) {
        console.error("Error during login:", err);
        return res.status(500).json({ message: "Login Failed due to server error." });
    }
});


// --- Protected Route: /dashboard ---
app.get("/dashboard", verifyToken, (req, res) => {
    res.json({ message: "Welcome to the secured dashboard!", user: req.user });
});

//  Node.js Server now runs on PORT (8081)
app.listen(process.env.PORT || 8081, () => {
    console.log(`Server running on port ${process.env.PORT || 8081}`);
});
