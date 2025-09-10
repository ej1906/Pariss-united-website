// A.I. Credit Attorney Backend Server
// This version is configured for Vercel deployment.

// --- 1. Import Dependencies ---
const express = require('express');
const admin = require('firebase-admin');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

// --- 2. Initialize App and Middleware ---
const app = express();
app.use(cors());
app.use(express.json());

// --- 3. Firebase Admin SDK Configuration ---
// It now reads the service account key from the environment variable
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}
const db = admin.firestore();

// --- 4. Secret Keys from Environment Variables ---
const JWT_SECRET = process.env.JWT_SECRET;
const HUBSPOT_API_KEY = process.env.HUBSPOT_API_KEY;

// --- 5. API Endpoints (The Server's "Doors") ---

// API Endpoint for User Signup
app.post('/api/signup', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ message: "Email and password are required." });
        }

        const userRef = db.collection('users').doc(email);
        const doc = await userRef.get();

        if (doc.exists) {
            return res.status(400).json({ message: "User with this email already exists." });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await userRef.set({
            email: email,
            password: hashedPassword,
            createdAt: new Date()
        });

        res.status(201).json({ message: "User account created successfully." });
    } catch (error) {
        console.error("Signup Error:", error);
        res.status(500).json({ message: "An internal server error occurred." });
    }
});

// API Endpoint for User Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const userRef = db.collection('users').doc(email);
        const doc = await userRef.get();

        if (!doc.exists) {
            return res.status(404).json({ message: "User not found." });
        }

        const user = doc.data();
        const isPasswordCorrect = await bcrypt.compare(password, user.password);

        if (!isPasswordCorrect) {
            return res.status(401).json({ message: "Invalid credentials." });
        }

        const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '1d' });

        res.status(200).json({ message: "Login successful.", token: token });
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ message: "An internal server error occurred." });
    }
});

// --- 6. Start the Server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

// This is necessary for Vercel to handle the Express app
module.exports = app;