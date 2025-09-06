const express = require('express');
const { MongoClient } = require('mongodb');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname)));

// MongoDB Connection URI
const uri = "mongodb://localhost:27017";
const client = new MongoClient(uri);
const dbName = "aivivid";
const collectionName = "users";

// Connect to MongoDB
async function connectToMongoDB() {
    try {
        await client.connect();
        console.log("Connected to MongoDB");
        return client.db(dbName);
    } catch (error) {
        console.error("Error connecting to MongoDB:", error);
        process.exit(1);
    }
}

// API endpoint for user registration
app.post('/api/signup', async (req, res) => {
    const { name, email, password } = req.body;
    
    if (!name || !email || !password) {
        return res.status(400).json({ success: false, message: "All fields are required" });
    }
    
    try {
        const db = client.db(dbName);
        const usersCollection = db.collection(collectionName);
        
        // Check if user already exists
        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ success: false, message: "Email already registered" });
        }
        
        // Hash the password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        // Create new user document
        const newUser = {
            name,
            email,
            password: hashedPassword,
            createdAt: new Date()
        };
        
        // Insert user into database
        const result = await usersCollection.insertOne(newUser);
        
        res.status(201).json({ 
            success: true, 
            message: "User registered successfully",
            userId: result.insertedId
        });
        
    } catch (error) {
        console.error("Error during registration:", error);
        res.status(500).json({ success: false, message: "Server error during registration" });
    }
});

// API endpoint for user login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ success: false, message: "Email and password are required" });
    }
    
    try {
        const db = client.db(dbName);
        const usersCollection = db.collection(collectionName);
        
        // Find user by email
        const user = await usersCollection.findOne({ email });
        if (!user) {
            return res.status(401).json({ success: false, message: "Invalid credentials" });
        }
        
        // Compare passwords
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ success: false, message: "Invalid credentials" });
        }
        
        // Password matches, user authenticated
        res.status(200).json({ 
            success: true, 
            message: "Login successful",
            user: {
                id: user._id,
                name: user.name,
                email: user.email
            }
        });
        
    } catch (error) {
        console.error("Error during login:", error);
        res.status(500).json({ success: false, message: "Server error during login" });
    }
});

// Start the server
connectToMongoDB().then(() => {
    app.listen(port, () => {
        console.log(`Server running on port ${port}`);
    });
});