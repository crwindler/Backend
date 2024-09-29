const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt'); // Import bcrypt for password hashing
const cors = require('cors'); // Import CORS middleware
require('dotenv').config(); // To load environment variables from a .env file

const app = express();
const PORT = process.env.PORT || 5000;

// Enable CORS for all routes
app.use(cors());

// Middleware to parse incoming JSON
app.use(express.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected successfully'))
  .catch(err => console.error('MongoDB connection error:', err));

// Define a User model
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', UserSchema); // Use the UserSchema

// Test route to check if server is working
app.get('/', (req, res) => {
  res.send('Hello from Express backend!');
});

// User registration route with password hashing
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Check if the user already exists
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ msg: 'User already exists' });
    }

    // Hash the password before saving the user
    const salt = await bcrypt.genSalt(10); // Generate salt for hashing
    const hashedPassword = await bcrypt.hash(password, salt); // Hash the password with the salt

    // Create new user with hashed password
    user = new User({ name, email, password: hashedPassword });
    await user.save();

    // Respond with a success message and the user data (excluding password)
    res.status(201).json({
      msg: 'User registered successfully',
      user: { name: user.name, email: user.email }
    });
  } catch (error) {
    console.error('Error registering user:', error); // Log the complete error object
    res.status(500).send('Server error');
  }
});

// User login route
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if the user exists
    let user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ msg: 'User not found' });
    }

    // Compare the provided password with the stored hashed password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ msg: 'Invalid credentials' });
    }

    // If the password matches, send a success response
    res.status(200).json({ msg: 'Login successful' });
  } catch (error) {
    console.error('Error during login:', error.message);
    res.status(500).send('Server error');
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
