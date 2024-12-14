// routes/auth.js
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const router = express.Router();

// Register a new user
router.post('/register', async (req, res) => {
    const { email, password, fullName, role } = req.body;
  
    try {
      // Check if user already exists
      const existingUser  = await User.findOne({ email });
      if (existingUser ) {
        return res.status(400).json({ message: 'User  already exists.' });
      }
  
      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser  = new User({
        email,
        password: hashedPassword,
        fullName,
        role,
      });
  
      await newUser .save();
      res.status(201).json({ message: 'User  registered successfully!' });
    } catch (error) {
      console.error('Error registering user:', error); // Log the error
      res.status(500).json({ message: 'Error registering user', error });
    }
  });

// Login user
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Create and assign a token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Middleware to authenticate JWT
const authenticateJWT = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) return res.sendStatus(403);
  
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) return res.sendStatus(403);
      req.user = user;
      next();
    });
  };
  
  // Get user profile
  router.get('/profile', authenticateJWT, async (req, res) => {
    try {
      const user = await User.findById(req.user.id).select('-password'); // Exclude password from response
      if (!user) return res.status(404).json({ message: 'User  not found' });
      res.json(user);
    } catch (error) {
      res.status(500).json({ message: 'Server error' });
    }
  });

module.exports = router;