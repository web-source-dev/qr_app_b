const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/Userlogin'); // Import the new schema
const UserTokenDb = require('../models/UserToken'); // Import the new schema
const router = express.Router();
const ThemeSelect = require('../models/themeselect');


// POST route for user signup
router.post('/signup', async (req, res) => {
  const { user_name, user_email, user_password } = req.body;

  try {
    // Validate if the required fields are provided
    if (!user_name || !user_email || !user_password) {
      return res.status(400).json({ message: 'Please fill in all fields.' });
    }

    // Check if the email is already registered
    const existingUser = await User.findOne({ user_email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists with this email.' });
    }

    // Hash the password before saving it
    const hashedPassword = await bcrypt.hash(user_password, 10);

    // Create a new user
    const newUser = new User({
      user_name,
      user_email,
      user_password: hashedPassword,
    });

    // Save the user to the database
    await newUser.save();

    res.status(201).json({ message: 'User created successfully!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

// POST route for user login
router.post('/login', async (req, res) => {
  const { user_email, user_password } = req.body;

  try {
    if (!user_email || !user_password) {
      return res.status(400).json({ message: 'Please fill in both email and password.' });
    }

    const user = await User.findOne({ user_email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    const isMatch = await bcrypt.compare(user_password, user.user_password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    const token = jwt.sign(
      { userId: user._id, username: user.user_name },
      process.env.JWT_SECRET_KEY,
      { expiresIn: '1h' }
    );

    const tokenSave = new UserTokenDb({
      userId: user._id,
      user_token: token,
      expiresAt: Date.now() + (60 * 60 * 1000), // Token expires in 1 hour
    });

    await tokenSave.save();

    res.status(200).json({
      message: 'Login successful!',
      token,
      user_name: user.user_name,
      user_email: user.user_email,
      user_id: user._id,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error. Please try again.' });
  }
});


router.post('/checkuserapi', async (req, res) => {
  const { UserToken } = req.body;

  // Ensure token is provided in the request
  if (!UserToken) {
    return res.status(400).json({ tokensts: 1, msg: 'Token is required' });
  }

  try {
    // Look up the token in the UserToken collection
    const tokenCheck = await UserTokenDb.findOne({ user_token: UserToken });

    if (!tokenCheck) {
      // Return 401 if token not found or invalid
      return res.status(401).json({ tokensts: 1, msg: 'Token invalid or expired' });
    } else {
      // Token verified successfully
      return res.status(200).json({ tokensts: 0, msg: 'Token successfully verified' });
    }
  } catch (error) {
    console.error('Error verifying user token:', error);
    return res.status(500).json({ tokensts: 1, msg: 'Internal server error' });
  }
});

router.post('/theme', async (req, res) => {
  try {
    const themeData = req.body;
    console.log('Received theme data:', themeData); // Debug log

    // Ensure userId is in the themeData
    if (!themeData.userId) {
      return res.status(400).json({ message: 'User ID is required' });
    }

    // Save the theme to the database
    const theme = new ThemeSelect(themeData);
    await theme.save();

    res.status(200).json({ message: 'Theme saved successfully' });
  } catch (error) {
    console.error('Error saving theme:', error);
    res.status(500).json({ message: 'Error saving theme' });
  }
});



module.exports = router;
