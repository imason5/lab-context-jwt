const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const User = require("../models/User.model");

// ******* SIGNUP ROUTE *******
router.post("/signup", async (req, res, next) => {
  /* Get back the payload from your request, as it's a POST you can access req.body */
  const { email, password } = req.body;

  // Check if email and password are provided
  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  // Check if user already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(400).json({ message: "User already exists" });
  }
  /* Hash the password using bcryptjs */
  const salt = await bcrypt.genSalt(13);
  const hashedPassword = await bcrypt.hash(password, salt);
  /* Record your user to the DB */
  const newUser = new User({ email, password: hashedPassword });
  await newUser.save();

  res.status(201).json({ message: "User registered successfully" });
});

// ******* LOGIN ROUTE *******
router.post("/login", async (req, res, next) => {
  /* Get back the payload from your request, as it's a POST you can access req.body */
  const { email, password } = req.body;
  // Check if email and password are provided
  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }
  /* Try to get your user from the DB */

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  /* If your user exists, check if the password is correct */

  const isPasswordCorrect = await bcrypt.compare(password, user.password);
  if (!isPasswordCorrect) {
    return res.status(400).json({ message: "Invalid credentials" });
  }

  /* If your password is correct, sign the JWT using jsonwebtoken */
  const authToken = jwt.sign(
    {
      userId: user._id,
    },
    process.env.TOKEN_SECRET,
    {
      expiresIn: "6h",
      algorithm: "HS256",
    }
  );

  res.json({ message: "Login successful", token: authToken });
});

router.get("/verify", (req, res, next) => {
  // You need to use the middleware there, if the request passes the middleware, it means your token is good
  res.json("Pinging verify");
});

module.exports = router;
