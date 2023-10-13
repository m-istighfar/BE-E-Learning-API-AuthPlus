const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/user");
const cache = require("memory-cache");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
require("dotenv").config();
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

const {
  JWT_SIGN,
  JWT_REFRESH_SIGN,
  ACCESS_TOKEN_EXPIRATION,
  REFRESH_TOKEN_EXPIRATION,
} = require("../config/jwt");

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      const existingUser = await User.findOne({ googleId: profile.id });

      if (existingUser) {
        return done(null, existingUser);
      }

      const newUser = new User({
        googleId: profile.id,
        username: profile.displayName,
        email: profile.emails[0].value,
        role: "student",
        verified: true,
      });
      await newUser.save();

      done(null, newUser);
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "daiqijb105@gmail.com",
    pass: "elrvbtfvypzvosdr",
  },
});

const sendVerificationEmail = async (email, token) => {
  const verificationLink = `http://localhost:3000/auth/verify-email/${token}`;

  const mailOptions = {
    from: "daiqijb105@gmail.com",
    to: email,
    subject: "Email Verification",
    text: `Click on the link to verify your email: ${verificationLink}`,
  };

  await transporter.sendMail(mailOptions);
};

const register = async (req, res) => {
  const { username, email, password, role } = req.body;

  const existingUser = await User.findOne({ username });
  if (existingUser)
    return res.status(400).json({ error: "User already exists" });

  try {
    const verificationToken = crypto.randomBytes(32).toString("hex");
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      role,
      verificationToken,
    });

    await newUser.save();

    await sendVerificationEmail(newUser.email, verificationToken);

    res.status(200).json({
      message: "User successfully registered",
      data: newUser,
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
};

const verifyEmail = async (req, res) => {
  const { token } = req.params;

  const user = await User.findOne({ verificationToken: token });
  if (!user) {
    return res.status(400).json({ error: "Invalid verification token." });
  }

  user.verified = true;
  user.verificationToken = undefined;
  await user.save();

  res.status(200).json({ message: "Email verified successfully!" });
};

const login = async (req, res) => {
  const { username, password } = req.body;

  try {
    const existingUser = await User.findOne({ username });
    if (!existingUser)
      return res.status(400).json({ error: "User does not exist" });

    if (!existingUser.verified)
      return res.status(400).json({
        error: "Email not verified. Please verify your email first.",
      });

    const isPasswordCorrect = await bcrypt.compare(
      password,
      existingUser.password
    );

    if (isPasswordCorrect) {
      const accessToken = jwt.sign(
        {
          username: existingUser.username,
          id: existingUser._id,
          role: existingUser.role,
        },
        JWT_SIGN,
        { expiresIn: ACCESS_TOKEN_EXPIRATION }
      );

      const refreshToken = jwt.sign(
        {
          username: existingUser.username,
          id: existingUser._id,
          role: existingUser.role,
        },
        JWT_REFRESH_SIGN,
        { expiresIn: REFRESH_TOKEN_EXPIRATION }
      );

      res.status(200).json({
        message: "Login successful",
        accessToken,
        refreshToken,
        accessTokenExp: ACCESS_TOKEN_EXPIRATION,
        refreshTokenExp: REFRESH_TOKEN_EXPIRATION,
      });
    } else {
      res.status(400).json({ error: "Password is incorrect" });
    }
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
};

const loginWihSession = async (req, res) => {
  const { username, password } = req.body;

  try {
    const existingUser = await User.findOne({ username });
    if (!existingUser)
      return res.status(400).json({ error: "User does not exist" });

    if (!existingUser.verified)
      return res.status(400).json({
        error: "Email not verified. Please verify your email first.",
      });

    const isPasswordCorrect = await bcrypt.compare(
      password,
      existingUser.password
    );

    if (isPasswordCorrect) {
      const accessToken = jwt.sign(
        {
          username: existingUser.username,
          id: existingUser._id,
          role: existingUser.role,
        },
        JWT_SIGN,
        { expiresIn: ACCESS_TOKEN_EXPIRATION }
      );

      const refreshToken = jwt.sign(
        {
          username: existingUser.username,
          id: existingUser._id,
          role: existingUser.role,
        },
        JWT_REFRESH_SIGN,
        { expiresIn: REFRESH_TOKEN_EXPIRATION }
      );

      res.cookie("accessToken", accessToken, {
        httpOnly: true,
        maxAge: 60 * 60 * 1000,
      });

      res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });
      res.status(200).json({
        message: "Login successful",
        accessToken,
        refreshToken,
        accessTokenExp: ACCESS_TOKEN_EXPIRATION,
        refreshTokenExp: REFRESH_TOKEN_EXPIRATION,
      });
    } else {
      res.status(400).json({ error: "Password is incorrect" });
    }
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
};

const refreshTokenHandler = async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(403).json({ error: "Refresh token not provided" });
  }

  let decodedToken;
  try {
    decodedToken = jwt.verify(refreshToken, JWT_REFRESH_SIGN);
  } catch (err) {
    return res.status(403).json({ error: "Invalid refresh token" });
  }

  const user = await User.findById(decodedToken.id);

  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  const accessToken = jwt.sign(
    { username: user.username, id: user._id, role: user.role },
    JWT_SIGN,
    { expiresIn: ACCESS_TOKEN_EXPIRATION }
  );

  res.status(200).json({
    accessToken: accessToken,
    accessTokenExp: ACCESS_TOKEN_EXPIRATION,
  });
};

const logoutWithSession = (req, res) => {
  let accessToken = req.cookies["accessToken"];

  if (!accessToken && req.headers.authorization) {
    accessToken = req.headers.authorization.split(" ")[1];
  }

  if (accessToken) {
    const expiresIn = jwt.decode(accessToken).exp * 1000 - Date.now();
    cache.put(accessToken, true, expiresIn);
  }

  res.clearCookie("accessToken");
  res.clearCookie("refreshToken");
  res.status(200).json({ message: "Logged out successfully" });
};

module.exports = {
  register,
  verifyEmail,
  login,
  refreshTokenHandler,
  loginWihSession,
  logoutWithSession,
};
