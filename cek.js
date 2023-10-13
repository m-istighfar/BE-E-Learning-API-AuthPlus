// app.js

require("dotenv").config();

const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const swaggerUi = require("swagger-ui-express");
const yaml = require("yaml");
const fs = require("fs");

const databaseMiddleware = require("./middleware/databaseMiddleware");
const authMiddleware = require("./middleware/authenticationMiddleware");
const authorizationMiddleware = require("./middleware/authorizationMiddleware");

const authRoutes = require("./routes/authRoutes");
const adminRoutes = require("./routes/adminRoutes");
const authorRoutes = require("./routes/authorRoutes");
const studentRoutes = require("./routes/studentRoutes");

const app = express();
app.use(bodyParser.json());
app.use(cors());
app.use(cookieParser());

const openApiPath = "doc/openapi.yaml";
const file = fs.readFileSync(openApiPath, "utf8");
const swaggerDocument = yaml.parse(file);
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocument));
app.use(databaseMiddleware);

app.use("/auth", authRoutes);
app.use(
  "/admin",
  authMiddleware,
  authorizationMiddleware(["admin"]),
  adminRoutes
);
app.use(
  "/author",
  authMiddleware,
  authorizationMiddleware(["author"]),
  authorRoutes
);
app.use(
  "/student",
  authMiddleware,
  authorizationMiddleware(["student"]),
  studentRoutes
);

const port = process.env.PORT;
app.listen(port, () => console.log(`Listening on port ${port}...`));

// authController
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/user");
const cache = require("memory-cache");
const nodemailer = require("nodemailer");
const crypto = require("crypto");

const {
  JWT_SIGN,
  JWT_REFRESH_SIGN,
  ACCESS_TOKEN_EXPIRATION,
  REFRESH_TOKEN_EXPIRATION,
} = require("../config/jwt");

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
  user.verificationToken = undefined; // Clear the token after verification
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

// authRoutes.js

const express = require("express");
const router = express.Router();
const AuthController = require("../controllers/AuthController");
const PasswordResetController = require("../controllers/PasswordResetController");
const cache = require("memory-cache");

const { rateLimit } = require("express-rate-limit");

const UserRateLimitStore = require("../routes/UserRateLimitStore");

const windowMs = 15 * 60 * 1000;

const userRateLimitStoreInstance = new UserRateLimitStore(windowMs);

const userLoginLimiter = rateLimit({
  store: userRateLimitStoreInstance,
  windowMs: windowMs,
  max: 5,
  skipSuccessfulRequests: true,
  message: "Too many failed login attempts, please try again after 15 minutes.",
  keyGenerator: (req) => {
    const key = req.body.username;
    console.log(`Generating key for rate limiter: ${key}`);
    return key;
  },
});

router.post("/login", userLoginLimiter, AuthController.login);
router.post("/login-session", userLoginLimiter, AuthController.loginWihSession);

router.post("/register", AuthController.register);
router.get("/verify-email/:token", AuthController.verifyEmail);
router.post("/refreshToken", AuthController.refreshTokenHandler);

router.post("/logout-session", AuthController.logoutWithSession);

router.post(
  "/request-password-reset",
  PasswordResetController.requestPasswordReset
);

router.post(
  "/reset-password/:resetToken",
  PasswordResetController.resetPassword
);

router.get("/rate-limit-data", (req, res) => {
  const storeData = userRateLimitStoreInstance.getAllData();

  res.json(storeData);
});

router.post("/rate-limit-reset/:key", async (req, res) => {
  const { key } = req.params;
  const keyWasReset = await userRateLimitStoreInstance.resetKey(key);

  if (keyWasReset) {
    res.json({ message: `Key ${key} reset.` });
  } else {
    res.status(404).json({ message: `Key ${key} not found.` });
  }
});

router.post("/rate-limit-reset-all", (req, res) => {
  userRateLimitStoreInstance.resetAll();
  res.send({ message: "All rate limits reset" });
});

router.get("/cache-data", (req, res) => {
  const cacheObject = JSON.parse(cache.exportJson());
  res.json(cacheObject);
});

module.exports = router;

// user model

const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  role: { type: String, required: true, enum: ["admin", "author", "student"] },
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  verified: { type: Boolean, default: false },
  verificationToken: String,
});

module.exports = mongoose.model("User", UserSchema);

// .env

JWT_SIGN = your - access - token - secret - key;
JWT_REFRESH_SIGN = your - refresh - token - secret - key;
ACCESS_TOKEN_EXPIRATION = "10m";
REFRESH_TOKEN_EXPIRATION = "7d";
PORT = 3000;
