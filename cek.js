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

// AuthController.js

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/user");

const {
  JWT_SIGN,
  JWT_REFRESH_SIGN,
  ACCESS_TOKEN_EXPIRATION,
  REFRESH_TOKEN_EXPIRATION,
} = require("../config/jwt");

const register = async (req, res) => {
  const { username, email, password, role } = req.body;

  const existingUser = await User.findOne({ username });
  if (existingUser)
    return res.status(400).json({ error: "User already exists" });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      role,
    });

    await newUser.save();

    res.status(200).json({
      message: "User successfully registered",
      data: newUser,
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
};

const login = async (req, res) => {
  const { username, password } = req.body;

  try {
    const existingUser = await User.findOne({ username });
    if (!existingUser)
      return res.status(400).json({ error: "User does not exist" });

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

      // Generate refresh token
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

      // Generate refresh token
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
        maxAge: 60 * 60 * 1000, // 1 hour
      });

      res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });
      res.status(200).json({ message: "Login successful" });
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

  // Generate a new access token
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
  res.clearCookie("accessToken");
  res.clearCookie("refreshToken");
  res.status(200).json({ message: "Logged out successfully" });
};

module.exports = {
  register,
  login,
  refreshTokenHandler,
  loginWihSession,
  logoutWithSession,
};

// AuthRoutes.js

const express = require("express");
const router = express.Router();
const AuthController = require("../controllers/AuthController");
const { rateLimit } = require("express-rate-limit");

//intermediate
const MemoryStore = rateLimit.MemoryStore;

const store = new MemoryStore();

const loginLimiter = rateLimit({
  store: store,
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true, // Only count failed requests
  message: "Too many failed login attempts, please try again after 15 minutes.",
});
router.post("/login", loginLimiter, AuthController.login);
router.post("/login-session", loginLimiter, AuthController.loginWihSession);

router.post("/register", AuthController.register);
router.post("/refreshToken", AuthController.refreshTokenHandler);

router.post("/logout-session", AuthController.logoutWithSession);

module.exports = router;

// authenticationMiddleware.js
const jwt = require("jsonwebtoken");
const { JWT_SIGN } = require("../config/jwt.js");

const authenticationMiddleware = (req, res, next) => {
  let token;

  // First, check for token in cookies
  if (req.cookies.accessToken) {
    token = req.cookies.accessToken;
  }
  // If not found in cookies, fall back to the Authorization header
  else if (req.headers.authorization) {
    token = req.headers.authorization.split(" ")[1];
  }

  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const decodedToken = jwt.verify(token, JWT_SIGN);
    req.user = decodedToken;
    next();
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
};

module.exports = authenticationMiddleware;

// authorizationMiddleware.js

const jwt = require("jsonwebtoken");
const { JWT_SIGN } = require("../config/jwt.js");

const authorizationMiddleware = (allowedRoles) => {
  return (req, res, next) => {
    let token;

    // First, check for token in cookies
    if (req.cookies.accessToken) {
      token = req.cookies.accessToken;
    }
    // If not found in cookies, fall back to the Authorization header
    else if (req.headers.authorization) {
      token = req.headers.authorization.split(" ")[1];
    }

    if (!token) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    try {
      const decodedToken = jwt.verify(token, JWT_SIGN);

      if (allowedRoles.includes(decodedToken.role)) {
        next();
      } else {
        res.status(401).json({ error: "Unauthorized" });
      }
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  };
};

module.exports = authorizationMiddleware;

// .env

JWT_SIGN = your - access - token - secret - key;
JWT_REFRESH_SIGN = your - refresh - token - secret - key;
ACCESS_TOKEN_EXPIRATION = "10m";
REFRESH_TOKEN_EXPIRATION = "7d";
PORT = 3000;
