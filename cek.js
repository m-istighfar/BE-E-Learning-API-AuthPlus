//app.js

require("dotenv").config();

const express = require("express");
const bodyParser = require("body-parser");
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

// authenticationMiddleware
const jwt = require("jsonwebtoken");
const { JWT_SIGN } = require("../config/jwt.js");

const authenticationMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decodedToken = jwt.verify(token, JWT_SIGN);
    req.user = decodedToken;
    next();
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
};

module.exports = authenticationMiddleware;

//authorizationMiddleware

const jwt = require("jsonwebtoken");
const { JWT_SIGN } = require("../config/jwt.js");

const authorizationMiddleware = (allowedRoles) => {
  return (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const token = authHeader.split(" ")[1];

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

// AuthController

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/user");
const { JWT_SIGN } = require("../config/jwt");

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

    console.log(isPasswordCorrect);

    if (isPasswordCorrect) {
      const token = jwt.sign(
        {
          username: existingUser.username,
          id: existingUser._id,
          role: existingUser.role,
        },
        JWT_SIGN
      );

      console.log(token);

      res.status(200).json({ message: "Login successful", token: token });
    } else {
      res.status(400).json({ error: "Password is incorrect" });
    }
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
};

module.exports = {
  register,
  login,
};

//authRoutes

const express = require("express");
const router = express.Router();
const AuthController = require("../controllers/AuthController");

router.post("/register", AuthController.register);
router.post("/login", AuthController.login);

module.exports = router;
