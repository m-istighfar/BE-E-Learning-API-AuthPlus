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

module.exports = {
  register,
  login,
  refreshTokenHandler,
};
