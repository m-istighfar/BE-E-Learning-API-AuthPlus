const express = require("express");
const router = express.Router();
const AuthController = require("../controllers/AuthController");
const PasswordResetController = require("../controllers/PasswordResetController");
const cache = require("memory-cache");
const passport = require("passport");
const jwt = require("jsonwebtoken");
const { JWT_SIGN } = require("../config/jwt");

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

router.get(
  "/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

router.get(
  "/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/login",
  }),
  (req, res) => {
    // User is authenticated with Google at this point

    // Now, generate a JWT token for the user with their role and other details
    const tokenPayload = {
      id: req.user.id, // Assuming user object has an ID
      role: req.user.role, // Assuming user object has a role
      // Add any other required fields
    };

    const token = jwt.sign(tokenPayload, JWT_SIGN, { expiresIn: "1h" }); // Example: Token expires in 1 hour

    // Store the token in a cookie or send it in the response
    res.cookie("accessToken", token, { httpOnly: true });
    res.redirect("/success"); // Redirect to home or wherever you want
  }
);

module.exports = router;
