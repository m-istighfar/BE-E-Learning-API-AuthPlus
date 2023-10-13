// Inside a new file, maybe passportConfig.js

const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      // Here, you should check if the user exists in your DB or not.
      // If not, you can create a new user.
      // For this example, I'll just return the profile info.

      return done(null, profile);
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  // You would typically use the id to get the user from your DB
  // For the sake of this example, I'll return an object.
  done(null, { id: id, username: "dummyUser" });
});
