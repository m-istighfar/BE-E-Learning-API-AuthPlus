require("dotenv").config();

const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const swaggerUi = require("swagger-ui-express");
const yaml = require("yaml");
const fs = require("fs");
const passport = require("passport");
const session = require("express-session");

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
app.use(
  session({
    secret: "your_secret_key", // This should be a long random string
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }, // Set to true if you're using HTTPS
  })
);

app.use(passport.initialize());
app.use(passport.session());

const openApiPath = "doc/openapi.yaml";
const file = fs.readFileSync(openApiPath, "utf8");
const swaggerDocument = yaml.parse(file);
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocument));
app.use(databaseMiddleware);

app.get("/", (req, res) => {
  res.render("login.ejs");
});
app.get("/success", (req, res) => {
  res.json({
    message: "You're logged in!",
  });
});
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
