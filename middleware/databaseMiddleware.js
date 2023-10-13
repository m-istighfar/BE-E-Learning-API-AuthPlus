const mongoose = require("mongoose");

const databaseMiddleware = (req, res, next) => {
  try {
    mongoose.connect("mongodb://127.0.0.1:27017/week16", {
      useNewUrlParser: true,

      useUnifiedTopology: true,
    });
    console.log("Connected to the database.");
    next();
  } catch (error) {
    console.error("Error connecting to the database:", error);
  }
};

module.exports = databaseMiddleware;
