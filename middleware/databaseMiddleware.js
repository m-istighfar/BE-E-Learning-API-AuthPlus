const mongoose = require("mongoose");

const databaseMiddleware = (req, res, next) => {
  try {
    mongoose.connect(
      "mongodb://mongo:zR6zyrFlpxU6sLFz5oPv@containers-us-west-90.railway.app:7854",
      {
        useNewUrlParser: true,

        useUnifiedTopology: true,
      }
    );
    console.log("Connected to the database.");
    next();
  } catch (error) {
    console.error("Error connecting to the database:", error);
  }
};

module.exports = databaseMiddleware;
