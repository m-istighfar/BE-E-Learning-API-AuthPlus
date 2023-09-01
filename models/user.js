const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  role: { type: String, required: true, enum: ["admin", "author", "student"] },
});

module.exports = mongoose.model("User", UserSchema);
