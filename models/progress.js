const mongoose = require("mongoose");

const ProgressSchema = new mongoose.Schema({
  studentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  courseId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Course",
    required: true,
  },
  completion: {
    type: Number,
    default: 0,
  },
});

module.exports = mongoose.model("Progress", ProgressSchema);
