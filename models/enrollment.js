const mongoose = require("mongoose");

const EnrollmentSchema = new mongoose.Schema({
  courseId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Course",
    required: true,
  },
  studentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  status: { type: String, enum: ["accepted", "rejected", "pending"] },
});

module.exports = mongoose.model("Enrollment", EnrollmentSchema);
