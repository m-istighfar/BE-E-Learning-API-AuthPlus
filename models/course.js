const mongoose = require("mongoose");

const ReviewSchema = new mongoose.Schema({
  studentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },

  rating: Number,
  review: String,
});

const CourseSchema = new mongoose.Schema({
  title: String,
  description: String,
  thumbnail: String,
  authorId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  creationDate: Date,
  reviews: [ReviewSchema],
  ratingAverage: {
    type: Number,
    default: 0,
  },
});

module.exports = mongoose.model("Course", CourseSchema);
