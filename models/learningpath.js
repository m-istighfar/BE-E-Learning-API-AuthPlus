const mongoose = require("mongoose");

const learningPathSchema = new mongoose.Schema({
  title: String,
  description: String,
  courses: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Course",
    },
  ],
});

module.exports = mongoose.model("LearningPath", learningPathSchema);
