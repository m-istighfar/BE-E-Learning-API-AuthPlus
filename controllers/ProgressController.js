const Progress = require("../models/progress");
const Enrollment = require("../models/enrollment");
const Course = require("../models/course");
const LearningPath = require("../models/learningpath");
const User = require("../models/user");

exports.getProgress = async (req, res) => {
  try {
    const progress = await Progress.findOne({
      studentId: req.user.id,
      courseId: req.params.courseId,
    });
    if (!progress) {
      return res.status(404).send("Progress not found");
    }
    res.status(200).send(progress);
  } catch (err) {
    res.status(500).send(err.message);
  }
};

exports.updateProgress = async (req, res) => {
  try {
    let progress = await Progress.findOne({
      studentId: req.user.id,
      courseId: req.params.courseId,
    });

    if (!progress) {
      progress = new Progress({
        studentId: req.user.id,
        courseId: req.params.courseId,
        completion: req.body.completion,
      });
    } else {
      progress.completion = req.body.completion;
    }
    await progress.save();

    if (progress.completion === 100) {
      const enrollment = await Enrollment.findOne({
        student: req.user.id,
        course: req.params.courseId,
      });

      if (enrollment) {
        enrollment.status = "complete";
        await enrollment.save();
      }
    }

    res.status(200).send(progress);
  } catch (err) {
    res.status(500).send(err.message);
  }
};

exports.markCourseAsCompleted = async (req, res) => {
  const { courseId } = req.body;
  const studentId = req.user.id;

  try {
    const enrollment = await Enrollment.findOneAndUpdate(
      { courseId, studentId, status: "accepted" },
      { status: "completed" },
      { new: true }
    );

    if (!enrollment) {
      return res.status(403).json({
        error: "Not enrolled in this course or enrollment not approved",
      });
    }

    await Progress.findOneAndUpdate(
      { courseId, studentId },
      { completion: 100 },
      { new: true }
    );

    res.status(200).json(enrollment);
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({
      error: "An error occurred while marking the course as completed",
    });
  }
};
