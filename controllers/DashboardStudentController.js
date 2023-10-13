const Enrollment = require("../models/enrollment");
const Course = require("../models/course");
const Progress = require("../models/progress");

exports.getStudentDashboardData = async (req, res) => {
  try {
    if (req.user.role !== "student") {
      return res.status(403).send("Permission denied");
    }

    const enrolledCourses = await Enrollment.find({
      studentId: req.user.id,
    }).populate(
      "courseId",
      "title thumbnail description authorId creationDate ratingAverage"
    );

    const totalEnrolledCourses = enrolledCourses.length;

    const latestProgress = await Progress.find({ studentId: req.user.id })
      .sort({ updatedAt: -1 })
      .limit(5)
      .populate(
        "courseId",
        "title thumbnail description authorId creationDate "
      );

    const dashboardData = {
      studentId: req.user.id,
      totalEnrolledCourses,
      enrolledCourses,
      latestProgress,
    };

    res.status(200).send(dashboardData);
  } catch (err) {
    res.status(500).send(err.message);
  }
};
