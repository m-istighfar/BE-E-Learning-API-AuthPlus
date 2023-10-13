const User = require("../models/user");
const Course = require("../models/course");
const Enrollment = require("../models/enrollment");

exports.getAdminDashboardData = async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).send("Permission denied");
    }

    const totalUsers = await User.countDocuments();

    const totalCourses = await Course.countDocuments();

    const totalEnrollments = await Enrollment.countDocuments();

    const latestUsers = await User.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .select("username email role");

    const latestCourses = await Course.find()
      .sort({ creationDate: -1 })
      .limit(5)
      .select(
        "title thumbnail description authorId creationDate ratingAverage"
      );

    const latestEnrollments = await Enrollment.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .populate(
        "courseId",
        "title thumbnail description authorId creationDate ratingAverage"
      )
      .populate("studentId", "username email");

    const dashboardData = {
      totalUsers,
      totalCourses,
      totalEnrollments,
      latestUsers,
      latestCourses,
      latestEnrollments,
    };

    res.status(200).send(dashboardData);
  } catch (err) {
    res.status(500).send(err.message);
  }
};
