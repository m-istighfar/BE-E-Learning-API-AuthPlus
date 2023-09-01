const Course = require("../models/course");
const Enrollment = require("../models/enrollment");

exports.getAuthorDashboardData = async (req, res) => {
  try {
    if (req.user.role !== "author") {
      return res.status(403).send("Permission denied");
    }

    const ownedCourses = await Course.find({ authorId: req.user.id }).select(
      "title thumbnail description creationDate reviews ratingAverage"
    );

    const ownedCourseIds = [];
    ownedCourses.forEach((course) => ownedCourseIds.push(course._id));

    const totalOwnedCourses = ownedCourses.length;

    const totalEnrollments = await Enrollment.countDocuments({
      courseId: { $in: ownedCourseIds },
    });

    const latestEnrollments = await Enrollment.find({
      courseId: { $in: ownedCourseIds },
    })
      .sort({ createdAt: -1 })
      .limit(5)
      .populate(
        "courseId",
        "title thumbnail description creationDate ratingAverage"
      );

    const dashboardData = {
      authorId: req.user.id,
      totalOwnedCourses,
      totalEnrollments,
      ownedCourses,
      latestEnrollments,
    };

    res.status(200).send(dashboardData);
  } catch (err) {
    res.status(500).send(err.message);
  }
};
