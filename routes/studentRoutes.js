const express = require("express");
const router = express.Router();
const DashboardStudentController = require("../controllers/DashboardStudentController");
const ProgressController = require("../controllers/ProgressController");
const courseController = require("../controllers/courseController");
const userController = require("../controllers/userController");
const enrollmentController = require("../controllers/enrollmentController");

router.get("/viewcourse", courseController.listCourses);
router.post("/sendEnrollRequest", enrollmentController.sendEnrollRequest);
router.get(
  "/readEnrolledCourseContent",
  enrollmentController.readEnrolledCourseContent
);
router.post("/unenrollFromCourse", enrollmentController.unenrollCourse);
router.post("/markCourseCompleted", ProgressController.markCourseAsCompleted);
router.put("/updateProfile", userController.updateProfile);

router.post("/addReview/:courseId", courseController.addReview);
router.get("/dashboard", DashboardStudentController.getStudentDashboardData);

router.get("/progress/:courseId", ProgressController.getProgress);
router.put("/progress/:courseId", ProgressController.updateProgress);

module.exports = router;
