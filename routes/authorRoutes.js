const express = require("express");
const router = express.Router();
const DashboardAuthorController = require("../controllers/DashboardAuthorController");
const learningPathController = require("../controllers/LearningPathController");
const courseController = require("../controllers/courseController");
const userController = require("../controllers/userController");
const enrollmentController = require("../controllers/enrollmentController");

router.post("/createCourse", courseController.createOwnCourse);
router.get("/listCourses", courseController.listCourses);
router.put("/updateOwnedCourse/:id", courseController.updateOwnCourse);
router.delete("/deleteOwnedCourse/:id", courseController.deleteOwnCourse);
router.get("/listEnrollRequests", enrollmentController.listEnrollRequests);
router.post(
  "/updateEnrollmentStatus/:requestId",
  enrollmentController.updateEnrollmentStatus
);

router.put("/updateProfile", userController.updateProfile);

router.get("/listowncourses", courseController.listOwnCourses);
router.get("/dashboard", DashboardAuthorController.getAuthorDashboardData);

router.get("/listLearningPaths", learningPathController.listLearningPaths);
router.post("/addCoursetoPath", learningPathController.addCourseToPath);
router.delete(
  "/deleteCoursefromPath/:pathId/:courseId",
  learningPathController.deleteCourseFromPath
);
module.exports = router;
