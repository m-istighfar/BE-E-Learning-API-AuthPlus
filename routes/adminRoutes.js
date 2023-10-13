const express = require("express");
const router = express.Router();
const userController = require("../controllers/userController");
const DashboardAdminController = require("../controllers/DashboardAdminController");
const LearningPathController = require("../controllers/LearningPathController");
const courseController = require("../controllers/courseController");

router.post("/createUser", userController.createUser);
router.put("/updateUser/:id", userController.updateUser);
router.delete("/deleteUser/:id", userController.deleteUser);
router.get("/listUsers", userController.listUsers);
router.post("/assignRole/", userController.assignRole);

router.post("/createCourse", courseController.createCourse);
router.put("/updateCourse/:id", courseController.updateCourse);
router.delete("/deleteCourse/:id", courseController.deleteCourse);
router.get("/listCourses", courseController.listCourses);

router.get("/dashboard", DashboardAdminController.getAdminDashboardData);

//tambah learning path
router.post("/createLearningPath", LearningPathController.createLearningPath);
router.get("/listLearningPaths", LearningPathController.listLearningPaths);
router.put(
  "/updateLearningPath/:id",
  LearningPathController.updateLearningPath
);
router.delete(
  "/deleteLearningPath/:id",
  LearningPathController.deleteLearningPath
);
router.post("/addCourse", LearningPathController.addCourseToPath);
router.delete(
  "/deleteCourse/:pathId/:courseId",
  LearningPathController.deleteCourseFromPath
);

module.exports = router;
