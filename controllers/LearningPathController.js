const LearningPath = require("../models/learningpath");
const Course = require("../models/course");

exports.createLearningPath = async (req, res) => {
  try {
    if (["admin"].includes(req.user.role)) {
      const { title, description, courses } = req.body;

      const newLearningPath = new LearningPath({
        title,
        description,
        courses,
      });

      await newLearningPath.save();

      res.status(201).send({ message: " succes ", newLearningPath });
    } else {
      res.status(403).send("Permission denied");
    }
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
};

exports.listLearningPaths = async (req, res) => {
  try {
    const learningPaths = await LearningPath.find().populate(
      "courses",
      "title thumbnail description authorId creationDate"
    );
    res.status(200).send({ message: " succes ", learningPaths });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
};

exports.updateLearningPath = async (req, res) => {
  try {
    const { id } = req.params;
    const { title, description, courses } = req.body;

    const learningPath = await LearningPath.findById(id);
    if (!learningPath) {
      return res.status(404).send({ message: "Learning path not found" });
    }

    learningPath.title = title;
    learningPath.description = description;
    learningPath.courses = courses;

    await learningPath.save();

    res.status(200).send({ message: " succes ", learningPath });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
};

exports.deleteLearningPath = async (req, res) => {
  try {
    const { id } = req.params;

    console.log(id);

    const learningPath = await LearningPath.findById(id);

    if (!learningPath) {
      return res.status(404).send({ message: "Learning path not found" });
    }

    await LearningPath.deleteOne({ _id: id });
    res.status(200).send({ message: "Learning path deleted successfully" });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
};

exports.addCourseToPath = async (req, res) => {
  try {
    const { pathId, courseId } = req.body;

    const learningPath = await LearningPath.findById(pathId).populate();

    if (!learningPath) {
      return res.status(404).send({ message: "Learning path not found" });
    }

    if (req.user.role === "author") {
      const course = await Course.findById(courseId);
      if (!course || course.author !== req.user._id) {
        return res
          .status(403)
          .send({ message: "You can only add your own courses" });
      }
    }

    learningPath.courses.push(courseId);
    await learningPath.save();
    res.status(200).send({ message: "succes", learningPath });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
};

exports.deleteCourseFromPath = async (req, res) => {
  try {
    const { pathId, courseId } = req.params;

    const learningPath = await LearningPath.findById(pathId);

    if (!learningPath) {
      return res.status(404).send({ message: "Learning path not found" });
    }

    if (req.user.role === "author") {
      return res
        .status(403)
        .send({ message: "You don't have permission to delete courses" });
    }

    const index = learningPath.courses.indexOf(courseId);
    if (index > -1) {
      learningPath.courses.splice(index, 1);
    } else {
      return res
        .status(404)
        .send({ message: "Course not found in the learning path" });
    }

    await learningPath.save();
    res
      .status(200)
      .send({ message: "Course deleted from learning path successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: err.message });
  }
};
