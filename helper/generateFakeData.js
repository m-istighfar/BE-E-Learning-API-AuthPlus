const mongoose = require("mongoose");
const {
  generateFakeUsers,
  generateFakeCourses,
  generateFakeEnrollments,
  generateFakeLearningPaths,
  generateFakeProgressRecords,
} = require("../helper/helper");

const clearDatabase = require("./clearDatabase");

async function generateFakeData() {
  try {
    await mongoose.connect(
      "mongodb://mongo:zR6zyrFlpxU6sLFz5oPv@containers-us-west-90.railway.app:7854",
      {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      }
    );

    await clearDatabase();

    const numFakeUsers = 20;
    const users = await generateFakeUsers(numFakeUsers);

    const numFakeCourses = 50;
    const courses = await generateFakeCourses(numFakeCourses, users);

    await generateFakeEnrollments(courses, users);

    await generateFakeLearningPaths(courses);

    await generateFakeProgressRecords(courses, users);

    console.log("Fake data generation completed.");
  } catch (error) {
    console.error("Error generating fake data:", error);
  }
}

generateFakeData();

module.exports = generateFakeData;
