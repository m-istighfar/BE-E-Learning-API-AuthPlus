# Simple E-Learning Platform

## Overview

This is a simple e-learning platform API built with Node.js and Express, focusing on providing different functionalities for users with different roles, such as Admin, Author, and Student. The application offers features like user authentication and authorization, course management, learning path management, and a feature-rich dashboard for admins, authors, and students.

## Deployment

This project is deployed on Cyclic. You can access the API at [https://inquisitive-outerwear.cyclic.app/api-docs/](https://inquisitive-outerwear.cyclic.app/api-docs/).

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Tech Stack](#tech-stack)
- [Database Setup and Schema](#database-setup-and-schema)
- [Database Relationships](#database-relationships)
- [Installation](#installation)
- [Environment Variables](#environment-variables)
- [Testing and Faker.js Integration](#testing-and-fakerjs-integration)
- [API Endpoints](#api-endpoints)
- [Contributing](#contributing)
- [License](#license)

## Key Features

### For Administrators

- **User Management**: Ability to create, update, and delete users.
- **Role Assignment**: Ability to assign roles to users.
- **Course Management**: Endpoints to create, update, and delete courses.
- **Learning Paths**: Creation and management of learning paths.
- **Admin Dashboard**: Overview of system-wide metrics.

### For Authors

- **Own Course Management**: Create, update, and delete courses that they have authored.
- **Enrollment Management**: View and manage student enrollment requests, but only for courses they have authored.
- **Author Dashboard**: Metrics related to engagement with courses they have authored.
- **Learning Path Integration**: Add courses to existing learning paths, but cannot create or delete learning paths.

  **Note**: Authors can only manage courses that they have personally authored.

### For Students

- **Course Discovery**: Browse and view available courses.
- **Enrollment Management**:
  - **Send Enrollment Requests**: Apply for enrollment in courses.
  - **View Accepted Enrollments**: Check the status of enrollment requests and see which have been accepted.
  - **Unenroll**: Option to unenroll from courses.
- **Progress Tracking**: Monitor course completion and progress.
- **Student Dashboard**: View enrolled courses, progress, and more.
- **Course Reviews**: Add reviews and ratings to courses they have completed.

  **Note**: Students can only see enrollments that have been accepted and have the option to unenroll.

### Additional Features

- **Secure Authentication**: JWT-based authentication.
- **Role-based Authorization**: Middleware to enable role-based access.
- **API Documentation**: Swagger UI for API documentation.

## Tech Stack

- **Node.js**: Backend runtime.
- **Express.js**: Web application framework.
- **MongoDB**: NoSQL database used for storing data.
- **YAML**: For Swagger API documentation.
- **Swagger-UI-Express**: For rendering API documentation.
- **JSON Web Token (JWT)**: For authentication.
- **dotenv**: For environment variable management.quest.

## Database Setup and Schema

### Database Setup

1. **Install MongoDB**: If you haven't installed MongoDB, you can follow the [official MongoDB installation guide](https://docs.mongodb.com/manual/installation/).

2. **Connection**: The connection string is specified in the `.env` file under `MONGO_URI`.

### Schema

<!-- images -->

![Database Schema](./asset/images/db%20schema.png)

#### User Collection (UserSchema)

- `username`: String (unique, required)
- `email`: String (unique, required)
- `password`: String (required)
- `role`: String (required, one of "admin", "author", "student")

#### Course Collection (CourseSchema)

- `title`: String
- `description`: String
- `thumbnail`: String
- `authorId`: ObjectID (reference to User collection, required)
- `creationDate`: Date
- `reviews`: Array of ReviewSchema
  - `studentId`: ObjectID (reference to User collection, required)
  - `rating`: Number
  - `review`: String
- `ratingAverage`: Number (default 0)

#### Review Collection (Embedded in CourseSchema)

- `studentId`: ObjectID (reference to User collection, required)
- `rating`: Number
- `review`: String

#### Enrollment Collection (EnrollmentSchema)

- `courseId`: ObjectID (reference to Course collection, required)
- `studentId`: ObjectID (reference to User collection, required)
- `status`: String (one of "accepted", "rejected", "pending")

#### Learning Path Collection (learningPathSchema)

- `title`: String
- `description`: String
- `courses`: Array of ObjectIDs (reference to Course collection)

#### Progress Collection (ProgressSchema)

- `studentId`: ObjectID (reference to User collection, required)
- `courseId`: ObjectID (reference to Course collection, required)
- `completion`: Number (default 0)

## Database Relationships

The Learning Platform API utilizes MongoDB, a NoSQL database, to store its data. Despite being a NoSQL database, relationships between the data are maintained through references. Here are the primary relationships:

### User and Course

- A `User` can be an `author` of multiple `Courses`.
- A `Course` has one `author`, represented by `authorId` in the `Course` collection, which refers back to a `User`.

### Course and Review

- A `Course` can have multiple `Reviews`.
- Each `Review` is associated with one `Course` and one `Student` (`User` with a role of "student").
- Reviews are embedded within the `Course` document as an array of `ReviewSchema`.

### User and Review

- A `User` with a role of "student" can write multiple `Reviews`.
- Each `Review` is specifically associated with a `Student` via `studentId`.

### Enrollment and User

- An `Enrollment` is a relationship between a `Course` and a `User` (with a role of "student").
- A `User` can have multiple `Enrollments`.
- Each `Enrollment` contains a `studentId` and `courseId` to indicate the relationship.

### Learning Path and Course

- A `Learning Path` can contain multiple `Courses`.
- Each `Course` can be part of multiple `Learning Paths`.
- The `Learning Path` collection has an array field `courses` that stores ObjectIDs referring to `Courses`.

### User and Progress

- A `Progress` document tracks the learning progress of a `User` in a particular `Course`.
- `Progress` is linked to `User` via `studentId` and to `Course` via `courseId`.

## Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/RevoU-FSSE-2/week-11-m-istighfar.git
```

### Step 2: Navigate to Project Folder

```bash
cd learning-platform-api
```

### Step 3: Install Dependencies

```bash
npm install
```

### Step 4: Environment Setup

Create a `.env` file:

```env
PORT=3000
DATABASE_URL=mongodb://localhost:27017/learning_platform
JWT_SECRET=mysecret
```

### Step 5: Start the Server

```bash
npm start
```

Visit `http://localhost:3000/api-docs` for API documentation.

## Environment Variables

| Variable       | Description                          |
| -------------- | ------------------------------------ |
| `PORT`         | The port number to run the server on |
| `DATABASE_URL` | MongoDB connection string            |
| `JWT_SECRET`   | Secret key for JSON Web Token        |

## Testing and Faker.js Integration

For generating mock data during testing or development, this project is integrated with [Faker.js](https://github.com/Marak/Faker.js). Faker.js allows you to generate a whole bunch of fake data for testing, seeding databases, and more.

### Installing Faker.js

If you haven't already installed Faker.js, you can add it to your project by running:

```bash
npm install faker --save-dev
```

### How to Run the Faker.js Script

#### Step 1: Navigate to the Project Folder

```bash
cd learning-platform-api
```

#### Step 2: Run the Faker.js Script

To run the Faker.js script and populate your MongoDB database with mock data, execute the following command:

```bash
node .\helper\generateFakeData.js
```

## API Endpoints

### **Authentication Endpoints**

| Method | Endpoint         | Description       |
| ------ | ---------------- | ----------------- |
| POST   | `/auth/register` | User Registration |
| POST   | `/auth/login`    | User Login        |

### **Admin Endpoints**

| Method | Endpoint                                | Description                          |
| ------ | --------------------------------------- | ------------------------------------ |
| POST   | `/admin/createUser`                     | Create a new user                    |
| PUT    | `/admin/updateUser/:id`                 | Update a user's details              |
| DELETE | `/admin/deleteUser/:id`                 | Delete a user                        |
| GET    | `/admin/listUsers`                      | List all users                       |
| POST   | `/admin/assignRole/`                    | Assign a role to a user              |
| POST   | `/admin/createCourse`                   | Create a new course                  |
| PUT    | `/admin/updateCourse/:id`               | Update a course                      |
| DELETE | `/admin/deleteCourse/:id`               | Delete a course                      |
| GET    | `/admin/listCourses`                    | List all courses                     |
| GET    | `/admin/dashboard`                      | Get admin dashboard data             |
| POST   | `/admin/createLearningPath`             | Create a new learning path           |
| GET    | `/admin/listLearningPaths`              | List all learning paths              |
| PUT    | `/admin/updateLearningPath/:id`         | Update a learning path               |
| DELETE | `/admin/deleteLearningPath/:id`         | Delete a learning path               |
| POST   | `/admin/addCourse`                      | Add a course to a learning path      |
| DELETE | `/admin/deleteCourse/:pathId/:courseId` | Delete a course from a learning path |

### **Author Endpoints**

| Method | Endpoint                                         | Description                            |
| ------ | ------------------------------------------------ | -------------------------------------- |
| POST   | `/author/createCourse`                           | Create a new course                    |
| GET    | `/author/listCourses`                            | List all courses                       |
| PUT    | `/author/updateOwnedCourse/:id`                  | Update an owned course                 |
| DELETE | `/author/deleteOwnedCourse/:id`                  | Delete an owned course                 |
| GET    | `/author/listEnrollRequests`                     | List all enroll requests               |
| POST   | `/author/updateEnrollmentStatus/:requestId`      | Update the status of an enroll request |
| PUT    | `/author/updateProfile`                          | Update author profile                  |
| GET    | `/author/listowncourses`                         | List own courses                       |
| GET    | `/author/dashboard`                              | Get author dashboard data              |
| GET    | `/author/listLearningPaths`                      | List all learning paths                |
| POST   | `/author/addCoursetoPath`                        | Add a course to a learning path        |
| DELETE | `/author/deleteCoursefromPath/:pathId/:courseId` | Delete a course from a learning path   |

### **Student Endpoints**

| Method | Endpoint                             | Description                        |
| ------ | ------------------------------------ | ---------------------------------- |
| GET    | `/student/viewcourse`                | List all courses                   |
| POST   | `/student/sendEnrollRequest`         | Send an enrollment request         |
| GET    | `/student/readEnrolledCourseContent` | Read content of an enrolled course |
| POST   | `/student/unenrollFromCourse`        | Unenroll from a course             |
| POST   | `/student/markCourseCompleted`       | Mark a course as completed         |
| PUT    | `/student/updateProfile`             | Update student profile             |
| POST   | `/student/addReview/:courseId`       | Add a review for a course          |
| GET    | `/student/dashboard`                 | Get student dashboard data         |
| GET    | `/student/progress/:courseId`        | Get progress for a course          |
| PUT    | `/student/progress/:courseId`        | Update progress for a course       |

For a complete list of API Endpoints and their descriptions, please check the Swagger documentation at `/api-docs`.

## Contributing

Contributions are welcome. Please follow the standard Git workflow:

1. Fork the repository.
2. Create a new branch.
3. Add your features or bug fixes.
4. Create a pull request.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.
