require("dotenv").config();
const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

const app = express();
const port = process.env.PORT || 3000;
const firebaseKey = Buffer.from(process.env.FIREBASEJDK, "base64").toString(
  "utf8"
);

const serviceAccount = JSON.parse(firebaseKey);

// const serviceAccount = require("./firebaseAdminJdk.json");
const stripe = require("stripe")(process.env.STRIPE);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

app.use(
  cors({
    origin: ["http://localhost:5173", "https://lessonlab-706ca.web.app"],
    credentials: true,
  })
);

app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.2ok3xcp.mongodb.net/?appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).send({ message: "Unauthorized Access" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.user = decoded; // email, uid, etc.
    next();
  } catch (error) {
    return res.status(401).send({ message: "Invalid Token" });
  }
};

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
    // Send a ping to confirm a successful connection

    const database = client.db("Lessonlab");
    const LessonColletion = database.collection("LessonCollection");
    const UserCollection = database.collection("UserCollection");
    const lessonsReports = database.collection("lessonsReports");
    const CommentsCollection = database.collection("CommentsCollection");

    app.get("/", (req, res) => {
      res.send("Lesson Lab is coocking.............");
    });

    // ------------------------- USER ROUTES ---------------------------------

    app.post("/register", async (req, res) => {
      try {
        const user = req.body;

        if (!user.email) {
          return res.status(400).send({
            success: false,
            message: "Email required",
          });
        }

        // 1️⃣ Check if user already exists
        const existingUser = await UserCollection.findOne({
          email: user.email,
        });

        if (existingUser) {
          return res.status(200).send({
            success: true,
            message: "User already registered",
          });
        }

        // 2️⃣ Insert only if not exists
        const result = await UserCollection.insertOne(user);

        res.status(201).send({
          success: true,
          message: "User registered successfully",
          data: result,
        });
      } catch (error) {
        res.status(500).send({
          success: false,
          message: error.message,
        });
      }
    });

    app.get("/me", verifyToken, async (req, res) => {
      try {
        const email = req.user.email;

        const user = await UserCollection.findOne({ email });

        if (!user) {
          return res.status(404).send({ message: "User not found" });
        }

        res.send({ success: true, user });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });
    app.put("/update", verifyToken, async (req, res) => {
      try {
        const email = req.user.email;
        const updateData = req.body;

        const result = await UserCollection.updateOne(
          { email },
          { $set: updateData }
        );

        res.send({ success: true, message: "Profile updated", result });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });
        // Admin-only: Get all users
    // GET /admin/users
    app.get("/admin/users", verifyToken, async (req, res) => {
      try {
        const requesterEmail = req.user.email;
        const requester = await UserCollection.findOne({
          email: requesterEmail,
        });

        if (!requester || requester.role !== "admin") {
          return res.status(403).send({ message: "Forbidden (Admin only)" });
        }

        // 1️⃣ Aggregate lesson counts per author
        const lessonCounts = await LessonColletion.aggregate([
          {
            $group: {
              _id: "$author_email",
              totalLessons: { $sum: 1 },
            },
          },
        ]).toArray();

        // Convert to a map for quick lookup
        const lessonMap = {};
        lessonCounts.forEach((l) => {
          lessonMap[l._id] = l.totalLessons;
        });
        
        // 2️⃣ Get all users and attach totalLessons
        const users = await UserCollection.find().toArray();
        const usersWithLessons = users.map((u) => ({
          _id: u._id,
          name: u.name,
          email: u.email,
          role: u.role,
          totalLessons: lessonMap[u.email] || 0,
        }));

        // Sort by totalLessons descending
        usersWithLessons.sort((a, b) => b.totalLessons - a.totalLessons);

        res.send({ success: true, users: usersWithLessons });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });
    // PUT /admin/users/:id/role
    app.put("/admin/users/:id/role", verifyToken, async (req, res) => {
      try {
        const requesterEmail = req.user.email;
        const requester = await UserCollection.findOne({
          email: requesterEmail,
        });

        if (!requester || requester.role !== "admin") {
          return res.status(403).send({ message: "Forbidden (Admin only)" });
        }

        const userId = req.params.id;
        const { role } = req.body; // expected "admin" or "user"

        if (!role || !["user", "admin"].includes(role)) {
          return res.status(400).send({ message: "Invalid role" });
        }

        const result = await UserCollection.updateOne(
          { _id: new ObjectId(userId) },
          { $set: { role } }
        );

        res.send({ success: true, message: "User role updated", result });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });
    // DELETE /admin/users/:id
    app.delete("/admin/users/:id", verifyToken, async (req, res) => {
      try {
        const requesterEmail = req.user.email;
        const requester = await UserCollection.findOne({
          email: requesterEmail,
        });

        if (!requester || requester.role !== "admin") {
          return res.status(403).send({ message: "Forbidden (Admin only)" });
        }

        const userId = req.params.id;

        const result = await UserCollection.deleteOne({
          _id: new ObjectId(userId),
        });

        // Optionally, delete their lessons
        await LessonColletion.deleteMany({ author_email: requester.email });

        res.send({ success: true, message: "User deleted", result });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });
    // --------------------------- Lesson Routes ----------------

    app.post("/addlesson", async (req, res) => {
      try {
        const lessonData = req.body;

        // Basic validation
        if (!lessonData.title || !lessonData.description) {
          return res.status(400).send({
            success: false,
            message: "Title and Description are required",
          });
        }
        const result = await LessonColletion.insertOne(lessonData);
        // Fake response for now
        res.send({
          success: true,
          message: "Lesson API triggered successfully",
          data: result,
        });
      } catch (error) {
        res.status(500).send({
          success: false,
          message: "Something went wrong",
          error: error.message,
        });
      }
    });
    app.get("/publicLesson", async (req, res) => {
      try {
        const page = parseInt(req.query.page) || 1;
        const pageSize = parseInt(req.query.pageSize) || 8;
        const search = req.query.search || "";
        const category = req.query.category || "";
        const tone = req.query.tone || "";
        const sort = req.query.sort || ""; // "newest" or "mostSaved"

        // Build filter object
        const filter = { visibility: { $regex: /^public$/i } };

        if (search) {
          filter.title = { $regex: search, $options: "i" }; // case-insensitive search by title
        }

        if (category) {
          filter.category = category;
        }

        if (tone) {
          filter.emotionalTone = tone;
        }

        // Build sort object
        let sortOption = {};
        if (sort === "newest") {
          sortOption = { created_at: -1 }; // newest first
        } else if (sort === "mostSaved") {
          sortOption = { savedCount: -1 }; // most saved
        }

        const totalLessons = await LessonColletion.countDocuments(filter);

        const lessons = await LessonColletion.find(filter)
          .sort(sortOption)
          .skip((page - 1) * pageSize)
          .limit(pageSize)
          .toArray();

        res.json({
          lessons,
          totalPages: Math.ceil(totalLessons / pageSize),
          currentPage: page,
          totalLessons,
        });
      } catch (error) {
        console.error("Error fetching public lessons:", error);
        res.status(500).json({ success: false, message: error.message });
      }
    });
    // GET /my-public-lessons
    app.get("/my-public-lessons", verifyToken, async (req, res) => {
      try {
        const userEmail = req.user.email;

        // Fetch all public lessons authored by this user
        const publicLessons = await LessonColletion.find({
          author_email: userEmail,
          visibility: { $regex: /^public$/i },
        }).toArray();

        // Fetch total lesson count (public + private) authored by the user
        const totalLessonsCount = await LessonColletion.countDocuments({
          author_email: userEmail,
        });

        res.json({
          success: true,
          publicLessons: publicLessons,
          totalLessonsCount, // includes both public + private
        });
      } catch (error) {
        console.error("Error fetching user lessons:", error);
        res.status(500).json({ success: false, message: error.message });
      }
    });

    // GET LESSONS (OWNER → only own lessons, ADMIN → all lessons)
    app.get("/lessons", verifyToken, async (req, res) => {
      try {
        const email = req.user.email;

        // Find requester from database
        const requester = await UserCollection.findOne({ email });

        if (!requester) {
          return res.status(404).send({ message: "User not found" });
        }

        let query = {};

        // If user is not admin, fetch only their lessons
        if (requester.role !== "admin") {
          query = { author_email: email };
        }

        const lessons = await LessonColletion.find(query).toArray();

        res.send({ success: true, lessons });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // GET SINGLE LESSON
    app.get("/lesson/:id", async (req, res) => {
      try {
        const id = req.params.id;
        const lesson = await LessonColletion.findOne({
          _id: new ObjectId(id),
        });

        if (!lesson) {
          return res
            .status(404)
            .send({ success: false, message: "Lesson not found" });
        }

        res.send({ success: true, lesson });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // UPDATE LESSON (OWNER OR ADMIN)
    app.patch("/lesson/:id", verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const updateData = req.body;
        delete updateData._id;
        delete updateData.author_email;
        delete updateData.author_name;
        delete updateData.author_photo;
        delete updateData.created_at;

        const lesson = await LessonColletion.findOne({
          _id: new ObjectId(id),
        });

        if (!lesson) {
          return res.status(404).send({ message: "Lesson not found" });
        }

        // Find requester from DB
        const requester = await UserCollection.findOne({
          email: req.user.email,
        });

        // Permission Check
        if (
          lesson.author_email !== req.user.email &&
          requester.role !== "admin"
        ) {
          return res.status(403).send({ message: "Forbidden: Not authorized" });
        }

        const result = await LessonColletion.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateData }
        );

        res.send({
          success: true,
          message: "Lesson updated successfully",
          result,
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // DELETE LESSON (OWNER OR ADMIN)
    app.delete("/lesson/:id", verifyToken, async (req, res) => {
      try {
        const id = req.params.id;

        const lesson = await LessonColletion.findOne({
          _id: new ObjectId(id),
        });

        if (!lesson) {
          return res.status(404).send({ message: "Lesson not found" });
        }

        // Find requester from DB
        const requester = await UserCollection.findOne({
          email: req.user.email,
        });

        // Permission Check
        if (
          lesson.author_email !== req.user.email &&
          requester.role !== "admin"
        ) {
          return res.status(403).send({ message: "Forbidden: Not authorized" });
        }

        const result = await LessonColletion.deleteOne({
          _id: new ObjectId(id),
        });

        res.send({
          success: true,
          message: "Lesson deleted successfully",
          result,
        });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    // ------------------------
    // TOGGLE LESSON LIKE / Save to favourite
    // ------------------------
    app.put("/like/:id", verifyToken, async (req, res) => {
      try {
        const lessonId = req.params.id;
        const userEmail = req.user.email;

        // Find the lesson
        const lesson = await LessonColletion.findOne({
          _id: new ObjectId(lessonId),
        });
        if (!lesson) {
          return res
            .status(404)
            .json({ success: false, message: "Lesson not found" });
        }

        lesson.isLiked = lesson.isLiked || [];

        let update;
        if (lesson.isLiked.includes(userEmail)) {
          // Remove like
          update = { $pull: { isLiked: userEmail }, $inc: { likesCount: -1 } };
        } else {
          // Add like
          update = {
            $addToSet: { isLiked: userEmail },
            $inc: { likesCount: 1 },
          };
        }

        const updatedLesson = await LessonColletion.findOneAndUpdate(
          { _id: new ObjectId(lessonId) },
          update,
          { returnDocument: "after" } // MongoDB >=4.4
        );

        res.json({
          success: true,
          message: "Like toggled successfully",
          lesson: updatedLesson,
          likes: updatedLesson.isLiked.includes(userEmail),
        });
      } catch (error) {
        console.error("Toggle like error:", error);
        res.status(500).json({ success: false, message: error.message });
      }
    });
    app.put("/save/:id", verifyToken, async (req, res) => {
      try {
        const lessonId = req.params.id;
        const userEmail = req.user.email;

        // Find the lesson
        const lesson = await LessonColletion.findOne({
          _id: new ObjectId(lessonId),
        });
        if (!lesson) {
          return res
            .status(404)
            .json({ success: false, message: "Lesson not found" });
        }

        lesson.isSaved = lesson.isSaved || [];

        let update;
        if (lesson.isSaved.includes(userEmail)) {
          // Remove from favorites
          update = {
            $pull: { isSaved: userEmail },
            $inc: { saveCount: -1 },
            $set: { updated_at: new Date() },
          };
        } else {
          // Add to favorites
          update = {
            $addToSet: { isSaved: userEmail },
            $inc: { saveCount: 1 },
            $set: { updated_at: new Date() },
          };
        }

        const updatedLesson = await LessonColletion.findOneAndUpdate(
          { _id: new ObjectId(lessonId) },
          update,
          { returnDocument: "after" }
        );

        res.json({
          success: true,
          message: updatedLesson.isSaved.includes(userEmail)
            ? "Added to favorites"
            : "Removed from favorites",
          lesson: updatedLesson,
          isSaved: updatedLesson.isSaved.includes(userEmail),
          saveCount: updatedLesson.saveCount,
        });
      } catch (error) {
        console.error("Toggle save error:", error);
        res.status(500).json({ success: false, message: error.message });
      }
    });

    app.post("/report/:id", verifyToken, async (req, res) => {
      try {
        const lessonId = req.params.id;
        const userEmail = req.user.email; // reporter email
        const { reason } = req.body;

        if (!reason) {
          return res.json({ success: false, message: "Reason is required" });
        }

        const reportEntry = {
          lessonId: new ObjectId(lessonId),
          reporterEmail: userEmail,
          reason: reason,
          timestamp: new Date(),
        };

        // Insert into lessonReports collection
        const result = await lessonsReports.insertOne(reportEntry);

        res.json({
          success: true,
          message: "Lesson reported successfully",
          reportId: result.insertedId,
        });
      } catch (error) {
        console.error("Report error:", error);
        res.status(500).json({ success: false, message: "Server error" });
      }
    });
    //  comment
    // --------------------------------
    app.get("/comments/:lessonId", async (req, res) => {
      try {
        const lessonId = req.params.lessonId;

        const comments = await CommentsCollection.find({ lessonId })
          .sort({ created_at: 1 })
          .toArray();

        res.json(comments);
      } catch (error) {
        console.error("Get comments error:", error);
        res
          .status(500)
          .json({ success: false, message: "Failed to fetch comments" });
      }
    });
    app.post("/comments/:lessonId", verifyToken, async (req, res) => {
      try {
        const lessonId = req.params.lessonId;
        const { text } = req.body;

        if (!text || !text.trim()) {
          return res
            .status(400)
            .json({ success: false, message: "Comment text is required" });
        }

        // Logged-in user info from verifyToken middleware
        const userEmail = req.user.email;
        const userName =
          req.user.name || req.user.displayName || "Unknown User";

        const newComment = {
          lessonId,
          userEmail,
          userName,
          text,
          created_at: new Date(),
        };

        const result = await CommentsCollection.insertOne(newComment);

        // Send inserted comment back including _id
        res.json({
          ...newComment,
          _id: result.insertedId,
          time: "Just now", // for instant UI update
        });
      } catch (error) {
        console.error("Post comment error:", error);
        res
          .status(500)
          .json({ success: false, message: "Failed to post comment" });
      }
    });
    // GET /lessons/similar/:lessonId
    app.get("/lessons/similar/:lessonId", async (req, res) => {
      try {
        const { lessonId } = req.params;

        // Find the current lesson first
        const currentLesson = await LessonColletion.findOne({
          _id: new ObjectId(lessonId),
        });
        if (!currentLesson) {
          return res
            .status(404)
            .json({ success: false, message: "Lesson not found" });
        }

        const { category, emotionalTone } = currentLesson;

        // Find lessons with same category or emotional tone, excluding current lesson
        const similarLessons = await LessonColletion.find({
          _id: { $ne: new ObjectId(lessonId) },
          $or: [{ category: category }, { emotionalTone: emotionalTone }],
        })
          .limit(6) // max 6 lessons
          .toArray();

        res.json(similarLessons);
      } catch (error) {
        console.error("Failed to fetch similar lessons:", error);
        res
          .status(500)
          .json({ success: false, message: "Failed to fetch similar lessons" });
      }
    });

    // ----------------- favourites -----------------------------

    // GET my favorite lessons
    app.get("/my-favorites", verifyToken, async (req, res) => {
      try {
        const userEmail = req.user.email;
        const { category, tone } = req.query;

        const query = {
          isSaved: userEmail,
        };

        if (category) {
          query.category = category;
        }

        if (tone) {
          query.emotionalTone = tone;
        }

        const favorites = await LessonColletion.find(query)
          .sort({ updated_at: -1 })
          .toArray();

        res.json({
          success: true,
          data: favorites,
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: error.message,
        });
      }
    });

    app.delete("/favorites/:id", verifyToken, async (req, res) => {
      try {
        const lessonId = req.params.id;
        const userEmail = req.user.email;

        const result = await LessonColletion.findOneAndUpdate(
          { _id: new ObjectId(lessonId) },
          {
            $pull: { isSaved: userEmail },
            $inc: { saveCount: -1 },
            $set: { updated_at: new Date() },
          },
          { returnDocument: "after" }
        );

        res.json({
          success: true,
          message: "Removed from favorites",
          lesson: result,
        });
      } catch (error) {
        res.status(500).json({ success: false, message: error.message });
      }
    });
