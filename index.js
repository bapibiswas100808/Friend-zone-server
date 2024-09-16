const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 5000;
app.use(express.json());

app.use(
  cors({
    origin: ["http://localhost:5173", "http://localhost:5174"],
  })
);

// MongoDB Credentials
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.5e8b5ac.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// ****Server-side token verification****
app.post("/verify-token", (req, res) => {
  const token = req.headers["authorization"]?.split(" ")[1];

  if (!token) {
    return res
      .status(401)
      .send({ success: false, message: "No token provided" });
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).send({ success: false, message: "Invalid token" });
    }

    res.send({ success: true });
  });
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
    // Database Collections
    const UserCollections = client.db("FriendZoneDB").collection("allUsers");
    const FriendRequestsCollection = client
      .db("FriendZoneDB")
      .collection("friendRequests");

    // ******Register new user****
    app.post("/register", async (req, res) => {
      const { name, email, password } = req.body;

      // Check if the user already exists
      const existingUser = await UserCollections.findOne({ email });
      if (existingUser) {
        return res
          .status(400)
          .send({ success: false, message: "User already exists" });
      }

      const existingUserByName = await UserCollections.findOne({ name });
      if (existingUserByName) {
        return res
          .status(400)
          .send({ success: false, message: "Name already in use" });
      }
      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Create a new user object
      const newUser = {
        name,
        email,
        password: hashedPassword,
      };
      // Insert the user into the database
      const result = await UserCollections.insertOne(newUser);

      res.send(result);
    });

    // ****Login User*****
    app.post("/login", async (req, res) => {
      const { email, password } = req.body;

      try {
        // Find the user by email
        const user = await UserCollections.findOne({ email });

        if (!user) {
          return res
            .status(404)
            .send({ success: false, message: "User not found" });
        }

        // Check if the password is correct
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
          return res
            .status(400)
            .send({ success: false, message: "Invalid credentials" });
        }

        // Generate a JWT token
        const token = jwt.sign(
          { email: user.email, id: user._id, username: user.name },
          process.env.ACCESS_TOKEN_SECRET,
          { expiresIn: "1h" }
        );

        // Send the token and userId to the client
        res.send({
          success: true,
          token,
          userId: user._id,
          username: user.name,
        });
      } catch (error) {
        console.error("Login error:", error);
        res
          .status(500)
          .send({ success: false, message: "Internal server error" });
      }
    });

    // **** Fetch all users ****
    app.get("/users", async (req, res) => {
      const { search, excludeUserId } = req.query;

      try {
        let query = {};

        // If search term is provided, search by name
        if (search) {
          query.name = new RegExp(search, "i");
        }

        // Exclude the logged-in user from the results if excludeUserId is valid
        if (excludeUserId && ObjectId.isValid(excludeUserId)) {
          query._id = { $ne: new ObjectId(excludeUserId) };
        }

        // Fetch users based on the query
        const users = await UserCollections.find(query).toArray();
        res.send(users);
      } catch (error) {
        console.error("Error fetching users:", error);
        res.status(500).send("Error fetching users");
      }
    });

    // ****Send a friend request****
    app.post("/friend-request", async (req, res) => {
      const { senderId, recipientId } = req.body;

      if (!senderId || !recipientId) {
        return res
          .status(400)
          .json({ message: "Sender and recipient IDs are required" });
      }

      try {
        const usersCollection = client
          .db("FriendZoneDB")
          .collection("allUsers");

        // Check if the friend request already exists
        const existingRequest = await FriendRequestsCollection.findOne({
          senderId: new ObjectId(senderId),
          recipientId: new ObjectId(recipientId),
        });

        if (existingRequest) {
          return res
            .status(400)
            .json({ message: "Friend request already sent" });
        }

        // Create a new friend request
        const newRequest = {
          senderId: new ObjectId(senderId),
          recipientId: new ObjectId(recipientId),
          status: "pending",
          createdAt: new Date(),
        };

        await FriendRequestsCollection.insertOne(newRequest);

        // Update the sender's and recipient's friendRequests arrays
        await usersCollection.updateOne(
          { _id: new ObjectId(senderId) },
          { $push: { friendRequests: new ObjectId(recipientId) } }
        );

        await usersCollection.updateOne(
          { _id: new ObjectId(recipientId) },
          { $push: { friendRequests: new ObjectId(senderId) } }
        );

        res.status(201).json({ message: "Friend request sent successfully" });
      } catch (error) {
        console.error("Error sending friend request:", error);
        res.status(500).json({ message: "Internal server error" });
      }
    });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("project is running");
});

app.listen(port, () => {
  console.log(`project is running at ${port}`);
});
