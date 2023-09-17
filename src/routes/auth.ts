import bcrypt from "bcrypt";
import express from "express";
import jwt from "jsonwebtoken";
import { authenticate } from "../middlewares/auth";
import { validateUser } from "../middlewares/validation";
import { SessionClass } from "../models/session";
import { UserClass } from "../models/user";

const router = express.Router();

// signup a new user
router.post("/signup", validateUser, async (req, res) => {
  const userExists = await UserClass.findByUsername(req.body.username);
  if (userExists)
    return res.status(400).json({ message: "User already exists." });

  // hash the password
  const hashedPassword = await bcrypt.hash(req.body.password, 10);

  // store the hashed password for later verification
  const user = await UserClass.create({
    ...req.body,
    password: hashedPassword,
  });

  res.json(user);
});

// login a user
router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  // get the user to verify
  const user = await UserClass.findByUsername(username);
  if (!user) {
    return res.status(400).json({ message: "Invalid username or password." });
  }

  // verify the password
  const validPassword = bcrypt.compareSync(password, user.password);
  if (!validPassword) {
    return res.status(400).json({ message: "Invalid username or password." });
  }

  // check if there is an active session
  const activeSessions = await SessionClass.findActiveSessions(user.id);
  if (activeSessions.length > 0) {
    return res.status(400).json({
      message: "There is already an active session using your account.",
    });
  }

  // At this phase, there is no active session, so create one
  const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET as string);
  await SessionClass.create({ userId: user.id, token });

  res.json({ token });
});

// logout a user from all sessions
router.post("/logout/all", authenticate, async (req, res) => {
  const userId = req.user.id;
  if (!userId) {
    return res.status(400).json({ message: "User already logged out." });
  }
  await SessionClass.logoutSession(userId);
  res.json({ message: "All sessions have been terminated." });
});

export default router;
