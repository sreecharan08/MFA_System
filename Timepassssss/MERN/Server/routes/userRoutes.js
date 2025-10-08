import userAuth from "../middleware/userAuth.js";
import express from "express";
import { getUserData } from "../controllers/userController.js";

const router = express.Router();

router.get("/data", userAuth, getUserData);

export default router;