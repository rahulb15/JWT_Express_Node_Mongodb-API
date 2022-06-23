import express from "express";
const router = express.Router();
import UserController from "../controllers/userController.js";
import checkUserAuth from "../middlewares/auth-middleware.js";

//Route Level Middleware - To Protect Route
router.use("/changepassword",checkUserAuth);

//Public Routes
router.post("/register",UserController.userRegistration);
router.post("/login",UserController.userLogin);


//Private Routes
router.post("/changepassword",UserController.changeUserPassword);


export default router;