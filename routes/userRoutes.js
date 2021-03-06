import express from "express";
const router = express.Router();
import UserController from "../controllers/userController.js";
import checkUserAuth from "../middlewares/auth-middleware.js";

//Route Level Middleware - To Protect Route
router.use("/changepassword",checkUserAuth);
router.use("/loggeduser",checkUserAuth);
router.use("/deleteuser",checkUserAuth);
router.use("/updateuser",checkUserAuth);


//Public Routes
router.post("/register",UserController.userRegistration);
router.post("/login",UserController.userLogin);
router.post("/send-reset-password-email",UserController.sendUserPasswordResetEmail);
router.post("/reset-password/:id/:token",UserController.userPasswordReset);


//Private Routes
router.post("/changepassword",UserController.changeUserPassword);
router.get("/loggeduser",UserController.loggedUser);
router.delete("/deleteuser",UserController.userDelete);
router.post("/updateuser",UserController.userUpdate);



export default router;