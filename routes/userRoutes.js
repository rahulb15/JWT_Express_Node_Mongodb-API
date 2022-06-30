import express from "express";
const router = express.Router();
import UserController from "../controllers/userController.js";
import { checkUserAuth, deleteAuth } from "../middlewares/auth-middleware.js";
import { check, oneOf } from "express-validator";





//Route Level Middleware - To Protect Route
router.use("/changepassword", checkUserAuth);
router.use("/loggeduser", checkUserAuth);
router.use("/deleteuser", checkUserAuth);
router.use("/updateuser", checkUserAuth);
router.use("/logout", checkUserAuth, deleteAuth);





//Public Routes
router.post(
  "/register",
  [
    check("name").notEmpty(),
    check("password").isLength({ min: 4 }).notEmpty(),
    check("email").isEmail(),
  ],
  UserController.userRegistration
);
router.post("/login", UserController.userLogin);
router.post(
  "/send-reset-password-email",
  UserController.sendUserPasswordResetEmail
);
router.post("/reset-password/:id/:token", UserController.userPasswordReset);
router.post("/searchuser",UserController.searchUser);
router.get("/allUsers",UserController.allUser);





//Private Routes
router.post("/changepassword", UserController.changeUserPassword);
router.get("/loggeduser", UserController.loggedUser);
router.delete("/deleteuser", UserController.userDelete);
router.post("/updateuser", UserController.userUpdate);
router.get("/logout", UserController.userLogout);

export default router;
