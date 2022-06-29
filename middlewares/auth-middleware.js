import jwt from "jsonwebtoken";
import userModel from "../models/User.js";

let token;
let getId;

var checkUserAuth = async (req, res, next) => {
  //let token
  const { authorization } = req.headers;
  if (authorization && authorization.startsWith("Bearer")) {
    try {
      //Get Token from Header

      token = authorization.split(" ")[1];
      //console.log(token);
      const { userID } = jwt.verify(token, process.env.JWT_SECRET_KEY);
      getId = userID;

      //GET User from Token
      const a = await userModel.findById(userID).select("token");
      console.log(a.token);

      if (token === a.token) {
        req.user = await userModel.findById(userID).select("-password");
        next();
      } else {
        res.send("You are logged out please login again");
      }
    } catch (error) {
      console.log(error);
      res.status(401).send({ status: "failed", message: "Unauthorized User" });
      //await userModel.findByIdAndUpdate(user._id, {$set:{status: "Active"}});
    }
  }
  if (!token) {
    res
      .status(401)
      .send({ status: "failed", messsage: "Unauthorized User, No Token" });
  }
};

var deleteAuth = async (req, res, next) => {
  try {
    req.user = await userModel.findByIdAndUpdate(getId, {
      $set: { token: " ", status: "Inactive" },
    });
    next();
  } catch (error) {
    res
      .status(401)
      .send({ status: "failed", messsage: "Unauthorized User, No Token" });
  }
};

export { checkUserAuth, deleteAuth };
