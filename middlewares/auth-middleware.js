import jwt from "jsonwebtoken";
import userModel from "../models/User.js";

var checkUserAuth = async(req,res,next)=>{
    let token 
    const { authorization } = req.headers
    if(authorization && authorization.startsWith('Bearer')){
        try {
            //Get Token from Header
            token = authorization.split(' ')[1];

            //Verify Token
            const {userID} = jwt.verify(token,process.env.JWT_SECRET_KEY);

            //GET User fron Token
            req.user = await userModel.findById(userID).select("-password");
            next();

        } catch (error) {
            console.log(error);
            res.status(401).send({"status": "failed", "message": "Unauthorized User"});
        }
    }
    if(!token){
        res.status(401).send({"status": "failed","messsage": "Unauthorized User, No Token"});
    }
}
export default checkUserAuth