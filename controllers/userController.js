import userModel from "../models/User.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";



class UserController{
    static userRegistration = async(req,res)=>{
        const {name, email, password, password_confirmation, tc} = req.body;
        const user = await  userModel.findOne({email: email});
        if(user){
            res.send({"status":"failed","message":"Email already existes"});
        }else{
            if(name && email && password && password_confirmation && tc){
                if(password === password_confirmation){
                   try {
                    const salt = await bcrypt.genSalt(10);
                    const hashPassword = await bcrypt.hash(password, salt);
                    const doc = new userModel({
                        name: name,
                        email: email,
                        password: hashPassword,
                        tc: tc
                    });
                    await doc.save();
                    const saved_user = await userModel.findOne({email:email});
                    //Generate JWT Token
                    const token = jwt.sign({userID:saved_user._id},process.env.JWT_SECRET_KEY,{ expiresIn:"5d" });

                    //res.status(201).res.send({"status":"success","message":"Registration Success"});
                    res.send({"status":"success","message":"Registration Success","token":token});
                   } catch (error) {
                    res.send({"status":"failed","message":"Unable to register"});
                   }
                }else{
                    res.send({"status":"failed","message":"Password and Confirmed password Doesn't Match"});

                }
            }else{
                res.send({"status":"failed","message":"Al fields are required"});
            }
        }
    }
    static userLogin = async(req,res)=>{
        try {
            const {email, password}= req.body;
            if(email && password){
                const user = await userModel.findOne({email:email});
                if(user != null){
                    const isMatch = await bcrypt.compare(password,user.password);
                    if((user.email === email) && isMatch){
                        //Generate JWT Tocken
                        const token = jwt.sign({userID:user._id},process.env.JWT_SECRET_KEY,{expiresIn: "5d"});
                        res.send({"status":"Success","message":"Login Success","tocken": token});
                    }else{
                        res.send({"status":"failed","message":"Email and Password is not Valid"});
                    }
                }else{
                    res.send({"status":"failed","message":"You are not a registered User"});
                }
            }else{
                res.send({"status":"failed","message":"All fields are required"});
            }
        } catch (error) {
            res.send({"status":"failed","message":"unable to Login"});
        }
    }

    static changeUserPassword = async(req,res)=>{
        const {password,password_confirmation}=req.body;
        if(password && password_confirmation){
            if(password!==password_confirmation){
                res.send({"status":"failed","message":"New Password and Confirm New Password doesn't match"});
            }else{
                const salt = await bcrypt.genSalt(10);
                const newHashPassword = await bcrypt.hash(password,salt);
                await userModel.findByIdAndUpdate(req.user._id, {$set:{password: newHashPassword}});
                res.send({"status": "success", "messgae": "Password Changed Succesfully"});
            }
        }else{
            res.send({"status":"failed","message":"All fields are required"});
        }
    }
}

export default UserController;