import userModel from "../models/User.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import transporter from '../config/emailConfig.js'


class UserController{

    static userRegistration = async(req,res)=>{
        const {name, email, password, password_confirmation, tc,status} = req.body;
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
                        tc: tc,
                        status: "Inactive"
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
                        //Status Change
                        await userModel.findByIdAndUpdate(user._id, {$set:{status: "Active"}});
                            
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

    static loggedUser = async(req,res)=>{
        // const user = req.user;
        // await userModel.updateMany({}, {$set:{status: "InActive"}});
        // if(user){
        // await userModel.findByIdAndUpdate(req.user._id, {$set:{status: "Active"}});
        // res.send({ "user": req.user })
        // }else{
        //     res.send({"status":"failed","message":"All users are Inactive and nothing change"});
        // }
        res.send({ "user": req.user })
    }

    static sendUserPasswordResetEmail = async(req,res)=>{
        const {email} = req.body
        if(email){
            const user = await userModel.findOne({email:email});
            if(user){
                const secret = user._id + process.env.JWT_SECRET_KEY
                const token = jwt.sign({userID:user._id}, secret, {expiresIn: "15m"});
                const link = `http://localhost:3010/api/user/reset/${user._id}/${token}`;
                console.log(link);
                
                // // Send Email
                      let info = await transporter.sendMail({
                       from: process.env.EMAIL_FROM,
                       to: user.email,
                       subject: "TestProject - Password Reset Link",
                       html: `<a href=${link}>Click Here</a> to Reset Your Password`
                   });


                res.send({"status": "success", "message": "Password Reset Email Sent... Please Check Your Email","info": info});
            }else{
                res.send({"status":"failed","message":"Email Doesn't Exists"});

            }         
        } else{
            res.send({"status":"failed","message": " Email fields are required"});
        }
    }
    static userPasswordReset = async(req,res)=>{
        const {password,password_confirmation} = req.body;
        const {id,token} = req.params
        const user = await userModel.findById(id);
        const new_secret = user._id + process.env.JWT_SECRET_KEY;
        try {
            jwt.verify(token,new_secret);
            if(password&&password_confirmation){
                if (password!==password_confirmation) {
                    res.send({"status":"failed","message": " New Password And Confirm New Password Doesn't Match"});
                } else {
                    const salt = await bcrypt.genSalt(10);
                    const newHashPassword = await bcrypt.hash(password,salt);
                    await userModel.findByIdAndUpdate(user._id, {$set:{password: newHashPassword}});
                    res.send({"status": "success", "message": "Password Reset Successfully"});
                }

            }else{
                res.send({"status":"failed","message": " All fields are required"});
            }
        } catch (error) {
            console.log(error);
            res.send({ "status": "failed", "message": "Invalid Token" });        }
    }
}

export default UserController;