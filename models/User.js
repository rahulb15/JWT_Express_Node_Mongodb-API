import mongoose from "mongoose";

//Defining Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, trim: true },
  password: { type: String, required: true, trim: true },
  tc: { type: Boolean, required: true },
  status: { type: String },
  token: { type: String },
});

//Model
const userModel = mongoose.model("user", userSchema);

export default userModel;
