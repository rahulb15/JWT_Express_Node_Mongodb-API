import dotenv from "dotenv";
dotenv.config({ path: "./routes/.env" });
import express from "express";
import cors from "cors";
import connectDB from "./config/connectdb.js";
import router from "./routes/userRoutes.js";
import bodyParser from "body-parser";

const app = express();
const port = process.env.PORT;
const DATABASE_URL = process.env.DATABASE_URL;

//CORS Policy
app.use(cors());

//DATABASE Connection
connectDB(DATABASE_URL);

//JSON
app.use(express.json());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

//Load Routes
app.use("/api/user", router);

app.listen(port, () => {
  console.log(`Server listening at http://localhost:${port}`);
});
