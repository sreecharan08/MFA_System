import express from 'express'
import cors from 'cors'
import 'dotenv/config'
import cookieParser from 'cookie-parser'
import connectDB from './config/mongodb.js'
import authRouter from './routes/authRouter.js'
import userRouter from './routes/userRoutes.js'

const app = express();
const port = process.env.port || 4000
connectDB();



app.use(cors({
  origin: "http://localhost:5173",   // your frontend URL
  credentials: true
}));

app.use(express.json());
app.use(cookieParser());



// API ENDPOINTS
app.get('/', (req, res) => res.send("API is working"));
app.use('/api/auth', authRouter)
app.use('/api/user', userRouter)

app.listen(port, () => console.log(`Server started on PORT: ${port}`));