
import cors from "cors";
import path from "path";
import passport from "./app/config/passport"
import router from "./app/routes";
import cookieParser from "cookie-parser";
import notFound from "./app/middlewares/notFound";
import express, { Application, Request, Response } from "express";
import globalErrorHandler from "./app/middlewares/globalErrorHandler";

import session from "express-session";

const app: Application = express();

// parsers
app.use(express.json());
app.use(cookieParser());
app.use("/uploads", express.static(path.join(process.cwd(), "uploads")));
app.use(cors({ origin: ["http://localhost:3000"], credentials: true }));

// app routes

app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    maxAge: 600000 // 10 minutes
  }
}));
app.use(passport.initialize());
app.use("/api/v1", router);

app.get("/", async (req: Request, res: Response) => {
	res.render("index.ejs");
});


app.use(globalErrorHandler);
app.use(notFound);

export default app;
