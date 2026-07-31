import express from "express";
import http from "http";
import mongoose from "mongoose";
import cors from "cors";
import cookieParser from "cookie-parser";
import dotenv from "dotenv"; 
import bcrypt from "bcryptjs";
import crypto from "crypto";
import multer from "multer";
import path from "path";
import fs from "fs";

dotenv.config(); 

const required = [
  "SECRET",
];

for (const key of required) {
  if (!process.env[key]) throw new Error(`Missing environment variable: ${key}`);
}

const config = {
  port: process.env.PORT || 5000,
  mongoUri: process.env.MONGO_URI || "mongodb://127.0.0.1:27017/dtube",
  clientUrl: process.env.CLIENT_URL || "http://localhost:5173",
  jwtSecret: process.env.SECRET,
  };

const base64url = value =>
  Buffer.from(typeof value === "string" ? value : JSON.stringify(value))
    .toString("base64") 
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

const decode64url = value => {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(normalized, "base64").toString();
};

function signJwt(payload, expiresInSeconds = 60 * 60 * 24 * 7) { // payload is the data we want to encode in the JWT, expiresInSeconds is the expiration time of the token (default is 7 days)
  const header = { alg: "HS256", typ: "JWT" }; // HS256 is the hashing algorithm used to sign the token, JWT is the type of token
  const body = { ...payload, exp: Math.floor(Date.now() / 1000) + expiresInSeconds };
  const unsigned = `${base64url(header)}.${base64url(body)}`;
  const signature = crypto.createHmac("sha256", config.jwtSecret)// means we are going to sign something with the HMAC SHA256 algorithm using the secret key stored in config.jwtSecret
                      .update(unsigned).digest("base64url");// digest("base64url") means we are going to output the signature in base64url format
  return `${unsigned}.${signature}`;
}

function verifyJwt(token) {
  if (!token) throw new Error("Missing token");
  const [header, payload, signature] = token.split(".");
  if (!header || !payload || !signature) throw new Error("Malformed token");

  const unsigned = `${header}.${payload}`;
  const expected = crypto.createHmac("sha256", config.jwtSecret).update(unsigned).digest("base64url");
  const a = Buffer.from(signature); 
  const b = Buffer.from(expected); // because timing safe equal works only with buffers, we convert the signature and expected signature to buffers

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw new Error("Invalid signature");

  const decoded = JSON.parse(decode64url(payload));
  if (decoded.exp < Math.floor(Date.now() / 1000)) throw new Error("Token expired");
  return decoded;
}


await mongoose.connect(config.mongoUri);// Connects Express server to MongoDB.
const app = express();
app.use(cors({ origin: config.clientUrl, credentials: true })); // allows cross-origin requests from the client URL and includes credentials (cookies) in the requests. This is necessary for the client to communicate with the server when they are hosted on different domains or ports.
app.use(express.json());
app.use(cookieParser());
app.use("/api/auth", authRouter);

app.use("/api/file", videosRouter);
app.use("/api/users", usersRouter);
app.listen(config.port, () => console.log(` API running on ${config.port}`));


const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, default: "" },
  resetTokenHash: String,
  resetTokenExpires: Date
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

const fileSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true },
  description: { type: String, default: "" },
  filename: { type: String, required: true },
  mimeType: { type: String, required: true },
  owner: { type:mongoose.Schema.Types.ObjectId, ref: "User", required: true },
}, { timestamps: true });

const File = mongoose.model("File", fileSchema);

async function auth(req, res, next) { 
    try {
    const bearer = req.headers.authorization?.startsWith("Bearer ")
      ? req.headers.authorization.slice(7)
      : null;
    const token = req.cookies?.token;
    const payload = verifyJwt(token);
    const user = await User.findById(payload.sub);
    if (!user) return res.status(401).json({ message: "Account unavailable" });
    req.user = user;
    next();
  } catch {
    res.status(401).json({ message: "Unauthorized" });
  }
}

const authRouter = express.Router();
const cookieOptions = { httpOnly: true, sameSite: "lax", secure: false, maxAge: 7 * 24 * 60 * 60 * 1000 }; // httpOnly: true means the cookie cannot be accessed by JavaScript, sameSite: "lax" means the cookie will be sent with same-site requests and top-level navigation GET requests, secure: false means the cookie will be sent over HTTP, maxAge: 7 * 24 * 60 * 60 * 1000 means the cookie will expire in 7 days

function issue(res, user) {
  const token = signJwt({ sub: user._id.toString()

   });
  res.cookie("token", token, cookieOptions);
}

authRouter.post("/signup", async (req, res) => {
  try {
    const { name, email, password, channelName } = req.body;
    if (!name || !email || !password) return res.status(400).json({ message: "Missing fields" });
    if (await User.findOne({ email: email.toLowerCase() })) return res.status(409).json({ message: "Email exists" });
    const passwordHash = await bcrypt.hash(password, 12); // The 12 is the cost factor . It tells bcrypt how much work to do.
    const user = await User.create({ name, email, passwordHash, });
    issue(res, user);
    res.status(201).json({ user });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

authRouter.post("/login", async (req, res) => {
  const user = await User.findOne({ email: req.body.email?.toLowerCase() }); 
  if (!user || !(await bcrypt.compare(req.body.password || "", user.passwordHash)))
    return res.status(401).json({ message: "Invalid credentials" });
  issue(res, user);
  res.json({ user });
  
});

authRouter.post("/signout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "Signed out" });
});

authRouter.get("/me", auth, (req, res) => res.json({ user: req.user }));

const usersRouter = express.Router();

usersRouter.get("/:id", async (req, res) => {
  const user = await User.findById(req.params.id).select("-passwordHash -resetTokenHash");
  if (!user ) return res.status(404).json({ message: "Channel unavailable" });
  const videos = await Video.find({ owner: user._id }).sort({ createdAt: -1 });
  res.json({ user, videos });
});

const videosRouter = express.Router();
const uploadDir = path.resolve("uploads");
fs.mkdirSync(uploadDir, { recursive: true }); 

const storage = multer.diskStorage({
  destination: uploadDir,
  filename: (_, file, cb) => cb(null, `${Date.now()}-${crypto.randomBytes(8).toString("hex")}${path.extname(file.originalname)}`) // cb is the callback function that takes an error and a filename. We generate a unique filename by combining the current timestamp, a random 8-byte hex string, and the original file extension. This helps prevent filename collisions and preserves the file type.
});
const upload = multer({ storage, limits: { fileSize: 1024 * 1024 * 500 } });

videosRouter.get("/:id/stream", async (req, res) => {
  const video = await File.findById(req.params.id);
  if (!video) return res.sendStatus(404);
  const filePath = path.join(uploadDir, video.filename);
  if (!fs.existsSync(filePath)) return res.sendStatus(404);
  const size = fs.statSync(filePath).size;
  const range = req.headers.range;

  if (!range) {
    res.writeHead(200, { "Content-Length": size, "Content-Type": video.mimeType, "Accept-Ranges": "bytes" });
    return fs.createReadStream(filePath).pipe(res);
  }

  const [startText, endText] = range.replace(/bytes=/, "").split("-");
  const start = parseInt(startText, 10);
  const end = endText ? parseInt(endText, 10) : Math.min(start + 1024 * 1024 - 1, size - 1);
  res.writeHead(206, {
    "Content-Range": `bytes ${start}-${end}/${size}`,
    "Accept-Ranges": "bytes",
    "Content-Length": end - start + 1,
    "Content-Type": video.mimeType
  });
  fs.createReadStream(filePath, { start, end }).pipe(res);
});