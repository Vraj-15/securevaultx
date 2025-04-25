import express from "express";
import multer from "multer";
import crypto from "crypto";
import { Storage } from "@google-cloud/storage";
import passport from "passport";
import session from "express-session";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { PrismaClient } from "@prisma/client";
import dotenv from "dotenv";
import path from "path";

// Load environment variables
dotenv.config();

// Initialize core services
const app = express();
const upload = multer();
const prisma = new PrismaClient();

// Google Cloud Storage config
const storage = new Storage({
  projectId: process.env.GOOGLE_CLOUD_PROJECT_ID,
  keyFilename: path.resolve(process.env.GOOGLE_CLOUD_KEY_FILE),
});
const bucket = storage.bucket(process.env.GCS_BUCKET);

// Session middleware
app.use(
  session({
    secret: process.env.SESSION_SECRET || "replace-with-your-secret",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

// Health-check endpoint
app.get("/", (req, res) => {
  res.send("🔐 Encrypted-Storage-App Backend is running!");
});

// Passport serialization
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// Google OAuth strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value;
        if (!email) throw new Error("No email in Google profile");
        const user = await prisma.user.upsert({
          where: { email },
          update: {},
          create: { email, name: profile.displayName },
        });
        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);

// Auth routes
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    res.redirect("/dashboard");
  }
);

// Auth-check middleware
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ error: "Not authenticated" });
}

// File upload + encryption route
app.post(
  "/upload",
  isAuthenticated,
  upload.single("file"),
  async (req, res) => {
    try {
      const file = req.file;
      if (!file) {
        return res.status(400).json({ error: "No file provided" });
      }
      const userId = req.user.id;

      // AES-GCM encryption
      const key = crypto.randomBytes(32);
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
      const encryptedData = Buffer.concat([
        cipher.update(file.buffer),
        cipher.final(),
      ]);
      const authTag = cipher.getAuthTag();
      const payload = Buffer.concat([iv, authTag, encryptedData]);

      const objectKey = `encrypted/${Date.now()}_${file.originalname}`;
      await bucket.file(objectKey).save(payload, {
        metadata: { contentType: "application/octet-stream" },
      });

      // Store file metadata in DB
      const dbEntry = await prisma.file.create({
        data: {
          userId,
          filename: file.originalname,
          s3Path: objectKey,
          iv: iv.toString("hex"),
          authTag: authTag.toString("hex"),
          encryptedKey: key.toString("hex"),
        },
      });

      res.json({ success: true, file: dbEntry });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Upload failed" });
    }
  }
);

// Start server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () =>
  console.log(`Encrypted-Storage-App Backend running on http://localhost:${PORT}`)
);