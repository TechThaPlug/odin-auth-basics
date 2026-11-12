require("dotenv").config();

const path = require("node:path");
const { Pool } = require("pg");
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcryptjs");

if (!process.env.DATABASE_URL || !process.env.SESSION_SECRET) {
  throw new Error(
    "Set DATABASE_URL and SESSION_SECRET (copy .env.example to .env).",
  );
}

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const isProduction = process.env.NODE_ENV === "production";
const BCRYPT_ROUNDS = 10;

// Used so a wrong username takes about as long as a wrong password
const DUMMY_HASH = bcrypt.hashSync("not-a-real-password", BCRYPT_ROUNDS);

const app = express();

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.disable("x-powered-by");

if (isProduction) {
  app.set("trust proxy", 1);
}

// ---------- Middleware (the order matters) ----------
app.use(express.urlencoded({ extended: false }));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: isProduction,
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  }),
);

app.use(passport.session());

// Every view can now use currentUser
app.use((req, res, next) => {
  res.locals.currentUser = req.user ?? null;
  next();
});

// ---------- Passport ----------
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const { rows } = await pool.query(
        "SELECT id, username, password FROM users WHERE lower(username) = lower($1)",
        [username],
      );
      const user = rows[0];

      const match = await bcrypt.compare(
        password,
        user ? user.password : DUMMY_HASH,
      );

      if (!user || !match) {
        return done(null, false, {
          message: "Incorrect username or password.",
        });
      }

      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }),
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query(
      "SELECT id, username FROM users WHERE id = $1",
      [id],
    );

    // false means "no such user any more", and the request continues logged out
    done(null, rows[0] ?? false);
  } catch (error) {
    done(error);
  }
});

function requireLogin(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/");
}

// ---------- Validation ----------
function validateSignUp(body = {}) {
  const username = String(body.username ?? "").trim();
  const password = String(body.password ?? "");
  const confirm = String(body.confirmPassword ?? "");
  const errors = [];

  if (!/^[A-Za-z0-9_]{3,30}$/.test(username)) {
    errors.push("Username must be 3 to 30 letters, numbers, or underscores.");
  }

  // bcrypt only uses the first 72 bytes, so we cap the length
  if (password.length < 8 || password.length > 72) {
    errors.push("Password must be 8 to 72 characters.");
  }

  if (password !== confirm) {
    errors.push("The two passwords do not match.");
  }

  return { username, password, errors };
}

// ---------- Routes ----------
app.get("/", (req, res) => {
  const messages = req.session.messages ?? [];
  req.session.messages = [];

  res.render("index", { title: "Home", messages });
});

app.get("/sign-up", (req, res) => {
  res.render("sign-up-form", { title: "Sign up", errors: [], username: "" });
});

app.post("/sign-up", async (req, res) => {
  const { username, password, errors } = validateSignUp(req.body);

  if (errors.length === 0) {
    try {
      const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);

      await pool.query(
        "INSERT INTO users (username, password) VALUES ($1, $2)",
        [username, hashedPassword],
      );

      return res.redirect("/");
    } catch (error) {
      // 23505 = unique violation: that username is taken
      if (error.code !== "23505") {
        throw error;
      }
      errors.push("That username is already taken.");
    }
  }

  res
    .status(400)
    .render("sign-up-form", { title: "Sign up", errors, username });
});

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
    failureMessage: true,
  }),
);

app.post("/log-out", (req, res, next) => {
  req.logout((error) => {
    if (error) {
      return next(error);
    }
    res.redirect("/");
  });
});

app.get("/secret", requireLogin, (req, res) => {
  res.render("secret", { title: "Members only" });
});

// ---------- Fallbacks ----------
app.use((req, res) => {
  res.status(404).render("404", { title: "Page not found" });
});

app.use((error, req, res, next) => {
  console.error(error);

  if (res.headersSent) {
    return next(error);
  }

  res.status(500).render("error", { title: "Server error" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, (error) => {
  if (error) {
    throw error;
  }
  console.log(`Auth practice - listening on port ${PORT}!`);
});
