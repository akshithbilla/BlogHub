import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

app.use(passport.initialize());
app.use(passport.session());

// Database configuration
const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

app.get("/", (req, res) => {
  res.render("login.ejs");
});

// Define routes
app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/login");
  });
});

app.get("/index", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const result = await db.query("SELECT * FROM posts ORDER BY id ASC");
      res.render("index.ejs", { posts: result.rows });
    } catch (error) {
      console.error("Error fetching posts:", error);
      res.status(500).send("Error fetching posts");
    }
  } else {
    res.redirect("/login");
  }
});

// Google OAuth Routes
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/posts",
    failureRedirect: "/login",
  })
);

// Passport local strategy for user login
passport.use(
  "local",
  new Strategy(async (username, password, cb) => {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            return cb(err);
          } else {
            return valid ? cb(null, user) : cb(null, false);
          }
        });
      } else {
        return cb(null, false, { message: "User not found" });
      }
    } catch (err) {
      return cb(err);
    }
  })
);

// Google OAuth strategy
passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [profile.email]);
        if (result.rows.length === 0) {
          const newUser = await db.query("INSERT INTO users (email, password) VALUES ($1, $2)", [profile.email, "google"]);
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

// Serialize and deserialize user for session management
passport.serializeUser((user, cb) => {
  cb(null, user.id); // Serialize only the user ID
});

passport.deserializeUser(async (id, cb) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    if (result.rows.length > 0) {
      cb(null, result.rows[0]);
    } else {
      cb(new Error('User not found'));
    }
  } catch (err) {
    cb(err);
  }
});

// Route to register a new user
app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    if (checkResult.rows.length > 0) {
      res.render("register.ejs", { message: "User already exists, please login." });
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            if (err) console.error(err);
            res.redirect("/index");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

// Local login route
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/posts",
    failureRedirect: "/login",
  })
);

// Route to show all posts
app.get('/posts', async (req, res) => {
  if (req.isAuthenticated()) {
    const result = await db.query("SELECT * FROM posts ORDER BY id ASC");
    res.render('index', { posts: result.rows });
  } else {
    res.redirect('/login');
  }
});

// Route to show a form to create a new post
app.get('/create', (req, res) => {
  if (req.isAuthenticated()) {
    res.render('create');
  } else {
    res.redirect('/login');
  }
});

// Route to create a new post
app.post('/create', async (req, res) => {
  if (req.isAuthenticated()) {
    const { title, content } = req.body;
    await db.query("INSERT INTO posts (title, content) VALUES ($1, $2)", [title, content]);
    res.redirect('/posts');
  } else {
    res.redirect('/login');
  }
});

// Route to view a single post by id
app.get('/post/:id', async (req, res) => {
  const result = await db.query("SELECT * FROM posts WHERE id = $1", [req.params.id]);
  const post = result.rows[0];
  if (post) {
    res.render('post', { post });
  } else {
    res.status(404).send('Post not found');
  }
});

// Route to show a form to edit a post
app.get('/edit/:id', async (req, res) => {
  const result = await db.query("SELECT * FROM posts WHERE id = $1", [req.params.id]);
  const post = result.rows[0];
  if (post) {
    res.render('edit', { post });
  } else {
    res.status(404).send('Post not found');
  }
});

// Route to update a post
app.post('/edit/:id', async (req, res) => {
  const { title, content } = req.body;
  await db.query("UPDATE posts SET title = $1, content = $2 WHERE id = $3", [title, content, req.params.id]);
  res.redirect(`/post/${req.params.id}`);
});

// Route to delete a post
app.post('/delete/:id', async (req, res) => {
  await db.query("DELETE FROM posts WHERE id = $1", [req.params.id]);
  res.redirect('/posts');
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
