import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth2";
import session from "express-session";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const port = 3000;
const saltRounds = 10;
const { Pool } = pg;

// Middleware setup
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Session configuration
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

app.use(passport.initialize());
app.use(passport.session());

// Database configuration using Pool
const pool = new Pool({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
  ssl: { rejectUnauthorized: false },
});

pool.connect((err) => {
  if (err) {
    console.error('Error connecting to the database:', err.stack);
  } else {
    console.log('Connected to the database');
  }
});

// Define the isAuthenticated middleware
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login");
};

// Define routes
app.get("/", (req, res) => {
  res.render("login.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.post("/login", 
  passport.authenticate("local", {
    successRedirect: "/index", // Redirect to index after successful login
    failureRedirect: "/login", // Redirect back to login on failure
  })
);

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  try {
    const checkResult = await pool.query("SELECT * FROM users WHERE email = $1", [username]);

    if (checkResult.rows.length > 0) {
      res.render("register.ejs", { message: "User already exists, please login." });
    } else {
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      const result = await pool.query(
        "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
        [username, hashedPassword]
      );
      const user = result.rows[0];
      req.login(user, (err) => {
        if (err) {
          console.error(err);
          return res.redirect("/register");
        }
        res.redirect("/index");
      });
    }
  } catch (err) {
    console.error("Error registering user:", err);
    res.status(500).send("Error registering user");
  }
});

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/login");
  });
});

app.get("/index", isAuthenticated, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM posts ORDER BY id ASC");
    res.render("index.ejs", { posts: result.rows });
  } catch (error) {
    console.error("Error fetching posts:", error);
    res.status(500).send("Error fetching posts");
  }
});

// Passport local strategy for user login
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const result = await pool.query("SELECT * FROM users WHERE email = $1", [username]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);
        return isPasswordValid ? done(null, user) : done(null, false, { message: "Invalid credentials" });
      } else {
        return done(null, false, { message: "User not found" });
      }
    } catch (err) {
      return done(err);
    }
  })
);

// Google OAuth strategy setup
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const result = await pool.query("SELECT * FROM users WHERE email = $1", [profile.email]);
        if (result.rows.length === 0) {
          const newUser = await pool.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [profile.email, "google"]
          );
          return done(null, newUser.rows[0]);
        } else {
          return done(null, result.rows[0]);
        }
      } catch (err) {
        return done(err);
      }
    }
  )
);

// Serialize and deserialize user for session management
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const result = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
    done(null, result.rows[0]);
  } catch (err) {
    done(err);
  }
});

// Route to show all posts
app.get('/posts', isAuthenticated, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM posts ORDER BY id ASC");
    res.render('index', { posts: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error retrieving posts');
  }
});

// Route to show a form to create a new post
app.get('/create', isAuthenticated, (req, res) => {
  res.render('create');
});

// Route to create a new post
app.post('/create', isAuthenticated, async (req, res) => {
  const { title, content } = req.body;
  try {
    await pool.query("INSERT INTO posts (title, content, username) VALUES ($1, $2, $3)", [title, content, req.user.username]);
    res.redirect('/posts');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error creating post');
  }
});

// Route to view a single post by id
app.get('/post/:id', async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM posts WHERE id = $1", [req.params.id]);
    const post = result.rows[0];
    if (post) {
      res.render('post', { post });
    } else {
      res.status(404).send('Post not found');
    }
  } catch (err) {
    console.error(err);
    res.status(500).send('Error retrieving post');
  }
});

// Route to show a form to edit a post
app.get('/edit/:id', isAuthenticated, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM posts WHERE id = $1", [req.params.id]);
    const post = result.rows[0];
    if (post) {
      res.render('edit', { post });
    } else {
      res.status(404).send('Post not found');
    }
  } catch (err) {
    console.error(err);
    res.status(500).send('Error retrieving post');
  }
});

// Route to update a post
app.post('/edit/:id', isAuthenticated, async (req, res) => {
  const { title, content } = req.body;
  try {
    await pool.query("UPDATE posts SET title = $1, content = $2 WHERE id = $3", [title, content, req.params.id]);
    res.redirect(`/post/${req.params.id}`);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error updating post');
  }
});

// Route to delete a post
app.post('/delete/:id', isAuthenticated, async (req, res) => {
  try {
    await pool.query("DELETE FROM posts WHERE id = $1", [req.params.id]);
    res.redirect('/posts');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error deleting post');
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
