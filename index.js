const express = require("express");
const passport = require("passport");
const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;
const LocalStrategy = require("passport-local").Strategy;
const jwt = require("jsonwebtoken");
const session = require("express-session");
const RedisStore = require("connect-redis")(session);
const redis = require("ioredis");

const app = express();

const client = redis.createClient({
  host: "localhost",
  port: 6379,
  legacyMode: true,
});
client.on("connect", () => {
  console.log("Connected to Redis");
});
client.on("error", (err) => {
  console.error("Error connecting to Redis:", err);
});

app.use(
  session({
    store: new RedisStore({ client: client , prefix:"myapp:session:"}),
    secret: "keyboard cat",
    resave: true,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(express.json());


const users = [{ id: 1, name: "Alice", email: "alice@example.com", password: "password1" }];
let refreshTokens = [];
const secretKey = "my_secret_key";
const refresh_secretKey = "my_secret_key2";

const options = {
  secretOrKey: "my_secret_key",
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
};

passport.use(
  new JwtStrategy(options, (jwtPayload, done) => {
    console.log(jwtPayload);
    const user = users.find((u) => u.id === jwtPayload.sub);
    if (user) {
      done(null, user);
    } else {
      done(null, false);
    }
  })
);
passport.use(
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    (email, password, done) => {
      const user = users.find((u) => u.email === email);
      if (!user || user.password !== password) {
        return done(null, false, { message: "Incorrect email or password" });
      }
      return done(null, user);
    }
  )
);
passport.serializeUser(function (user, cb) {
  cb(null, user);
});
passport.deserializeUser(function (obj, cb) {
  cb(null, obj);
});

app.get(
  "/protected",
  passport.authenticate("jwt", { session: true }),
  (req, res) => {
    res.json({ message: "This is a protected resource", user: req.user });
  }
);

app.post("/login", (req, res, next) => {
  passport.authenticate("local", { session: true }, (err, user, info) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      return res.status(401).json({ message: info.message });
    }
    const accessToken = generateAccessToken(user);
    const refreshToken = jwt.sign({ sub: user.id }, refresh_secretKey);
    refreshTokens.push(refreshToken);
    res.json({ accessToken: accessToken, refreshToken: refreshToken });
  })(req, res, next);
});

app.post("/token", (req, res) => {
  const refreshToken = req.body.token;
  if (refreshToken == null) return res.sendStatus(401);
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);
  jwt.verify(refreshToken, refresh_secretKey, (err, user) => {
    if (err) return res.sendStatus(403);
    const accessToken = generateAccessToken({ id: user.sub });
    console.log("users data", user);
    res.json({ accessToken: accessToken });
  });
});

app.delete("/logout", (req, res) => {
  refreshTokens = refreshTokens.filter((token) => token !== req.body.token);
  res.sendStatus(204);
});

function generateAccessToken(user) {
  return jwt.sign({ sub: user.id }, secretKey, { expiresIn: "60s" });
}

app.listen(3000, () => console.log("listening on port http://localhost:3000"));
