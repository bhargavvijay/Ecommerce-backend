const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;
const cookieParser = require('cookie-parser');
const path = require('path');
const stripe = require("stripe")("sk_test_51OrfRdBZotp1XksgLMgOzMQpvcSkUPqOUVEdTJ7hq7dhAanCz0XjrphZkwGLrZTkEMmLqG8T1ZUhfWVqG6DQEnGZ00sIPo9IBh");

// Import your routes
const productsRouter = require("./routes/Products");
const categoriesRouter = require("./routes/Categories");
const brandsRouter = require("./routes/Brands");
const usersRouter = require("./routes/Users");
const authRouter = require("./routes/Auth");
const cartRouter = require("./routes/Cart");
const ordersRouter = require("./routes/Order");
const { User } = require("./model/User");
const { isAuth, sanitizeUser, cookieExtractor } = require('./services/common');

const SECRET_KEY = "SECRET_KEY";

const server = express();

// Middleware
server.use(cors({
  exposedHeaders: ["X-Total-Count"],
}));
server.use(cookieParser());
server.use(express.json({ limit: '50mb' }));
server.use(express.urlencoded({ limit: '50mb', extended: true }));

server.use(
  session({
    secret: "keyboard cat",
    resave: false,
    saveUninitialized: false,
  })
);

server.use(passport.authenticate("session"));

// API routes
server.use("/products", isAuth(), productsRouter.router);
server.use("/categories", isAuth(), categoriesRouter.router);
server.use("/brands", isAuth(), brandsRouter.router);
server.use("/users", isAuth(), usersRouter.router);
server.use("/auth", authRouter.router);
server.use("/cart", isAuth(), cartRouter.router);
server.use("/orders", isAuth(), ordersRouter.router);

// Stripe Checkout Session
server.post("/api/create-checkout-session", async (req, res) => {
  const product = req.body;
  const lineItems = product.products.map((product) => ({
    price_data: {
      currency: "usd",
      product_data: {
        name: product.product.title,
      },
      unit_amount: Math.round(product.product.price * (100 - product.product.discountPercentage) * product.quantity),
    },
    quantity: product.quantity,
  }));

  const session = await stripe.checkout.sessions.create({
    payment_method_types: ["card"],
    line_items: lineItems,
    mode: "payment",
    success_url: `${req.protocol}://${req.get('host')}/order-success/65ef420dd00060856d788dac`,
    cancel_url: `${req.protocol}://${req.get('host')}/payment-failed`,
  });
  res.json({ id: session.id });
});

// Passport configuration
passport.use("local", new LocalStrategy(
  { usernameField: "email" },
  async (email, password, done) => {
    try {
      const user = await User.findOne({ email: email }).exec();
      if (!user) {
        return done(null, false, { message: "Invalid credentials" });
      }
      crypto.pbkdf2(password, user.salt, 310000, 32, "sha256", async (err, hashedPassword) => {
        if (!crypto.timingSafeEqual(user.password, hashedPassword)) {
          return done(null, false, { message: "Invalid credentials" });
        }
        const token = jwt.sign(sanitizeUser(user), SECRET_KEY);
        const userWithoutSensitiveInfo = {
          email: user.email,
          role: user.role,
          addresses: user.addresses,
          orders: user.orders,
          profileImage: user.profileImage,
          verified: user.verified
        };
        done(null, { token, userWithoutSensitiveInfo });
      });
    } catch (err) {
      done(err);
    }
  }
));

passport.use("jwt", new JwtStrategy(
  { jwtFromRequest: cookieExtractor, secretOrKey: SECRET_KEY },
  async (jwt_payload, done) => {
    try {
      const user = await User.findById(jwt_payload.id);
      if (user) {
        return done(null, user);
      } else {
        return done(null, false);
      }
    } catch (err) {
      return done(err, false);
    }
  }
));

passport.serializeUser((user, cb) => {
  process.nextTick(() => {
    return cb(null, user);
  });
});

passport.deserializeUser((user, cb) => {
  process.nextTick(() => {
    return cb(null, user);
  });
});

// MongoDB connection
async function main() {
  await mongoose.connect("mongodb+srv://bhargavvijay:sparbhar@cluster0.pjy1orn.mongodb.net/Ecommerce?retryWrites=true&w=majority&appName=Cluster0", {});
  console.log("Connected to MongoDB Atlas");
}
main().catch(err => console.log(err));

// Serve static files from the React frontend app
server.use(express.static(path.join(__dirname, 'build')));

// The "catchall" handler: for any request that doesn't match one above, send back React's index.html file.
server.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'build', 'index.html'));
});

// Start the server
server.listen(8080, () => {
  console.log("Server started on port 8080");
});
