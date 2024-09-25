const express = require("express");
const server = express();
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
const path=require('path');
const stripe=require("stripe")("sk_test_51OrfRdBZotp1XksgLMgOzMQpvcSkUPqOUVEdTJ7hq7dhAanCz0XjrphZkwGLrZTkEMmLqG8T1ZUhfWVqG6DQEnGZ00sIPo9IBh");

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

// JWT options

const opts = {};
opts.jwtFromRequest = cookieExtractor;
opts.secretOrKey = SECRET_KEY; // TODO: should not be in code;

server.use(express.static('build'));
server.use(cookieParser())
server.use(
  session({
    secret: "keyboard cat",
    resave: false, // don't save session if unmodified
    saveUninitialized: false, // don't create session until something stored
  })
);

server.use(passport.authenticate("session"));

server.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
    exposedHeaders: ["X-Total-Count"],
  })
);

server.use(express.json({ limit: '50mb' }));
server.use(express.urlencoded({ limit: '50mb', extended: true }));

server.use("/products", isAuth(), productsRouter.router);
server.use("/categories", isAuth(), categoriesRouter.router);
server.use("/brands", isAuth(), brandsRouter.router);
server.use("/users", isAuth(), usersRouter.router);
server.use("/auth", authRouter.router);
server.use("/cart", isAuth(), cartRouter.router);
server.use("/orders", isAuth(), ordersRouter.router);

server.post("/api/create-checkout-session", async(req,res)=>{
  const product=req.body;
  const orderId=req.body.orderId;
  console.log(req.body.orderId)
  const products=product.products;
  const lineItems=products.map((product)=>({
    price_data:{
      currency:"usd",
      product_data: {
        name:product.product.title,
      },
      unit_amount:Math.round(product.product.price*(100-product.product.discountPercentage)*product.quantity)
    },
    quantity:product.quantity
  }))
  const session=await stripe.checkout.sessions.create({
    payment_method_types:["card"],
    line_items:lineItems,
    mode:"payment",
    success_url:"http://localhost:3000/order-success/65ef420dd00060856d788dac",
    cancel_url:"http://localhost:3000/payment-failed"
  })
  res.json({id:session.id})
});

passport.use(
  "local",
  new LocalStrategy(
    { usernameField: "email" },
    async function (email, password, done) {
      try {
        const user = await User.findOne({ email: email }).exec();
        if (!user) {
          done(null, false, { message: "invalid credentials" });
        }
        crypto.pbkdf2(
          password,
          user.salt,
          310000,
          32,
          "sha256",
          async function (err, hashedPassword) {
            if (!crypto.timingSafeEqual(user.password, hashedPassword)) {
              return done(null, false, { messag: "invalid credentials" });
            }
            const token = jwt.sign(sanitizeUser(user), SECRET_KEY);
            const userWithoutSensitiveInfo={
              email:user.email,
              role:user.role,
              addresses:user.addresses,
              orders:user.orders,
              profileImage:user.profileImage,
              verified:user.verified
            }
            done(null, {token,userWithoutSensitiveInfo});
          }
        );
      } catch (err) {
        done(err);
      }
    }
  )
);

passport.use(
  "jwt",
  new JwtStrategy(opts, async function (jwt_payload, done) {
    try {
      const user = await User.findById(jwt_payload.id );
      if (user) {
        return done(null, user); // this calls serializer
      } else {
        return done(null, false);
      }
    } catch (err) {
      return done(err, false);
    }
  })
);

passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
    return cb(null, user);
  });
});

const { Product } = require('./model/Product');

async function updateProducts() {
  try {
      const products = await User.find();
      for (const product of products) {
          product.verified=true;
          await product.save();
      }
      console.log('All products updated successfully.');
  } catch (error) {
      console.error('Error updating products:', error);
  }
}

main().catch((err) => console.log(err));

async function main() {
  await mongoose.connect("mongodb+srv://bhargavvijay:sparbhar@cluster0.pjy1orn.mongodb.net/Ecommerce?retryWrites=true&w=majority&appName=Cluster0", {
    useNewUrlParser: true,
  });
  console.log("Connected to MongoDB Atlas");
}


server.get("/", (req, res) => {
  res.json({ status: "success" });
});

server.listen(8080, () => {
  console.log("server started");
});
