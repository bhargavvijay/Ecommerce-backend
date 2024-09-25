const { User } = require('../model/User');
const crypto=require('crypto')
const jwt = require('jsonwebtoken');
const SECRET_KEY='SECRET_KEY'
const {sanitizeUser, EmailVerificationTemplate}=require('../services/common')
const {sendMail}=require('../services/common');
const { response } = require('express');


exports.resetPasswordRequest = async (req, res) => {
  const email = req.body.email;
  const user = await User.findOne({ email: email });
  if (user) {
    const token = crypto.randomBytes(48).toString('hex');
    user.resetPasswordToken = token;
    await user.save();

    // Also set token in email
    const resetPageLink =
      'http://localhost:3000/reset-password?token=' + token + '&email=' + email;
    const subject = 'reset password for e-commerce';
    const html = `<p>Click <a href='${resetPageLink}'>here</a> to Reset Password</p>`;

    // lets send email and a token in the mail body so we can verify that user has clicked right link

    if (email) {
      const response = await sendMail({ to: email, subject, html });
      res.json(response);
    } else {
      res.sendStatus(400);
    }
  } else {
    res.sendStatus(400);
  }
};

exports.resetPassword = async (req, res) => {
  const { email, password, token } = req.body;

  const user = await User.findOne({ email: email, resetPasswordToken: token });
  if (user) {
    const salt = crypto.randomBytes(16);
    crypto.pbkdf2(
      req.body.password,
      salt,
      310000,
      32,
      'sha256',
      async function (err, hashedPassword) {
        user.password = hashedPassword;
        user.salt = salt;
        await user.save();
        const subject = 'password successfully reset for e-commerce';
        const html = `<p>Successfully able to Reset Password</p>`;
        if (email) {
          const response = await sendMail({ to: email, subject, html });
          res.json(response);
        } else {
          res.sendStatus(400);
        }
      }
    );
  } else {
    res.sendStatus(400);
  }
};

exports.createUser = async (req, res) => {
  try {
    email=req.body.email;
    const salt = crypto.randomBytes(16);
    crypto.pbkdf2(
      req.body.password,
      salt,
      310000,
      32,
      'sha256',
      async function (err, hashedPassword) {
        const user = new User({
          ...req.body,
          password: hashedPassword,
          salt,
          profileImage: req.body.profileImage || '',
          verified:false
        });
        const doc = await user.save();
        const userObj = doc.toJSON();
        req.login(userObj,async (err) => {
          if (err) {
            res.status(400).json(err);
          } else {
            const token = jwt.sign(sanitizeUser(doc), SECRET_KEY)
            const user=await User.findOne({email:email});
            user.emailVerificationToken=token;
            await user.save();
            const subject = 'Email Verification ShopNest';
            const link='http://localhost:3000/email-verification?token=' + token + '&email=' + email;
            const html=EmailVerificationTemplate(link);
            const response = await sendMail({ to: email, subject, html });


            res
              .cookie('jwt', token, {
                expires: new Date(Date.now() + 3600000),
                httpOnly: true,
              })
              .json({
                token,
                user: userObj,
              });
          }
        });

      }
    );
  } catch (err) {
    res.status(400).json(err);
  }
};
exports.emailVerification = async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (user && user.emailVerificationToken === req.body.token) {
    user.verified = true;
    await user.save();
    res.json({ response: "success" }); // Send JSON response
  } else {
    res.sendStatus(400);
  }
};

exports.loginUser = async (req, res) => {
  const userWithoutSensitiveInfo = {
    email: req.user.email,
    role: req.user.role,
    addresses: req.user.addresses,
    orders: req.user.orders,
    profileImage: req.user.profileImage,
    verified:req.user.verified
  };

  res
    .cookie('jwt', req.user.token, {
      expires: new Date(Date.now() + 3600000),
      httpOnly: true,
    })
    .status(201)
    .json(req.user);
};


exports.checkAuth = async (req, res) => {
  if(req.user)
  {
    const userWithoutSensitiveInfo={
      email:req.user.email,
      role:req.user.role,
      addresses:req.user.addresses,
      orders:req.user.orders,
      profileImage:req.user.profileImage,
      verified:req.user.verified
    }
    res.json( userWithoutSensitiveInfo );
  }
  else{
    res.sendStatus(401)
  }
};

exports.logout = async (req, res) => {
  res
    .cookie('jwt', null, {
      expires: new Date(Date.now()),
      httpOnly: true,
    })
    .sendStatus(200)
};