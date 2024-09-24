const { use } = require('passport');
const { Category } = require('../model/Category');
const { User } = require('../model/User');

exports.fetchUserById = async (req, res) => {
  const { id } = req.user;
  try {
    const user = await User.findById(id);
 
    res.status(200).json({id:user.id,email:user.email,role:user.role,addresses:user.addresses,orders:user.orders,profileImage:user.profileImage});
  } catch (err) {
    res.status(400).json(err);
  }
};

exports.updateUser = async (req, res) => {
  const { id } = req.user;
  try {
    const user = await User.findByIdAndUpdate(id, req.body, { new: true });
    res.status(200).json(user);
  } catch (err) {
    res.status(400).json(err);
  }
};