const router = require("express").Router();
const User = require("../models/User");
const bcrypt = require("bcrypt");

//REGISTER
router.post("/register", async (req, res) => {
  try {
    //generate new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);

    //create new user
    const newUser = new User({
      username: req.body.username,
      email: req.body.email,
      password: hashedPassword,
    });

    //save user and respond
    const user = await newUser.save();
    res.status(200).json(user);
  } catch (err) {
    res.status(500).json(err)
  }
});

router.post("/change-password", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    const validOldPassword = await bcrypt.compare(req.body.oldpassword, user.password)
    if(!validOldPassword){
      return res.status(400).json("Sai mật khẩu hiện tại")
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.newpassword, salt);

    user.password = hashedPassword;
    res.status(200).json({ message: 'Password updated successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Internal Server Error' });
  }
});

//LOGIN
router.post("/login", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if(!user){
      return res.status(404).json("user not found");
    }
    const validPassword = await bcrypt.compare(req.body.password, user.password)
    if(!validPassword){
      return res.status(400).json("wrong password")
    }

    res.status(200).json(user)
  } catch (err) {
    res.status(500).json(err)
  }
});

module.exports = router;