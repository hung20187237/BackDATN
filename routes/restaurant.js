const router = require("express").Router();
const Restaurant = require('../models/Restaurant')
const Post = require('../models/Post')
const User = require('../models/User')

//create a res
router.post("/", async (req, res) => {
  const newRestaurant = new Restaurant(req.body);
  try {
    const savedRestaurant = await newRestaurant.save();
    res.status(200).json(savedRestaurant);
  } catch (err) {
    res.status(500).json(err);
  }
});

//get a res
router.get("/:id", async (req, res) => {
  const resName = req.params.name;
  const resId = req.params.id;
  try {
    const restaurant = resId
       ? await Restaurant.findById(resId)
        : await Restaurant.findOne({ title: resName });
    res.status(200).json(restaurant);
  } catch (err) {
    res.status(500).json(err);
  }
});

//get id res
router.get("/getId/:title", async (req, res) => {
  const resName = req.params.title;
  console.log('resName', resName)
  try {
    const restaurant = await Restaurant.findOne({ name: resName });
    console.log('restaurant', restaurant)
    res.status(200).json(restaurant._id);
  } catch (err) {
    res.status(500).json(err);
  }
});


//get list post
router.get("/reviewposts/:id", async (req, res) => {
  try {
    const currentRestaurant = await Restaurant.findById(req.params.id);
    const savedposts = await Post.find({ title: currentRestaurant.name });
    res.status(200).json(savedposts)
  } catch (err) {
    res.status(500).json(err);
  }
});



module.exports = router;