const express = require("express");
const app = express();

const cors = require('cors')
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const helmet = require("helmet");
const morgan = require("morgan");
const multer = require("multer");
const userRoute = require("./routes/user");
const authRoute = require("./routes/auth");
const postRoute = require("./routes/post");
const commentRoute = require('./routes/comment')
const messageRoute = require('./routes/message')
const conversationRoute = require('./routes/conversation')
const friendRequestRoute = require('./routes/friendRequest')
const notificationRoute = require("./routes/notification");
const restaurantRoute = require("./routes/restaurant");
const reportRoute = require("./routes/report");
const path = require("path");
const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const tf = require('@tensorflow/tfjs');
const Post = require("./models/Post");
const Comment = require("./models/Comment");
const { Types } = require('mongoose');


dotenv.config();

mongoose.connect(
  process.env.MONGO_URL,
  { useNewUrlParser: true, useUnifiedTopology: true },
  () => {
    console.log("Connected to MongoDB");
  }
);
app.use("/images", express.static(path.join(__dirname, "public/images")));

//middleware
app.use(express.json());
app.use(helmet());
app.use(morgan("common"));
app.use(cors())

const storage = multer.diskStorage({
  destination:(req, file, cb)=> {
    cb(null, 'public/images')
  },
  filename:  (req, file, cb)=> {
    cb(null, Date.now()+'_' +file.originalname)
  }
})

const upload = multer({ storage: storage });
app.post("/api/upload", upload.single("file"), (req, res) => {
  try {
    return res.status(200).json("File uploded successfully");
  } catch (error) {
    console.error(error);
  }
});

const mutiupload = multer({ storage: storage })
app.post("/api/mutiupload", mutiupload.array("images",12), async (req, res) => {
  try {
    return res.status(200).json({data:"File uploaded successfully",file:req.files});
  } catch (error) {
    console.log(error);
    if (error.code === "LIMIT_UNEXPECTED_FILE") {
      return res.status(403).json("Too many files to upload.");
    }
    return res.status(500).json(`Error when trying upload many files: ${error}`);
  }
})

const uploadImage = multer({ storage: storage });
app.post('/api/check-image', uploadImage.array("media", 12), async (req, res) => {
  const uploadedFile = req.files;
  try {
    const data = new FormData();
    uploadedFile.forEach((imagePath, index) => {
      data.append(`media[${index}]`, fs.createReadStream(imagePath.path));
    });
    data.append('workflow', 'wfl_fcYaLLijOa94P50zolWlw');
    data.append('api_user', '1777157158');
    data.append('api_secret', 'HFVyXMsK2mo3DqavoGECiGhNbq');

    const response = await axios({
      method: 'post',
      url: 'https://api.sightengine.com/1.0/check-workflow.json',
      data: data,
      headers: data.getHeaders(),
    });

    res.json(response.data);
  } catch (error) {
    if (error.response) res.status(error.response.status).json(error.response.data);
    else res.status(500).json({ error: error.message });
  }
});


app.post('/api/check-content', async (req, res) => {

  console.log('req.body', req.body)

  try {
    const data = new FormData();
    data.append('text', req.body.content);
    data.append('lang', 'en');
    data.append('mode', 'ml,rules');
    data.append('categories', 'drug, weapon, extremism');
    data.append('api_user', '1777157158');
    data.append('api_secret', 'HFVyXMsK2mo3DqavoGECiGhNbq');

    const response = await axios({
      method: 'post',
      url: 'https://api.sightengine.com/1.0/text/check.json',
      data: data,
      headers: data.getHeaders(),
    });

    res.json(response.data);
  } catch (error) {
    if (error.response) res.status(error.response.status).json(error.response.data);
    else res.status(500).json({ error: error.message });
  }
});


let raking = [];
const xs = tf.tensor2d([
  [100, 20, 4.5],
  [150, 25, 3.5],
  [80, 15, 4.0],
  [120, 30, 4.8],
  [200, 35, 3.0],
  [90, 18, 4.2],
  [130, 28, 4.6],
  [180, 40, 3.8],
  [160, 32, 4.4],
  [110, 22, 4.7],
  [140, 26, 4.1],
  [170, 38, 3.3],
  [95, 19, 4.3],
  [105, 21, 4.9],
  [210, 45, 2.5],
  [115, 24, 3.7],
  [125, 29, 4.0],
  [145, 33, 3.2],
  [155, 36, 3.6],
]);
const ys = tf.tensor2d([
  [8],
  [7],
  [6],
  [9],
  [5],
  [7],
  [8],
  [6],
  [7],
  [9],
  [6],
  [7],
  [6],
  [8],
  [4],
  [7],
  [8],
  [5],
  [6],
]);

const inputSize = 3; // Số lượng thuộc tính đầu vào (like, comment, rating)
const outputSize = 1; // Số lượng đầu ra (xếp hạng)
const model = tf.sequential();
model.add(tf.layers.dense({ units: outputSize, inputShape: [inputSize] }));

model.compile({
  optimizer: tf.train.adam(),
  loss: 'meanSquaredError',
  metrics: ['mse'],
});

// Huấn luyện mô hình
const trainModel = async () => {
  await model.fit(xs, ys, { epochs: 1000 });
  console.log('Model trained successfully!');
};
const calculateAverage = obj => {
  let sum = 0;
  let count = 0;

  for (let key in obj) {
    sum += obj[key];
    count++;
  }
  return count === 0 ? 0 : sum / count;
};
trainModel().then( async () => {
  const posts = await Post.find().exec();
  const comments = await Comment.find().exec();
  const combinedArray = posts.map(post => ({
    ...post.toObject(),
    comments: comments.filter(comment => Types.ObjectId(comment.postId).equals(post._id)),
  }));

  const newPredictions = combinedArray.map(data => {
    const input = tf.tensor2d([[data.likes.length, calculateAverage(data.rating), data.comments.length]]);
    const prediction = model.predict(input);
    return { ...data, prediction: prediction.dataSync()[0].toFixed(2) };
  });
  raking = newPredictions;
});

app.get('/api/top-posts', async (req, res) => {
  try {
    res.json(raking.sort((a, b) => b.prediction - a.prediction).slice(0, 5));
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});



// socket



app.use("/api/auth", authRoute);
app.use("/api/user", userRoute);
app.use("/api/post", postRoute);
app.use("/api/comment",commentRoute);
app.use("/api/message",messageRoute);
app.use("/api/conversation",conversationRoute);
app.use("/api/friendRequest",friendRequestRoute);
app.use("/api/notification", notificationRoute);
app.use("/api/restaurant", restaurantRoute);
app.use("/api/report", reportRoute);


app.listen(8800, () => {
  console.log("Backend server is running!");
});