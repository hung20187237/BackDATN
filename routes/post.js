const router = require("express").Router();
const Post = require("../models/Post");
const User = require("../models/User");
const Report = require("../models/Report");
const Comment = require("../models/Comment");

//create a post
router.post("/", async (req, res) => {
    const newPost = new Post(req.body);
    try {
        const savedPost = await newPost.save();
        res.status(200).json(savedPost);
    } catch (err) {
        res.status(500).json(err);
    }
});

router.get('/suggest-posts/:id', async (req, res) => {

    async function getUserHistory(userId) {
        const user = await User.findById(userId);
        return await Promise.all(
            user.savedposts.map((item) => {
                return Post.findById(item);
            })
        );
    }

    async function getIdPostHistory(userId) {
        const user = await User.findById(userId);
        return user.savedposts;
    }

    async function getFilterPosts(userHistory) {
        return Post.find({_id: {$nin: userHistory}});
    }

    async function getSimilarPosts(savedPosts, allPosts) {
        // Extract unique tags from saved posts
        const uniqueTags = [...new Set(savedPosts.map(post => post.tagkv))];

        // Filter posts with tags similar to saved posts' tags
        const similarPosts = allPosts.filter(post => uniqueTags.includes(post.tagkv));

        // Return the first 10 posts (or fewer if there are less than 10)
        const shuffledPosts = similarPosts.sort(() => Math.random() - 0.5);

        return shuffledPosts.slice(0, 8);
    }


    try {
        const userHistory = await getIdPostHistory(req.params.id);
        const PostsFilter = await getFilterPosts(userHistory);
        // Lấy lịch sử truy cập bài viết của người dùng từ database
        const userPostHistory = await getUserHistory(req.params.id);

        // Tìm các bài viết gợi ý dựa trên lịch sử truy cập
        const suggestedPosts = await getSimilarPosts(userPostHistory, PostsFilter);

        res.json(suggestedPosts);
    } catch (error) {
        console.error(error);
        res.status(500).json({error: 'Đã xảy ra lỗi'});
    }
});


//update a post
router.put("/:id", async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        if (post.userId === req.body.userId) {
            await post.updateOne({$set: req.body});
            res.status(200).json("the post has been updated");
        } else {
            res.status(403).json("you can update only your post");
        }
    } catch (err) {
        res.status(500).json(err);
    }
});

//delete a post

router.delete("/:id", async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        if (post.userId === req.body.userId) {
            await post.deleteOne();
            res.status(200).json("the post has been deleted");
        } else {
            res.status(403).json("you can delete only your post");
        }
    } catch (err) {
        res.status(500).json(err);
    }
});

//delete a post width Admin

router.delete("/deleteAdmin/:id", async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        await post.deleteOne();
        await Report.deleteMany({postReportId: req.params.id});
        await Comment.deleteMany({postId: req.params.id});
        res.status(200).json("the post has been deleted");
    } catch (err) {
        res.status(500).json(err);
    }
});

//like / dislike a post
router.put("/:id/like", async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        if (!post.likes.includes(req.body.userId)) {
            await post.updateOne({$push: {likes: req.body.userId}});
            res.status(200).json("The post has been liked");
        } else {
            await post.updateOne({$pull: {likes: req.body.userId}});
            res.status(200).json("The post has been disliked");
        }
    } catch (err) {
        res.status(500).json(err);
    }
});

// save a post
router.put("/:id/save", async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        if (!post.saveposts.includes(req.body.userId)) {
            await post.updateOne({$push: {saveposts: req.body.userId}});
            res.status(200).json("The post has been saved");
        } else {
            await post.updateOne({$pull: {saveposts: req.body.userId}});
            res.status(200).json("The post has been unsaved");
        }
    } catch (err) {
        res.status(500).json(err);
    }
});


//get a post
router.get("/:id", async (req, res) => {
    const postTitle = req.params.title;
    const postId = req.params.id;
    try {
        const post = postId
            ? await Post.findById(postId)
            : await Post.findOne({title: postTitle});
        res.status(200).json(post);
    } catch (err) {
        res.status(500).json(err);
    }
});


//get timeline posts
router.get("/timeline/:id", async (req, res) => {
    try {
        const currentUser = await User.findById(req.params.id);
        const userPosts = await Post.find({userId: currentUser._id});
        const followingPosts = await Promise.all(
            currentUser.followings.map((followingId) => {
                return Post.find({userId: followingId});
            })
        );
        const friendPosts = await Promise.all(
            currentUser.friends.map((friendId) => {
                return Post.find({userId: friendId});
            })
        );
        let post = userPosts.concat(...followingPosts).concat(...friendPosts)

        //loai bo bai viet trung lap
        let timelinePost = post;
        // timelinePost = post.filter(function (item) {
        //   return timelinePost.includes(item) ? '' : timelinePost.push(item)
        // })
        // console.log("postfaf: ",timelinePost)
        res.status(200).json(timelinePost);
    } catch (err) {
        res.status(500).json(err);
    }
});

//get user's all posts
router.get("/profile/:username", async (req, res) => {
    try {
        const user = await User.findOne({username: req.params.username});
        const posts = await Post.find({userId: user._id});
        res.status(200).json(posts);
    } catch (err) {
        res.status(500).json(err);
    }
});

//get all posts
router.get("/allPosts/:username", async (req, res) => {
    try {
        const posts = await Post.find();
        res.status(200).json(posts);
    } catch (err) {
        res.status(500).json(err);
    }
});

//get post by userID
router.get("/byUserId/:id", async (req, res) => {
    try {
        const posts = await Post.find({userId: req.params.id});
        res.status(200).json(posts);
    } catch (err) {
        res.status(500).json(err);
    }
});

//get user's with save
router.get("/saveposts/:id", async (req, res) => {
    const savePosts = [];
    try {
        const currentUser = await User.findById(req.params.id);
        await Post.saveposts.map((saveid) => {
            if (saveid === currentUser._id) {
                return savePosts.push(Post)
            }
        });
        res.status(200).json(savePosts);
    } catch (err) {
        res.status(500).json(err);
    }
});
//get all posts with tag
router.get("/profile/:tagkv", async (req, res) => {
    try {
        const posts = await Post.find({tagkv: this.post.tagkv});
        res.status(200).json(posts);
    } catch (err) {
        res.status(500).json(err);
    }
});
module.exports = router;