const router = require("express").Router();
const Comment = require('../models/Comment')
const Post = require('../models/Post')
const User = require('../models/User')
const Report = require("../models/Report");

//create a comment
router.post("/", async (req, res) => {
    const newComment = new Comment(req.body);
    try {
        const savedComment = await newComment.save();
        res.status(200).json(savedComment);
    } catch (err) {
        res.status(500).json(err);
    }
});

// get a Comment
router.get("/:id", async (req, res) => {
    const commentId = req.params.id;
    try {
        const comment = await Comment.findById(commentId)
        console.log('Comment', comment)
        res.status(200).json(comment);
    } catch (err) {
        res.status(500).json(err);
    }
});


// get a reply
router.put("/:id/reply", async (req, res) => {
    const {descreply, userreplyId} = req.body.reply;
    try {
        const comment = await Comment.findById(req.params.id);
        const reply = await comment.updateOne({$push: {reply: {descreply, userreplyId}}});
        const comment1 = await Comment.findById(req.params.id);
        res.status(200).json(comment1);
    } catch (err) {
        res.status(500).json(err);
    }
});

//delete a comment
router.delete("/:id", async (req, res) => {
    try {
        const comment = await Comment.findById(req.params.id);
        if (comment.userId == req.body.userId) {
            await comment.deleteOne();
            res.status(200).json("the comment has been deleted");
        } else {
            res.status(403).json("you can delete only your comment");
        }
    } catch (err) {
        res.status(500).json(err);
    }
});

//delete a comment with Admin role
router.delete("/adminRole/:id", async (req, res) => {
    try {
        const comment = await Comment.findById(req.params.id);
        await comment.deleteOne();
        await Report.deleteMany({commentReportId: req.params.id});
        res.status(200).json("the comment has been deleted");
    } catch (err) {
        res.status(500).json(err);
    }
});

//get all comments
router.get("/all/all", async (req, res) => {
    try {
        const comments = await Comment.find();
        res.status(200).json(comments);
    } catch (err) {
        res.status(500).json(err);
    }
});

//get comments on post
router.get("/onPost/:postId", async (req, res) => {
    try {
        const comments = await Comment.find({postId: req.params.postId});
        const users = []
        for (let i = 0; i < comments.length; i++) {
            const user = await User.findById(comments[i].userId)
            users.push(user)
        }
        res.status(200).json({comments, users});
    } catch (err) {
        res.status(500).json(err);
    }
});

//get comments on postManagement
router.get("/postManagement/:postId", async (req, res) => {
    try {
        const comments = await Comment.find({postId: req.params.postId});
        res.status(200).json(comments);
    } catch (err) {
        res.status(500).json(err);
    }
});

module.exports = router;