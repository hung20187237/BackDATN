const router = require("express").Router();
const Report = require("../models/Report");
const Post = require("../models/Post");


//create a post
router.post("/", async (req, res) => {
    const newReport = new Report(req.body);
    try {
        const savedReport = await newReport.save();
        res.status(200).json(savedReport);
    } catch (err) {
        res.status(500).json(err);
    }
});

//delete a report with Admin role
router.delete("/:id", async (req, res) => {
    try {
        const report = await Report.findById(req.params.id);
        await report.deleteOne();
        res.status(200).json("the report has been deleted");
    } catch (err) {
        res.status(500).json(err);
    }
});


//delete a report with PostId
router.delete("/byPostId/:id", async (req, res) => {
    try {
        await Report.deleteMany({postReportId: req.params.id});
        res.status(200).json("the report has been deleted");
    } catch (err) {
        res.status(500).json(err);
    }
});

//delete a report with CommentId
router.delete("/byCommentId/:id", async (req, res) => {
    try {
        await Report.deleteMany({commentReportId: req.params.id});
        res.status(200).json("the report has been deleted");
    } catch (err) {
        res.status(500).json(err);
    }
});

//get all post
router.get("/all", async (req, res) => {
    try {
        const reports = await Report.find();
        res.status(200).json(reports);
    } catch (err) {
        res.status(500).json(err);
    }
});


module.exports = router;