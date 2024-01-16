const mongoose = require('mongoose')

const ReportSchema = new mongoose.Schema(
    {
        userId:{
            type: String,
            required: true
        },
        postReportId:{
            type: String,
        },
        commentReportId:{
            type: String,
        },
        ReportProblemId:{
            type: String,
            required: true
        },
        desc: {
            type: String,
        },
    },
    {timestamps: true})

module.exports = mongoose.model('Report',ReportSchema)
