var express = require("express");
var router = express.Router();

/* GET home page. */
router.get("/test", function(req, res) {
	res.render("test", { title: "Express" });
});

module.exports = router;
