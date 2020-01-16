const bcrypt = require("bcrypt");

exports.randomNumber = function (length) {
	var text = "";
	var possible = "123456789";
	for (var i = 0; i < length; i++) {
		var sup = Math.floor(Math.random() * possible.length);
		text += i > 0 && sup == i ? "0" : possible.charAt(sup);
	}
	return Number(text);
};


exports.hashPwd = (pwd, saltRounds) => {
	return new Promise((resolve, reject) => {
		bcrypt.hash(pwd, saltRounds, function (err, hash) {
			if (err) reject(err)
			resolve(hash)
		});
	})
}

exports.hashCompare = (comingPwd, originPwd) => {
	return new Promise((resolve, reject)=>{
		bcrypt.compare(comingPwd, originPwd, function (err, same) {
			if (err) reject(err)
			resolve(same)
		})
	})
}