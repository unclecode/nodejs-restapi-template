const UserModel = require("../models/UserModel");
const { body, validationResult } = require("express-validator");
const { sanitizeBody } = require("express-validator");
//helper file to prepare responses.
const apiResponse = require("../helpers/apiResponse");
const utility = require("../helpers/utility");

const jwt = require("jsonwebtoken");
const mailer = require("../helpers/mailer");
const { constants } = require("../helpers/constants");

/**
 * User registration.
 *
 * @param {string}      firstName
 * @param {string}      lastName
 * @param {string}      email
 * @param {string}      password
 *
 * @returns {Object}
 */
exports.register = [
	// Validate fields.
	body("firstName").isLength({ min: 1 }).trim().withMessage("First name must be specified.")
		.isAlphanumeric().withMessage("First name has non-alphanumeric characters."),
	body("lastName").isLength({ min: 1 }).trim().withMessage("Last name must be specified.")
		.isAlphanumeric().withMessage("Last name has non-alphanumeric characters."),
	body("email").isLength({ min: 1 }).trim().withMessage("Email must be specified.")
		.isEmail().withMessage("Email must be a valid email address.").custom(async (value) => {
			const user = await UserModel.findOne({ email: value }).exec();
			if (user)
				throw new Error("E-mail already in use")
		}),
	body("password").isLength({ min: 6 }).trim().withMessage("Password must be 6 characters or greater."),
	// Sanitize fields.
	sanitizeBody("firstName").escape(),
	sanitizeBody("lastName").escape(),
	sanitizeBody("email").escape(),
	sanitizeBody("password").escape(),
	// Process request after validation and sanitization.
	async (req, res) => {
		try {
			// Extract the validation errors from a request.
			const errors = validationResult(req);
			if (!errors.isEmpty()) {
				// Display sanitized values/errors messages.
				return apiResponse.validationErrorWithData(res, "Validation Error.", errors.array());
			}

			//hash input password
			const hash = await utility.hashPwd(req.body.password, 10)
			// generate OTP for confirmation
			let otp = utility.randomNumber(4);
			// Create User object with escaped and trimmed data
			var user = new UserModel(
				{
					firstName: req.body.firstName,
					lastName: req.body.lastName,
					email: req.body.email,
					password: hash,
					confirmOTP: otp
				}
			);
			// Html email body
			let html = "<p>Please Confirm your Account.</p><p>OTP: " + otp + "</p>";
			// Send confirmation email
			try {
				await mailer.send(
					constants.confirmEmails.from,
					req.body.email,
					"Confirm Account",
					html
				)
			}
			catch (err) {
				console.log(err);
				return apiResponse.ErrorResponse(res, err);
			}
			try {
				// Save user.

				user = await user.save()
				let userData = {
					_id: user._id,
					firstName: user.firstName,
					lastName: user.lastName,
					email: user.email
				};
				return apiResponse.successResponseWithData(res, "Registration Success.", userData);
			}
			catch (err) {
				console.log(err);
				return apiResponse.ErrorResponse(res, err);
			}
		} catch (err) {
			//throw error in json response with status 500.
			return apiResponse.ErrorResponse(res, err);
		}
	}];

/**
 * User login.
 *
 * @param {string}      email
 * @param {string}      password
 *
 * @returns {Object}
 */
exports.login = [
	body("email").isLength({ min: 1 }).trim().withMessage("Email must be specified.")
		.isEmail().withMessage("Email must be a valid email address."),
	body("password").isLength({ min: 1 }).trim().withMessage("Password must be specified."),
	sanitizeBody("email").escape(),
	sanitizeBody("password").escape(),
	async (req, res) => {
		try {
			const errors = validationResult(req);
			if (!errors.isEmpty()) {
				return apiResponse.validationErrorWithData(res, "Validation Error.", errors.array());
			} else {
				const user = await UserModel.findOne({ email: req.body.email }).exec()
				if (user) {
					//Compare given password with db's hash.
					const same = await utility.hashCompare(req.body.password, user.password)
					if (same) {
						//Check account confirmation.
						if (user.isConfirmed) {
							// Check User's account active or not.
							if (user.status) {
								let userData = {
									_id: user._id,
									firstName: user.firstName,
									lastName: user.lastName,
									email: user.email,
								};
								//Prepare JWT token for authentication
								const jwtPayload = userData;
								const jwtData = {
									expiresIn: process.env.JWT_TIMEOUT_DURATION,
								};
								const secret = process.env.JWT_SECRET;
								//Generated JWT token with Payload and secret.
								userData.token = jwt.sign(jwtPayload, secret, jwtData);
								return apiResponse.successResponseWithData(res, "Login Success.", userData);
							} else {
								return apiResponse.unauthorizedResponse(res, "Account is not active. Please contact admin.");
							}
						} else {
							return apiResponse.unauthorizedResponse(res, "Account is not confirmed. Please confirm your account.");
						}
					} else {
						return apiResponse.unauthorizedResponse(res, "Email or Password wrong.");
					}
				} else {
					return apiResponse.unauthorizedResponse(res, "Email or Password wrong.");
				}
			}
		} catch (err) {
			return apiResponse.ErrorResponse(res, err);
		}
	}];

/**
 * Verify Confirm otp.
 *
 * @param {string}      email
 * @param {string}      otp
 *
 * @returns {Object}
 */
exports.verifyConfirm = [
	body("email").isLength({ min: 1 }).trim().withMessage("Email must be specified.")
		.isEmail().withMessage("Email must be a valid email address."),
	body("otp").isLength({ min: 1 }).trim().withMessage("OTP must be specified."),
	sanitizeBody("email").escape(),
	sanitizeBody("otp").escape(),
	async (req, res) => {
		try {
			const errors = validationResult(req);
			if (!errors.isEmpty()) {
				return apiResponse.validationErrorWithData(res, "Validation Error.", errors.array());
			}
			var query = { email: req.body.email };
			const user = await UserModel.findOne(query).exec()
			if (user) {
				//Check already confirm or not.
				if (!user.isConfirmed) {
					//Check account confirmation.
					if (user.confirmOTP == req.body.otp) {
						//Update user as confirmed
						UserModel.findOneAndUpdate(query, {
							isConfirmed: 1,
							confirmOTP: null
						})
							.then(() => {
								return apiResponse.successResponse(res, "Account confirmed success.");
							})
							.catch(err => {
								return apiResponse.ErrorResponse(res, err);
							});
					} else {
						return apiResponse.unauthorizedResponse(res, "Otp does not match");
					}
				} else {
					return apiResponse.unauthorizedResponse(res, "Account already confirmed.");
				}
			} else {
				return apiResponse.unauthorizedResponse(res, "Specified email not found.");
			}
		} catch (err) {
			return apiResponse.ErrorResponse(res, err);
		}
	}];

/**
 * Resend Confirm otp.
 *
 * @param {string}      email
 *
 * @returns {Object}
 */
exports.resendConfirmOtp = [
	body("email").isLength({ min: 1 }).trim().withMessage("Email must be specified.")
		.isEmail().withMessage("Email must be a valid email address."),
	sanitizeBody("email").escape(),
	async (req, res) => {
		try {
			const errors = validationResult(req);
			if (!errors.isEmpty()) {
				return apiResponse.validationErrorWithData(res, "Validation Error.", errors.array());
			}

			var query = { email: req.body.email };
			const user = await UserModel.findOne(query).exec();
			if (user) {
				//Check already confirm or not.
				if (!user.isConfirmed) {
					// Generate otp
					let otp = utility.randomNumber(4);
					// Html email body
					let html = "<p>Please Confirm your Account.</p><p>OTP: " + otp + "</p>";
					// Send confirmation email
					try {
						await mailer.send(
							constants.confirmEmails.from,
							req.body.email,
							"Confirm Account",
							html
						)
					}
					catch (e) {
						return apiResponse.ErrorResponse(res, err);
					}
					try {
						user.isConfirmed = 0;
						user.confirmOTP = otp;
						// Save user.
						user.save(function (err) {
							if (err) { return apiResponse.ErrorResponse(res, err); }
							return apiResponse.successResponse(res, "Confirm otp sent.");
						});
					}
					catch (err) {
						return apiResponse.ErrorResponse(res, err);

					}

				} else {
					return apiResponse.unauthorizedResponse(res, "Account already confirmed.");
				}
			} else {
				return apiResponse.unauthorizedResponse(res, "Specified email not found.");
			}

		} catch (err) {
			return apiResponse.ErrorResponse(res, err);
		}
	}];