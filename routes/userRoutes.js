const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const _ = require('lodash');
const { check, validationResult } = require('express-validator/check');
const User = require('../models/userModel');
const mailgun = require("mailgun-js");

const DOMAIN = "sandbox0a8f096a3dea4e19b048c53e157da52f.mailgun.org";
const mg = mailgun({ apiKey: "b8dcd6ce10d7ffa62b4fd40d37749f5e-9b1bf5d3-593ff1b9", domain: DOMAIN });

// @route    POST api/users
// @desc     Register user
// @access   Public
router.post(
	'/',
	[
		check('name', 'Name is required')
			.not()
			.isEmpty(),
		check('email', 'Please include a valid email').isEmail(),
		check(
			'password',
			'Please enter a password with 6 or more characters'
		).isLength({ min: 6 })
	],
	async (req, res) => {
		const errors = validationResult(req);
		if (!errors.isEmpty()) {
			return res.status(400).json({ message: errors.array() });
		}

		const { name, email, password } = req.body;

		try {
			let user = await User.findOne({ email });

			if (user) {
				return res.status(400).json({ message: 'User already exists' });
			}

			const token = jwt.sign(
				{ name, email, password },
				process.env.JWT_SECRET,
				{ expiresIn: 360000 }
			);

			const data = {
				from: "no-reply@dhanush.com",
				to: email,
				subject: "Email verification token",
				text: `
					<h3>Please get the below token to activate your account</h3>
					<p>${token}</p>
				`
			};
			mg.messages().send(data, function (error, body) {
				if (error) {
					return res.json({
						message: error.message
					})
				}
				res.status(200).json({
					message:"Verification mail has sent successfully"
				})
			});

		} catch (err) {
			res.status(500).json({message:"Server error"});
		}
	}
);


// @route    POST api/users/email-verification
// @desc     verify user
// @access   Public
router.post(
	'/email-verification',
	  (req, res) => {

		const { token } = req.body;

			if (token) {
				jwt.verify(token, process.env.JWT_SECRET, async function(error, decodedToken) {
					if (error) {
						res.status(400).json({ message: "Incorrect or expired link" })
					}
					const { email, password, name } = decodedToken

					let user = await User.findOne({ email });

					if (user) {
						return res.status(400).json({ message: 'User already exists' });
					}

					user = new User({
						name,
						email,
						password
					});

					const salt = await bcrypt.genSalt(10);

					user.password = await bcrypt.hash(password, salt);

					await user.save((err,success)=>{
						if(err){
							return res.status(400).json({message:err})
						}
						res.json({
							message:"signup success"
						})
					});
				})

			}
			else{
				res.status(500).json({message:"Server error"});
			}
			
		
	}
);


// @route    POST api/users/forgot-password
// @desc     forgot password
// @access   Public
router.post(
	'/forgot-password',
	 async (req, res) => {

		const { email } = req.body;

		try {
			let user = await User.findOne({ email });

			if (!user) {
				return res.status(400).json({ message: 'User with this email address doesnt exists' });
			}

			const token = jwt.sign({_id:user._id},process.env.FORGOT_PASSWORD_SECRET,{ expiresIn: 360000 })
			const data = {
				from: "no-reply@dhanush.com",
				to: email,
				subject: "Password reset token",
				text: `
					<h3>Please get the below token to reset the password</h3>
					<p>${token}</p>
				`
			};

			return user.updateOne({resetLink: token},(err,sucess)=>{
				if(err){
					return res.status(400).json({message:"reset password link error"})
				}else{
					mg.messages().send(data, function (error, body) {
						if (error) {
							return res.json({
								message: error.message
							})
						}
						res.status(200).json({
							message:"Verification mail has sent, kindly follow the instruction to reset the password"
						})
					});
				}
			})
			

		} catch (err) {
			res.status(500).send('Server error');
		}
		
	}
);


// @route    POST api/users/reset-password
// @desc     reset password
// @access   Public
router.post(
	'/reset-password',
	 (req, res) => {

		const { resetLink , password} = req.body;

		try {
			jwt.verify(resetLink, process.env.FORGOT_PASSWORD_SECRET, (err,decodedData)=>{
				if(err){
					return res.status(401).json({
						message: "Incorrect token or its expired ."
					})
				}
				User.findOne({resetLink},(err,user)=>{
					if(err || !user){
						return res.status(400).json({message:"User with this token does not exist"})
					}
					const obj = {
						password:password,
						resetLink: ''
					}

					user = _.extend(user, obj);

					user.save((err,result) => {
						if(err){
							return res.status(400).json({message:"Reset password error"})
						}else{
							return res.status(200).json({message:"Your password has been changed"})
						}
					})
				})
			})

		} catch (err) {
			res.status(500).send('Server error');
		}
		
	}
);

module.exports = router;
