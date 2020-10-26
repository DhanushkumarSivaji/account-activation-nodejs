const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
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
			return res.status(400).json({ errors: errors.array() });
		}

		const { name, email, password } = req.body;

		try {
			let user = await User.findOne({ email });

			if (user) {
				return res.status(400).json({ msg: 'User already exists' });
			}

			const token = jwt.sign(
				{ name, email, password },
				process.env.JWT_SECRET,
				{ expiresIn: 360000 }
			);

			const data = {
				from: "Mailgun Sandbox <postmaster@sandbox0a8f096a3dea4e19b048c53e157da52f.mailgun.org>",
				to: "dhanushkumarsivaji@gmail.com",
				subject: "Account Activation Link :",
				text: `
					<h1>Please click the below link to activate the account</h1>
					<p>${token}</p>
				`
			};
			mg.messages().send(data, function (error, body) {
				if (error) {
					return res.json({
						message: error.message
					})
				}
				console.log("sucess", body);
				res.status(200).json({
					message:"Verification mail has sent successfully"
				})
			});

		} catch (err) {
			console.error(err.message);
			res.status(500).send('Server error');
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
				jwt.verify(token, process.env.JWT_SECRET, async function (error, decodedToken) {
					if (error) {
						res.status(400).json({ message: "Incorrect or expired link" })
					}
					const { email, password, name } = decodedToken

					let user = await User.findOne({ email });

					if (user) {
						return res.status(400).json({ msg: 'User already exists' });
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
							console.log("Error in savin user : ",err);
							return res.status(400).json({error:err})
						}
						res.json({
							message:"signup success"
						})
					});
				})

			}
			else{
				console.error(err.message);
				res.status(500).send('Server error');
			}
			
		
	}
);

module.exports = router;
