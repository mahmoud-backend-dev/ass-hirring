import fs from 'fs';
import asyncHandler from 'express-async-handler';
import User from '../models/User.js';
import BadRequest from '../errors/badRequest.js';
import CustomErrorAPI from '../errors/customErrorAPI.js';
import sendEmail from '../utils/sendEmail.js';
import { StatusCodes } from 'http-status-codes';
import pkj from 'jsonwebtoken';
import UnauthenticatedError from '../errors/unauthenticated.js';
import { sanitizeData } from '../utils/sanitizeData.js';
import hbs from 'handlebars';
import NotFoundError from '../errors/notFound.js';

class AuthController {
  constructor() {
    this.templateForSignup = hbs.compile(
      fs.readFileSync('templates/confirmMail.hbs', 'utf-8')
    );

    // Bind methods to the class instance
    this.signup = asyncHandler(this.signup.bind(this));
    this.verifyForSignup = asyncHandler(this.verifyForSignup.bind(this));
    this.login = asyncHandler(this.login.bind(this));
  }

  // @desc Signup
  // @route POST  /auth/signup
  // @access Public
  async signup(req, res) {
    let user = await User.findOne({ Email: req.body.Email });

    if (user) {
      if (user.resetTokenExpiredForSignup > new Date(Date.now())) {
        fs.unlinkSync(req.file.path); 
        throw new BadRequest(`Your Account Not Verified`);
      }
      if (user.resetVerifyForSignup === true) {
        fs.unlinkSync(req.file.path);
        throw new BadRequest(`This email already used, choose another email`);
      }
      fs.unlinkSync(`./uploads/users/${user.IDDocument.split('/').pop()}`);
      user.IDDocument = `${process.env.BASE_URL}/users/${req.file.filename}`;
      user.fullName = req.body.fullName;
      user.Email = req.body.Email;
      user.password = req.body.password;
      user.resetTokenExpiredForSignup = Date.now() + 10 * 60 * 1000;

      const token = user.createJWTForSignup();
      const url = `${process.env.BASE_URL_FRONT}/confirmSignup?token=${token}`;
      const mailOpts = {
        to: user.Email,
        subject: "Verification Your Account (valid for one hour)",
      };
      try {
        await sendEmail(mailOpts, this.templateForSignup({
          name: user.firstName,
          url: url,
        }));
        await user.hashedPass();
        await user.save();
        return res.status(StatusCodes.CREATED).json({ status: "Success" });
      } catch (error) {
        await user.deleteOne();
        throw new CustomErrorAPI('There is an error in sending email', StatusCodes.INTERNAL_SERVER_ERROR);
      }
    }

    user = await User.create({
      fullName: req.body.fullName,
      Email: req.body.Email,
      password: req.body.password,
      IDDocument: `${process.env.BASE_URL}/users/${req.file.filename}`,
    });
    user.resetTokenExpiredForSignup = Date.now() + 10 * 60 * 1000;
    const token = user.createJWTForSignup();

    const url = `${process.env.BASE_URL_FRONT}/confirmSignup?token=${token}`;
    const mailOpts = {
      to: user.Email,
      subject: "Verification Your Account (valid for one hour)",
    };
    try {
      await sendEmail(mailOpts, this.templateForSignup({
        name: user.fullName,
        url: url,
      }));
      await user.hashedPass();
      await user.save();
      res.status(StatusCodes.CREATED).json({ status: "Success" });
    } catch (error) {
      await user.deleteOne();
      throw new CustomErrorAPI('There is an error in sending email', StatusCodes.INTERNAL_SERVER_ERROR);
    }
  }

  // @desc Verify For Signup
  // @route POST  /auth/verifySignup
  // @access Public
  async verifyForSignup(req, res) {
    const decoded = pkj.verify(req.body.token, process.env.JWT_SECRET);
    if (!decoded.userIdForSignup)
      throw new BadRequest('Invalid Token');

    const user = await User.findById(decoded.userId);

    if (!user)
      throw new UnauthenticatedError('The user that belongs to this token does no longer exist');
    if (user.resetVerifyForSignup)
      throw new BadRequest('User Is Active');

    user.resetTokenExpiredForSignup = undefined;
    user.resetVerifyForSignup = true;
    await user.save();

    const token = user.createJWTForAuthorization();
    res.status(StatusCodes.OK).json({ status: "Success", token, user: sanitizeData(user) });
  }

  // @desc Login
  // @route POST  /auth/login
  // @access Public
  async login(req, res) {
    const user = await User.findOne({ Email: req.body.Email });

    if (!user || !(await user.comparePass(req.body.password)))
      throw new NotFoundError(`No user for this email: ${req.body.Email}`);

    if (user.resetVerifyForSignup === false)
      throw new BadRequest('Your Account Not Verified');

    const token = user.createJWTForAuthorization();
    res.status(StatusCodes.OK).json({ status: "Success", token, user: sanitizeData(user) });
  }
}

export default AuthController;
