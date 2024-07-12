import { Router } from 'express';
import AuthController from '../controller/auth.controller.js';
import { LoginValidator, SignupValidator, VerifyForSignupValidator } from '../utils/validators/auth.validator.js';
import { uploadSingleImage } from '../middleware/uploadImageMiddleWare.js';

const router = Router();
const authController = new AuthController();

router.post(
  '/signup',
  uploadSingleImage('ID','users'),
  SignupValidator.validate(),
  authController.signup
);
router.post(
  '/verify-signup',
  VerifyForSignupValidator.validate(),
  authController.verifyForSignup
);
router.post('/login', 
  LoginValidator.validate(),
  authController.login
);

export default router;
