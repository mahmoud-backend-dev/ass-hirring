import { body } from "express-validator";
import validatorMiddleware from '../../middleware/validatorMiddleware.js'
import BadRequest from "../../errors/badRequest.js";

export class SignupValidator {
  static validate() {
    return [
      body('fullName').exists().isString().withMessage(`fullName required and must be string`),
      body('Email').exists().isEmail().withMessage(`Email required and must be valid mail`),
      body('phone').exists().isMobilePhone('ar-EG').withMessage('phone required')
        .custom((val) => {
          if (!val.startsWith('+2'))
            throw new BadRequest('phone must be start with +2')
          return true;
        }),
      body('password').notEmpty().withMessage('password required')
        .isLength({ min: 8 }).withMessage('password must be at least 8 characters'),
      body('confirmPassword').notEmpty().withMessage('confirmPassword required')
        .custom((val, { req }) => {
          if (val !== req.body.password) throw new BadRequest('Password confirmation incorrect');
          return true;
        }),
      body('ID').custom((val, { req }) => {
        if (!req.file)
          throw new BadRequest('PLZ, provide id document and must be file')
        return true
      }),
      validatorMiddleware,
    ]
  }
};

export class VerifyForSignupValidator {
  static validate() {
    return [
      body('token').exists().withMessage('token required'),
      validatorMiddleware,
    ]
  }
};

export class LoginValidator {
  static validate() {
    return [
      body('Email').notEmpty().withMessage('Email required')
        .isEmail().withMessage('E-mail must be valid format'),
      body('password').notEmpty().withMessage('password required'),
      validatorMiddleware,
    ]
  }
}