import { Schema, Types, model } from "mongoose";
import pkj from "jsonwebtoken";
const { sign } = pkj;
import bcrypt from 'bcryptjs';

const userSchema = new Schema({
  fullName:
  {
    type: String,
    required: [true, 'fullName required']
  },
  Email:
  {
    type: String,
    required: [true, 'fullName required'],
    unique: [true, 'Email must be unique'],
  },
  password: {
    type: String,
    minlength: [8, 'Too short password'],
  },
  IDDocument: {
    type: String,
  },
  // Send Otp
  resetTokenExpiredForSignup: Date,
  resetVerifyForSignup: {
    type: Boolean,
    default: false
  },
  resetTokenExpiredForPassword: Date,
  resetVerifyForPassword: Boolean,

}, { timestamps: true });

userSchema.pre(/^find/, function (next) {
  this.select("-__v -createdAt -updatedAt");
  next()
});

userSchema.pre('find', function (next) {
  this.select('-password');
  next();
});
userSchema.methods.createJWTForSignup = function () {
  return sign({
    userIdForSignup: 1,
    userId: this._id,
  },
    process.env.JWT_SECRET,
    {
      expiresIn: '10m'
    }
  )
};

userSchema.methods.createJWTForResetPassword = function () {
  return sign({
    userIdForResetPassword: 2,
    userId: this._id,
  },
    process.env.JWT_SECRET,
    {
      expiresIn: '10m'
    }
  )
};


userSchema.methods.createJWTForAuthorization = function () {
  return sign({
    userId: this._id,
  },
    process.env.JWT_SECRET,
    {
      expiresIn: '30d'
    }
  )
};

userSchema.methods.comparePass = async function (checkPass) {
  return await bcrypt.compare(checkPass, this.password);
};

userSchema.methods.hashedPass = async function () {
  this.password = await bcrypt.hash(this.password, 10);
};

export default model('User', userSchema);