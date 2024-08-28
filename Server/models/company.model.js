import mongoose from "mongoose";
import bcrypt from "bcrypt";
import crypto from "crypto";

const companySchema = new mongoose.Schema({
  companyName: {
    type: String,
    required: true,
  },
  ownerName: {
    type: String,
    required: true,
  },
  rollNo: {
    type: String,
    required: true,
  },
  ownerEmail: {
    type: String,
    required: true,
    unique: true,
    match: [/^\S+@\S+\.\S+$/, 'Please use a valid email address.'],
  },
  accessCode: {
    type: String,
    required: true,
  },
  clientID: {
    type: String,
    required: true,
    unique: true,
    default: () => crypto.randomUUID(),
  },
  clientSecret: {
    type: String,
    required: true,
    default: () => crypto.randomBytes(32).toString("hex"),
  },
  refreshToken: {
    type: String,
  },
});

// Hash access code before saving
companySchema.pre("save", async function (next) {
  if (!this.isModified("accessCode")) return next();

  this.accessCode = await bcrypt.hash(this.accessCode, 10);
  next();
});

// Compare the access code
companySchema.methods.isAccessCodeCorrect = async function (accessCode) {
  return await bcrypt.compare(accessCode, this.accessCode);
};

// Generate Access Token
companySchema.methods.generateAccessToken = function () {
  return jwt.sign(
    {
      _id: this._id,
      ownerEmail: this.ownerEmail,
      rollNo: this.rollNo,
      ownerName: this.ownerName,
    },
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
    }
  );
};

// Generate Refresh Token
companySchema.methods.generateRefreshToken = function () {
  return jwt.sign(
    {
      _id: this._id,
    },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
    }
  );
};

export const Company = mongoose.model("Company", companySchema);
