import { ApiError } from "../utils/ApiError.js";
import { Company } from "../models/company.model.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import crypto from "crypto";
import { asyncHandler } from "../utils/asyncHandler.js";

const generateClientSecret = () => {
    return crypto.randomBytes(32).toString("hex");
};

const generateAccessAndRefreshTokens = async (userId) => {
    try {
        const user = await Company.findById(userId);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();

        user.refreshToken = refreshToken;
        await user.save({ validateBeforeSave: false });

        return { accessToken, refreshToken };

    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating refresh and access tokens");
    }
};

const registerUser = asyncHandler(async (req, res) => {
    const { companyName, ownerName, rollNo, ownerEmail, accessCode } = req.body;

    if ([companyName, ownerName, rollNo, ownerEmail, accessCode].some((field) => field?.trim() === "")) {
        throw new ApiError(400, "All fields are required");
    }

    const existedCompany = await Company.findOne({ ownerEmail });

    if (existedCompany) {
        throw new ApiError(409, "Company with this email already exists");
    }

    const clientID = crypto.randomUUID();
    const clientSecret = generateClientSecret();

    const company = await Company.create({
        companyName,
        ownerName,
        rollNo,
        ownerEmail,
        accessCode,
        clientID,
        clientSecret
    });

    const createdCompany = await Company.findById(company._id).select("-accessCode -refreshToken");

    if (!createdCompany) {
        throw new ApiError(500, "Something went wrong while registering the company");
    }

    return res.status(201).json(
        new ApiResponse(200, {
            companyName: createdCompany.companyName,
            clientID: createdCompany.clientID,
            clientSecret: createdCompany.clientSecret,
            ownerName: createdCompany.ownerName,
            ownerEmail: createdCompany.ownerEmail,
            rollNo: createdCompany.rollNo,
        }, "Company registered successfully. Don't forget to save your credentials!")
    );
})

const loginUser = asyncHandler(async (req, res) => {
    const { companyName,
        ownerName,
        rollNo,
        ownerEmail,
        accessCode,
        clientID,
        clientSecret } = req.body;

    if (!companyName || 
        !ownerName || 
        !rollNo || 
        !ownerEmail || 
        !accessCode || 
        !clientID ||
        !clientSecret) {
        throw new ApiError(400, "All Fields are required");
    }

    const user = await Company.findOne({ ownerEmail: ownerEmail , clientID : clientID });

    if (!user) {
        throw new ApiError(404, "Company does not exist or Please Provide Valid Email or ClientId");
    }

    const isAccessCodeValid = await user.isAccessCodeCorrect(accessCode);

    if (!isAccessCodeValid) {
        throw new ApiError(401, "Invalid access code");
    }

    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user._id);

    const loggedInUser = await Company.findById(user._id).select("-accessCode -refreshToken");

    const options = {
        httpOnly: true,
        secure: true
    };
    const token_type = accessToken.split(" ")[0];
    const expiryDate = process.env.ACCESS_TOKEN_EXPIRY;
    return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(
            new ApiResponse(200, {
                    token_type : token_type,
                    accessToken : accessToken,
                    expires_in : expiryDate
                
            }, "CompanyMan logged in successfully")
        );
});

const logoutUser = asyncHandler(async (req, res) => {
    await Company.findByIdAndUpdate(
        req.user._id,
        {
            $unset: { refreshToken: 1 }
        },
        { new: true }
    );

    const options = {
        httpOnly: true,
        secure: true
    };

    return res
        .status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(new ApiResponse(200, {}, "Company logged out"));
});

const getCurrentUser = asyncHandler(async (req, res) => {
    return res
        .status(200)
        .json(new ApiResponse(200, req.user, "Company fetched successfully"));
});

export {
    registerUser,
    loginUser,
    logoutUser,
    getCurrentUser
};
