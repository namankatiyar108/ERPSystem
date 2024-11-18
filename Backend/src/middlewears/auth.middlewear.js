import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken"
import { User } from "../models/user.models.js";
import bcryptjs from bcryptjs;

export const signup = async(req, res, next) => {
    const {username, email, password,} = req.body;

    if(!username || !email || !password || username === '' || email === '' || password === ''){
        next(ApiError(400, 'All Fields are required'));
    }
    const hashedPassword = bcryptjs.hashSync(password,10);

// new User is method which will automatically detect if user is present or not through user model

    const newUser = new User({
        username,
        email,
        password: hashedPassword
    });

    try {
        await newUser.save();
        res.json("User signup succesfully")
        
    } catch (error) {
        next(ApiError(400, "User with username or email Already registered"))
        
    }
}

export const signin = async(req, res, next) => {
    const {email, password} = req.body;
    if(!email || !password || email === "" || password === ""){
        return next(ApiError(400, "All field are reuired"));
    }
    try {
        const validuser = await User.findOne({email});
        if(!validuser){
            return next(ApiError(400,"Email id is not valid"))
        }

        const validpassword = bcryptjs.compareSync(password, validuser.password)
        if(!validpassword){
            return next(ApiError(400, "Please enter correct password"));

        }
        const token = jwt.sign({id : validuser._id, isAdmin: validuser.isAdmin}, process.env.ACCESS_TOKEN_SECRET);

        const {password: pass, ...rest} = validuser._doc //it is used to sepatreate passwor and other details
        res.status(200).cookies('access_token', token, { httpOnly: true }).json(rest);
        
    } catch (error) {
        next(error);
        
    }

}

export const verifyJWT = asyncHandler(async(req, _, next) => {
    try {
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "")
        
        // console.log(token);
        if (!token) {
            throw new ApiError(401, "Unauthorized request")
        }
        
        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
    
        const user = await User.findById(decodedToken.UserInfo._id).select("-password -refreshToken ")
         
        if (!user) {
            
            throw new ApiError(401, "Invalid Access Token")
        }
    
        req.user = user;
        req.user.roles= decodedToken.UserInfo.roles;
        next()
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid access token")
    }
    
})