const User = require("../models/user.model");
const bycrypt= require("bcryptjs");
const auth= require("../middlewares/auth");
const otpGenerator = require("otp-generator");
const crypto = require("crypto");
const key = "otp-seceret-key";

async function login({username,password},callback){
    const user= await User.findOne({username});

    if(user!=null){
        if(bycrypt.compareSync(password,user.password)){
            const token= auth.generateAccessToken(username);
            return callback(null,{...user.toJSON(),token});
        }
        else{
            return callback({
                message:"Invalid UserName/ Password"
            })
        }
    }
    else{
        return callback({
            message:"Invalid UserName/ Password"
        })
    }
}


async function register(params,callback){
    if(params.username === undefined){
        return callback({message:"Username Required"});
    }

    const user= new User(params);
    user.save()
    .then((response)=>{
        return callback(null,response);
        // return res.status(200).json({message:"Authorized User!"})
    }).catch((error)=>{
        return callback(error);
    });
}



async function createOtp(params,callback){
    const otp = otpGenerator.generate(4,{
        lowerCaseAlphabets: false,
        upperCaseAlphabets: false,
        specialChars:false
    });

    const ttl=5*60*1000;
    const expires= Date.now()+ttl;
    const data= `${params.phone}.${otp}.${expires}`;
    const hash = crypto.createHmac("sha256",key).update(data).digest("hex");
    const fullHash = `${hash}.${expires}`;

    console.log(`Your OTP is ${otp}`);

    //Send SMS
    return callback(null,fullHash);

}


async function verifyOTP(params,callback){
    let[hashValue,expires]=params.hash.split('.');

    let now = Date.now();
    if(now> parseInt(expires))return callback("OTP Expired");
    let data = `${params.phone}.${params.otp}.${expires}`;
    let newCalculateHash = crypto
    .createHmac("sha256",key)
    .update(data)
    .digest("hex");


    if(newCalculateHash === hashValue){
        return callback(null, "Sucess");
    }

    return callback("Invalid Otp");

}

module.exports={
    login,
    register,
    createOtp,
    verifyOTP
}