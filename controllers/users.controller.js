const bycrypt = require('bcryptjs');
const userService= require("../services/users.services");

exports.register= (req,res,next)=>{
    const {password}=req.body;
    const salt= bycrypt.genSaltSync(10);


    req.body.password=bycrypt.hashSync(password,salt);

    userService.register(req.body,(error,result)=>{
        if(error){
            return next(error);
        }
        return res.status(200).send({
           message:"Success",
           data: result, 
        });
    });

};


exports.login=(req,res,next)=>{
    const { username, password}=req.body;

    userService.login({username,password},(error,result)=>{
        if(error){
            return next(error);
        }
        return res.status(200).send({
           message:"Success",
           data: result, 
        });
    });
};


exports.userProfile=(req,res,next)=>{
    return res.status(200).json({message:"Authorized user"});
}


exports.otpLogin= (req,res,next)=>{
    
    userService.createOtp(req.body,(error,results)=>{
        if(error){
            return next(error);
        }
        console.log("Ready OTP!");
        return res.status(200).send({
            message:"Sucess",
            data : results,
            
            
        })
    });
}


exports.verifyOTP= (req,res,next)=>{
    userService.verifyOTP(req.body,(error,results)=>{
        if(error){
            return next(error);
        }
        return res.status(200).send({
            message:"Sucess",
            data: results,
        })


    })
}