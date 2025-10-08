import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true, unique: true },
    verifyOTP: { type: String, default: '' },
    verifyOTPexpAt: { type: Number, default: 0 },
    isAccountVerified: { type: Boolean, default: false },
    resetotp: { type: String, default: '' },
    resetotpexpAT: { type: Number, default: 0 },
    verifyQuestion:{type: String, required:true},
    verifyAnswer:{type: String,required:true}
});

const usermodel = mongoose.models.user || mongoose.model('user',userSchema)

export default usermodel;