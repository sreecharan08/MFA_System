import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken';
import usermodel from '../models/userModel.js';
import transporter from '../config/nodemailer.js';






export const register = async (req, res) => {
    const { name, email, password,verifyQuestion, verifyAnswer } = req.body || {};


    if (!name || !email || !password ||!verifyQuestion ||!verifyAnswer) {
        return res.json({ success: false, message: 'Missing details' })
    }



    try {

        const existingUser = await usermodel.findOne({ email })

        if (existingUser) {
            return res.json({ success: false, message: "User already exists" })


        }






        const hashedPassword = await bcrypt.hash(password, 8);
        const hashedAnswer = await bcrypt.hash(verifyAnswer, 8);
        const user = new usermodel({ name, email, password: hashedPassword,verifyQuestion,verifyAnswer:hashedAnswer });
        await user.save();

        const token = jwt.sign({ id: user._id }, process.env.jwt_secret, { expiresIn: '7d' });




        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ?
                'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });
        //welcome mail
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome to TimePassssss',
            text: `Welcome ${name}. Your account has been created with email id: ${email}.`
        }
        await transporter.sendMail(mailOptions);

        return res.json({ success: true });
    }
    catch (error) {
        res.json({ success: false, message: error.message })
    }



}


export const login = async (req, res) => {
    const { email, password, verifyQuestion, verifyAnswer } = req.body;
    if (!email || !password || !verifyQuestion || !verifyAnswer) {
        return res.json({ success: false, message: 'Email, password, security question, and answer are required' });
    }

    try {
        const user = await usermodel.findOne({ email });
        if (!user) {
            return res.json({ success: false, message: 'Invalid email' });
        }

        // Compare password
        const isPasswordMatch = await bcrypt.compare(password, user.password);
        if (!isPasswordMatch) {
            return res.json({ success: false, message: 'Invalid password' });
        }

        // Compare security question (plain text)
        if (verifyQuestion !== user.verifyQuestion) {
            return res.json({ success: false, message: 'Security question is incorrect' });
        }

        // Compare security answer (hashed)
        const isAnswerMatch = await bcrypt.compare(verifyAnswer, user.verifyAnswer);
        if (!isAnswerMatch) {
            return res.json({ success: false, message: 'Security answer is incorrect' });
        }

        // Generate token
        const token = jwt.sign({ id: user._id }, process.env.jwt_secret, { expiresIn: '7d' });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.json({ success: true });
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};

export const logout = async (req, res) => {
    try {
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ?
                'none' : 'strict',
        })
        return res.json({ success: true, message: 'Logged out' })





    }
    catch (error) {
        return res.json({ success: false, message: error.message })
    }
}


//verifying the user.....using otp
export const sendVerifyotp = async (req, res) => {
    try {
         const user = await usermodel.findById(req.user.id);

        if (!user) {
            return res.json({ success: false, message: "User not found" });
        }

        if (user.isAccountVerified) {
            return res.json({ success: false, message: "Account already verified" });
        }

        if (!user) {
            return res.json({ success: false, message: "User not found" });
        }

        if (user.isAccountVerified) {
            return res.json({ success: false, message: "Account already verified" });
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));
        user.verifyOTP = otp;
        user.verifyOTPexpAt = Date.now() + 24 * 60 * 60 * 1000;
        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: "Account verification OTP from Timepassss",
            text: `Verify your account using this OTP. Your OTP is: ${otp}.`
        };

        await transporter.sendMail(mailOptions);

        return res.json({ success: true, message: "Verification OTP sent on Email" });
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};



export const verifyEmail = async (req, res) => {
    const { otp } = req.body;

    if (!otp) {
        return res.json({ success: false, message: "OTP is required" });
    }

    try {
        // read token from cookies
        const token = req.cookies.token;
        if (!token) {
            return res.json({ success: false, message: "No token found, please login again" });
        }

        // verify and decode token
        const decoded = jwt.verify(token, process.env.jwt_secret);
        const userId = decoded.id;

        const user = await usermodel.findById(userId);
        if (!user) {
            return res.json({ success: false, message: "User not found" });
        }

        if (!user.verifyOTP || user.verifyOTP !== otp) {
            return res.json({ success: false, message: "Invalid OTP" });
        }

        if (user.verifyOTPexpAt < Date.now()) {
            return res.json({ success: false, message: "OTP expired" });
        }

        user.isAccountVerified = true;
        user.verifyOTP = "";
        user.verifyOTPexpAt = 0;

        await user.save();

        return res.json({ success: true, message: "Email verified successfully" });
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};

export const isAuthenticated = async (req, res) => {


    try {
        return res.json({ success: true })
    }
    catch (error) {
        return res.json({ success: false, message: "error.message" })
    }
}

//paswd reset OTP
export const sendResetOtp = async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.json({ success: false, message: "Email is required" })
    }
    try {
        const user = await usermodel.findOne({ email });
        if (!user) {
            return res.json({ success: false, message: "User not found" })
        }
        const otp = String(Math.floor(100000 + Math.random() * 900000));

        user.resetotp = otp;
        user.resetotpexpAT = Date.now() + 15 * 60 * 1000;
        await user.save()

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password reset otp',
            text: `Your reset passwrod otp is: ${otp}. Please use this OTP to reset Your account password and security question and answer.`
        }

        await transporter.sendMail(mailOptions);
        return res.json({ success: true, message: "Otp sent to your email" })

    }
    catch (error) {
        return res.json({ success: false, message: "error.message" })
    }
}

//reset user passwd
export const resetPassword = async (req, res) => {
    const { email, otp, newPassword, newVerifyQuestion, newVerifyAnswer } = req.body;

    if (!email || !otp || !newPassword || !newVerifyQuestion || !newVerifyAnswer) {
        return res.json({ success: false, message: "Email, otp, new password, new Verify Question and new Verify Answer are required" });
    }

    try {
        const user = await usermodel.findOne({ email });
        if (!user) {
            return res.json({ success: false, message: "User not found" });
        }

        if (user.resetotp === "" || user.resetotp !== otp) {
            return res.json({ success: false, message: "Invalid OTP" });
        }

        if (user.resetotpexpAT < Date.now()) {
            return res.json({ success: false, message: "OTP expired" });
        }

        // Hash new password and new verify answer
        const hashedPassword = await bcrypt.hash(newPassword, 8);
        const hashedVerifyAnswer = await bcrypt.hash(newVerifyAnswer, 8);

        // Update user data
        user.password = hashedPassword;
        user.verifyQuestion = newVerifyQuestion;
        user.verifyAnswer = hashedVerifyAnswer;

        // Reset OTP fields
        user.resetotp = '';
        user.resetotpexpAT = 0;

        await user.save();

        return res.json({ success: true, message: "Password and security question updated successfully" });
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};



