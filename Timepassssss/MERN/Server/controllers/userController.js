import usermodel from '../models/userModel.js';
export const getUserData = async (req, res) => {
  try {
    const user = await usermodel.findById(req.user.id); // ✅ from token

    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }

    res.json({
      success: true,
      userData: {
        name: user.name,
        email: user.email,
        isAccountVerified: user.isAccountVerified,
        
      },
    });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};
