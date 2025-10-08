import jwt from 'jsonwebtoken';

const userAuth = async (req, res, next) => {
  const token = req.cookies.token || req.headers["authorization"]?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.jwt_secret);

    if (!decoded.id) {
      return res.status(401).json({ success: false, message: 'Not Authorised, Login Again' });
    }

    // ✅ attach decoded user info to request
    req.user = decoded;  

    next();
  } catch (error) {
    return res.status(401).json({ success: false, message: error.message });
  }
};

export default userAuth;
