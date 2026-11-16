
const jwt = require("jsonwebtoken");
const User = require("../models/User");

const getBearerToken = (authorization) => {
  if (typeof authorization !== "string") return null;

  const match = authorization.match(/^Bearer\s+(\S+)$/i);
  return match ? match[1] : null;
};

const isInvalidTokenError = (error) =>
  [
    "JsonWebTokenError",
    "TokenExpiredError",
    "NotBeforeError",
    "CastError",
  ].includes(error.name);

const verifyAccessToken = (token) => {
  if (!process.env.JWT_SECRET) {
    const error = new Error("JWT_SECRET is not configured");
    error.statusCode = 500;
    throw error;
  }

  const decoded = jwt.verify(token, process.env.JWT_SECRET);

  if (
    !decoded ||
    typeof decoded !== "object" ||
    !decoded.id ||
    (decoded.tokenType && decoded.tokenType !== "access")
  ) {
    const error = new Error("Invalid access token");
    error.statusCode = 401;
    throw error;
  }

  return decoded;
};

const isTokenVersionValid = (decoded, user) =>
  (decoded.tokenVersion ?? 0) === (user.tokenVersion ?? 0);

// Middleware to protect routes
const protect = async (req, res, next) => {
  const token = getBearerToken(req.headers.authorization);

  if (!token) {
    return res.status(401).json({
      message: "Not authorized, no valid token",
    });
  }

  let decoded;

  try {
    decoded = verifyAccessToken(token);
  } catch (error) {
    if (error.statusCode === 500) {
      return res.status(500).json({ message: "Authentication is not configured" });
    }

    return res.status(401).json({ message: "Token failed" });
  }

  try {
    const user = await User.findById(decoded.id).select("-password");

    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    if (!user.isEmailVerified) {
      return res.status(403).json({
        message: "Please verify your email to access this resource",
      });
    }

    if (!isTokenVersionValid(decoded, user)) {
      return res.status(401).json({
        message: "Session expired, please log in again",
      });
    }

    req.user = user;
    return next();
  } catch (error) {
    if (isInvalidTokenError(error)) {
      return res.status(401).json({ message: "Token failed" });
    }

    console.error("Authentication database error:", error);
    return res.status(500).json({ message: "Authentication service error" });
  }
};

// Restrict a route to administrators.
// Must run after protect.
const requireAdmin = (req, res, next) => {
  const adminEmails = (process.env.ADMIN_EMAILS || "")
    .split(",")
    .map((email) => email.trim().toLowerCase())
    .filter(Boolean);

  const userEmail = req.user?.email?.trim().toLowerCase();

  if (!adminEmails.length) {
    return res.status(403).json({
      message: "Forbidden: no admins configured",
    });
  }

  if (!userEmail || !adminEmails.includes(userEmail)) {
    return res.status(403).json({
      message: "Forbidden: admin access required",
    });
  }

  return next();
};

// Attach req.user when a valid token is present.
// Continue anonymously when no valid token is supplied.
const optionalProtect = async (req, res, next) => {
  const token = getBearerToken(req.headers.authorization);

  if (!token) {
    return next();
  }

  try {
    const decoded = verifyAccessToken(token);
    const user = await User.findById(decoded.id).select("-password");

    if (user && isTokenVersionValid(decoded, user)) {
      req.user = user;
    }
  } catch (error) {
    // Optional authentication must not block anonymous access.
    if (!isInvalidTokenError(error) && error.statusCode !== 500) {
      console.error("Optional authentication error:", error);
    }
  }

  return next();
};

const parseModeratorEmails = () =>
  (process.env.MODERATOR_EMAILS || "")
    .split(",")
    .map((email) => email.trim().toLowerCase())
    .filter(Boolean);

// Restrict moderation endpoints to configured moderator emails.
// Must run after protect.
const requireModerator = (req, res, next) => {
  const email = req.user?.email?.trim().toLowerCase();
  const moderators = parseModeratorEmails();

  if (!email || !moderators.includes(email)) {
    return res.status(403).json({
      message: "Not authorized: moderator access required",
    });
  }

  return next();
};

module.exports = {
  protect,
  requireAdmin,
  optionalProtect,
  requireModerator,
};
