import { UserRole } from "@prisma/client";
import { Router } from "express";
import auth from "../../middlewares/auth";
import validateRequest from "../../middlewares/validateRequest";
import { AuthController } from "./auth.controller";
import { AuthValidation } from "./auth.validation";
import passport from "../../config/passport"
import config from "../../config";
import session from "express-session";

const router = Router();
// TikTok routes - disabled until passport-tiktok is properly installed
// TikTok Authentication Routes (only if configured)

router.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key-here',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    maxAge: 600000 // 10 minutes
  }
}));
// TikTok Authentication Routes
router.get("/tiktok", passport.authenticate("tiktok"));

router.get("/tiktok/callback", 
  passport.authenticate("tiktok", { session: false, failureRedirect: "/" }),
  (req, res) => {
    const { accessToken } = req.user as any;
    res.redirect(`http://localhost:3000/auth/success?token=${accessToken}`);
  }
);
// Google login redirect
router.get("/google", passport.authenticate("google", { scope: ["profile", "email"] }));

// Callback
router.get(
  "/google/callback",
  passport.authenticate("google", { session: false, failureRedirect: "/" }),
  (req, res) => {
    const { accessToken } = req.user as any;
    // Redirect to frontend with token
    res.redirect(`${process.env.FRONTEND_URL}/auth/success?token=${accessToken}`);
  }
);

router.get("/facebook", passport.authenticate("facebook", { scope: ["email"] }));

router.get(
  "/facebook/callback",
  passport.authenticate("facebook", { session: false, failureRedirect: "/" }),
  (req, res) => {
    const { accessToken } = req.user as any;
    res.redirect(`${process.env.FRONTEND_URL}/auth/success?token=${accessToken}`);
  }
);

router.get("/verify-email", AuthController.verifyEmail);

router.get("/verify-reset-password", AuthController.verifyResetPassLink);

router.post(
  "/login",
  validateRequest(AuthValidation.loginValidationSchema),
  AuthController.login
);

router.put(
  "/change-password",
  auth(UserRole.USER, UserRole.ADMIN),
  validateRequest(AuthValidation.changePasswordValidationSchema),
  AuthController.changePassword
);

router.post(
  "/forgot-password",
  validateRequest(AuthValidation.forgotPasswordValidationSchema),
  AuthController.forgotPassword
);

router.post("/reset-password", AuthController.resetPassword);

router.post(
  "/resend-verification-link",
  validateRequest(AuthValidation.resendConfirmationLinkValidationSchema),
  AuthController.resendVerificationLink
);

router.post(
  "/resend-reset-pass-link",
  validateRequest(AuthValidation.resendConfirmationLinkValidationSchema),
  AuthController.resendResetPassLink
);

router.get("/me", auth(), AuthController.getMe);

router.post("/refresh-token", AuthController.refreshToken);



export const AuthRoutes = router;
