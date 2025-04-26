const express = require('express');
const {
  checkUserExistsMiddleware,
  registerOtpController,
  verifyOtpController,
  loginController,
  sendOtpController,
  loginOtpController,
  getProfileController,
  logoutController,
  refreshTokenController,
  updateProfileController,
  sendForgotPasswordOtpController,
  resetPasswordController,
  validateToken,
} = require('../../Controllers/UserController/UserController');

const UserRoute = express.Router();

UserRoute.post('/register-otp', checkUserExistsMiddleware, registerOtpController);
UserRoute.post('/verify-otp', verifyOtpController);
UserRoute.post('/login', loginController);
UserRoute.post('/send-otp', sendOtpController);
UserRoute.post('/login-otp', loginOtpController);
UserRoute.get('/me', getProfileController);
UserRoute.post('/logout', logoutController);
UserRoute.post('/refresh-token', refreshTokenController);
UserRoute.put('/profile', updateProfileController);
UserRoute.post('/forgot-password-otp', sendForgotPasswordOtpController);
UserRoute.post('/reset-password', resetPasswordController);
UserRoute.get('/validate', validateToken);

module.exports = UserRoute;