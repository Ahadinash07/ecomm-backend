const db = require('../../Models/db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const twilio = require('twilio');
const validator = require('validator');
require('dotenv').config();

if (!process.env.JWT_SECRET || !process.env.JWT_REFRESH_SECRET) {
  console.error('Missing JWT_SECRET or JWT_REFRESH_SECRET in .env');
  process.exit(1);
}

const otpStore = new Map();

const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

const generateOtp = () => Math.floor(100000 + Math.random() * 900000).toString();

const sendOtp = (email, phone, otp, callback) => {
  console.log(`[${new Date().toISOString()}] Sending OTP to:`, { email, phone });
  transporter.sendMail(
    {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP Code for Password Reset',
      text: `Your OTP code for password reset is ${otp}. It is valid for 5 minutes.`,
    },
    (err) => {
      if (err) {
        console.error(`[${new Date().toISOString()}] Email sending error:`, err);
        return callback(err);
      }
      if (phone) {
        twilioClient.messages.create(
          {
            body: `Your OTP code for password reset is ${otp}. It is valid for 5 minutes.`,
            from: process.env.TWILIO_PHONE_NUMBER,
            to: phone,
          },
          (err) => {
            console.error(`[${new Date().toISOString()}] SMS sending error:`, err);
            callback(err);
          }
        );
      } else {
        callback(null);
      }
    }
  );
};

const findByEmailOrPhone = (emailOrPhone, callback) => {
  const query = 'SELECT * FROM users WHERE email = ? OR phone = ?';
  db.query(query, [emailOrPhone, emailOrPhone], (err, results) => {
    if (err) {
      console.error(`[${new Date().toISOString()}] Database query error:`, err);
      return callback(err, null);
    }
    callback(null, results[0]);
  });
};

const findById = (user_id, callback) => {
  const query = 'SELECT * FROM users WHERE user_id = ?';
  db.query(query, [user_id], (err, results) => {
    if (err) {
      console.error(`[${new Date().toISOString()}] Database query error:`, err);
      return callback(err, null);
    }
    callback(null, results[0]);
  });
};

const checkUserExists = (email, username, phone, callback) => {
  console.log(`[${new Date().toISOString()}] Checking if user exists:`, { email, username, phone });
  const query = 'SELECT * FROM users WHERE email = ? OR username = ? OR phone = ?';
  db.query(query, [email, username, phone], (err, results) => {
    if (err) {
      console.error(`[${new Date().toISOString()}] Database query error:`, err);
      return callback(err, null);
    }
    callback(null, results.length > 0);
  });
};

const create = (userData, callback) => {
  const { first_name, last_name, username, email, phone, password } = userData;
  console.log(`[${new Date().toISOString()}] Creating user:`, { first_name, last_name, username, email, phone });

  if (!validator.isEmail(email)) {
    return callback(new Error('Invalid email format'), null);
  }
  if (!username || username.length < 3) {
    return callback(new Error('Username must be at least 3 characters long'), null);
  }
  if (phone && !validator.isMobilePhone(phone)) {
    return callback(new Error('Invalid phone number'), null);
  }
  if (!password || password.length < 6) {
    return callback(new Error('Password must be at least 6 characters long'), null);
  }

  const query =
    'INSERT INTO users (first_name, last_name, username, email, phone, password, status) VALUES (?, ?, ?, ?, ?, ?, ?)';
  db.query(
    query,
    [first_name || null, last_name || null, username, email, phone || null, password, 'Active'],
    (err, result) => {
      if (err) {
        console.error(`[${new Date().toISOString()}] Error creating user:`, err);
        return callback(err, null);
      }
      const selectQuery = 'SELECT user_id FROM users WHERE email = ? AND username = ?';
      db.query(selectQuery, [email, username], (err, results) => {
        if (err) {
          console.error(`[${new Date().toISOString()}] Error fetching user_id:`, err);
          return callback(err, null);
        }
        if (!results[0]?.user_id) {
          console.error(`[${new Date().toISOString()}] No user_id found for:`, { email, username });
          return callback(new Error('Failed to create user: No user_id found'), null);
        }
        callback(null, results[0].user_id);
      });
    }
  );
};

const updateStatus = (user_id, status, callback) => {
  const query = 'UPDATE users SET status = ? WHERE user_id = ?';
  db.query(query, [status, user_id], (err) => {
    if (err) {
      console.error(`[${new Date().toISOString()}] Error updating status:`, err);
      return callback(err);
    }
    callback(null);
  });
};

const updateProfile = (user_id, profileData, callback) => {
  const { first_name, last_name, email, phone, address, city, zip_code, state, country } = profileData;
  console.log(`[${new Date().toISOString()}] Updating profile for user:`, user_id, profileData);

  if (email && !validator.isEmail(email)) {
    return callback(new Error('Invalid email format'), null);
  }
  if (phone && !validator.isMobilePhone(phone)) {
    return callback(new Error('Invalid phone number'), null);
  }

  const checkQuery = 'SELECT user_id FROM users WHERE (email = ? OR phone = ?) AND user_id != ?';
  db.query(checkQuery, [email || null, phone || null, user_id], (err, results) => {
    if (err) {
      console.error(`[${new Date().toISOString()}] Error checking existing email/phone:`, err);
      return callback(err, null);
    }
    if (results.length > 0) {
      return callback(new Error('Email or phone already in use'), null);
    }

    const query = `
      UPDATE users 
      SET first_name = ?, last_name = ?, email = ?, phone = ?, address = ?, city = ?, zip_code = ?, state = ?, country = ?
      WHERE user_id = ?
    `;
    db.query(
      query,
      [
        first_name || null,
        last_name || null,
        email || null,
        phone || null,
        address || null,
        city || null,
        zip_code || null,
        state || null,
        country || null,
        user_id,
      ],
      (err) => {
        if (err) {
          console.error(`[${new Date().toISOString()}] Error updating profile:`, err);
          return callback(err, null);
        }
        callback(null);
      }
    );
  });
};

const resetPassword = (user_id, newPassword, callback) => {
  console.log(`[${new Date().toISOString()}] Resetting password for user:`, user_id);
  if (!newPassword || newPassword.length < 6) {
    return callback(new Error('New password must be at least 6 characters long'), null);
  }

  bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
    if (err) {
      console.error(`[${new Date().toISOString()}] Hashing error:`, err);
      return callback(err, null);
    }

    const query = 'UPDATE users SET password = ? WHERE user_id = ?';
    db.query(query, [hashedPassword, user_id], (err) => {
      if (err) {
        console.error(`[${new Date().toISOString()}] Error resetting password:`, err);
        return callback(err, null);
      }
      callback(null);
    });
  });
};

const checkUserExistsMiddleware = (req, res, next) => {
  const { email, username, phone } = req.body;
  console.log(`[${new Date().toISOString()}] Checking user existence:`, { email, username, phone });
  checkUserExists(email, username, phone, (err, exists) => {
    if (err) {
      console.error(`[${new Date().toISOString()}] Database error:`, err);
      return res.status(500).json({ message: 'Database error' });
    }
    if (exists) {
      return res.status(400).json({ message: 'User already exists' });
    }
    next();
  });
};

const registerOtpController = (req, res) => {
  const { first_name, last_name, username, email, phone, password } = req.body;
  console.log(`[${new Date().toISOString()}] Register OTP request:`, { first_name, last_name, username, email, phone });

  if (!validator.isEmail(email)) {
    return res.status(400).json({ message: 'Invalid email format' });
  }
  if (!username || username.length < 3) {
    return res.status(400).json({ message: 'Username must be at least 3 characters long' });
  }
  if (phone && !validator.isMobilePhone(phone)) {
    return res.status(400).json({ message: 'Invalid phone number' });
  }
  if (!password || password.length < 6) {
    return res.status(400).json({ message: 'Password must be at least 6 characters long' });
  }

  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
      console.error(`[${new Date().toISOString()}] Hashing error:`, err);
      return res.status(500).json({ message: 'Internal server error' });
    }
    const otp = generateOtp();
    otpStore.set(email, { otp, userData: { first_name, last_name, username, email, phone, password: hashedPassword } });
    console.log(`[${new Date().toISOString()}] OTP generated and stored:`, otp);

    sendOtp(email, phone, otp, (err) => {
      if (err) {
        console.error(`[${new Date().toISOString()}] OTP sending error:`, err);
        return res.status(500).json({ message: 'Failed to send OTP' });
      }
      setTimeout(() => otpStore.delete(email), 5 * 60 * 1000);
      return res.status(200).json({ message: 'OTP sent successfully' });
    });
  });
};

const verifyOtpController = (req, res) => {
  const { email, otp } = req.body;
  console.log(`[${new Date().toISOString()}] Verify OTP request:`, { email, otp });

  if (!otpStore.has(email) || otpStore.get(email).otp !== otp) {
    console.log(`[${new Date().toISOString()}] Invalid or expired OTP`);
    return res.status(400).json({ message: 'Invalid or expired OTP' });
  }

  const { first_name, last_name, username, email: storedEmail, phone, password } = otpStore.get(email).userData;

  create({ first_name, last_name, username, email: storedEmail, phone, password }, (err, user_id) => {
    if (err) {
      console.error(`[${new Date().toISOString()}] Database error in create:`, err);
      return res.status(500).json({ message: 'Failed to create user' });
    }

    const token = jwt.sign({ user_id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    const refreshToken = jwt.sign({ user_id }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });
    console.log(`[${new Date().toISOString()}] Tokens generated:`, { token, refreshToken });

    otpStore.delete(email);

    transporter.sendMail(
      {
        from: process.env.EMAIL_USER,
        to: storedEmail,
        subject: 'Welcome to E-Shop!',
        text: `Hi ${first_name}, welcome to E-Shop! Your account has been created successfully.`,
      },
      (err) => {
        if (err) {
          console.error(`[${new Date().toISOString()}] Email error:`, err);
        }
        if (phone) {
          twilioClient.messages.create(
            {
              body: `Hi ${first_name}, welcome to E-Shop! Your account has been created successfully.`,
              from: process.env.TWILIO_PHONE_NUMBER,
              to: phone,
            },
            (err) => {
              if (err) {
                console.error(`[${new Date().toISOString()}] SMS error:`, err);
              }
              return res.status(201).json({ message: 'Registration successful', token, refreshToken });
            }
          );
        } else {
          return res.status(201).json({ message: 'Registration successful', token, refreshToken });
        }
      }
    );
  });
};

const loginController = (req, res) => {
  const { emailOrPhone, password } = req.body;

  findByEmailOrPhone(emailOrPhone, (err, user) => {
    if (err) {
      console.error(`[${new Date().toISOString()}] Database error:`, err);
      return res.status(500).json({ message: 'Database error' });
    }
    if (!user) {
      console.log(`[${new Date().toISOString()}] User not found`);
      return res.status(400).json({ message: 'User not found' });
    }

    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        console.error(`[${new Date().toISOString()}] Password comparison error:`, err);
        return res.status(500).json({ message: 'Internal server error' });
      }
      if (!isMatch) {
        console.log(`[${new Date().toISOString()}] Invalid credentials`);
        return res.status(400).json({ message: 'Invalid credentials' });
      }

      updateStatus(user.user_id, 'Active', (err) => {
        if (err) {
          console.error(`[${new Date().toISOString()}] Status update error:`, err);
          return res.status(500).json({ message: 'Error updating status' });
        }

        const token = jwt.sign({ user_id: user.user_id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        const refreshToken = jwt.sign({ user_id: user.user_id }, process.env.JWT_REFRESH_SECRET, {
          expiresIn: '7d',
        });

        return res.status(200).json({ message: 'Login successful', token, refreshToken });
      });
    });
  });
};

const sendOtpController = (req, res) => {
  const { emailOrPhone } = req.body;
  console.log(`[${new Date().toISOString()}] Send OTP request:`, { emailOrPhone });

  if (!emailOrPhone) {
    return res.status(400).json({ message: 'Email or phone is required' });
  }

  findByEmailOrPhone(emailOrPhone, (err, user) => {
    if (err) {
      console.error(`[${new Date().toISOString()}] Database error:`, err);
      return res.status(500).json({ message: 'Database error' });
    }
    if (!user) {
      console.log(`[${new Date().toISOString()}] User not found for:`, emailOrPhone);
      return res.status(400).json({ message: 'User not found' });
    }

    const otp = generateOtp();
    otpStore.set(user.email, { otp, user_id: user.user_id });
    console.log(`[${new Date().toISOString()}] OTP generated for login:`, otp);

    sendOtp(user.email, user.phone, otp, (err) => {
      if (err) {
        console.error(`[${new Date().toISOString()}] OTP sending error:`, err);
        return res.status(500).json({ message: 'Failed to send OTP' });
      }
      setTimeout(() => otpStore.delete(user.email), 5 * 60 * 1000);
      return res.status(200).json({ message: 'OTP sent successfully' });
    });
  });
};

const loginOtpController = (req, res) => {
  const { emailOrPhone, otp } = req.body;
  console.log(`[${new Date().toISOString()}] Login OTP request:`, { emailOrPhone, otp });

  findByEmailOrPhone(emailOrPhone, (err, user) => {
    if (err) {
      console.error(`[${new Date().toISOString()}] Database error:`, err);
      return res.status(500).json({ message: 'Database error' });
    }
    if (!user) {
      console.log(`[${new Date().toISOString()}] User not found`);
      return res.status(400).json({ message: 'User not found' });
    }

    if (!otpStore.has(user.email) || otpStore.get(user.email).otp !== otp) {
      console.log(`[${new Date().toISOString()}] Invalid or expired OTP`);
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    updateStatus(user.user_id, 'Active', (err) => {
      if (err) {
        console.error(`[${new Date().toISOString()}] Status update error:`, err);
        return res.status(500).json({ message: 'Error updating status' });
      }

      const token = jwt.sign({ user_id: user.user_id }, process.env.JWT_SECRET, { expiresIn: '1h' });
      const refreshToken = jwt.sign({ user_id: user.user_id }, process.env.JWT_REFRESH_SECRET, {
        expiresIn: '7d',
      });
      console.log(`[${new Date().toISOString()}] OTP login tokens generated:`, { token, refreshToken });

      otpStore.delete(user.email);
      return res.status(200).json({ message: 'Login successful', token, refreshToken });
    });
  });
};

const getProfileController = (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Unauthorized: No token provided' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    findById(decoded.user_id, (err, user) => {
      if (err) {
        console.error(`[${new Date().toISOString()}] Database error:`, err);
        return res.status(500).json({ message: 'Database error' });
      }
      if (!user) {
        console.log(`[${new Date().toISOString()}] User not found for ID:`, decoded.user_id);
        return res.status(404).json({ message: 'User not found' });
      }
      return res.status(200).json({ message: 'User details', user });
    });
  });
};

const logoutController = (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    updateStatus(decoded.user_id, 'Inactive', (err) => {
      if (err) {
        console.error(`[${new Date().toISOString()}] Status update error:`, err);
        return res.status(500).json({ message: 'Error updating status' });
      }
      return res.status(200).json({ message: 'Logout successful' });
    });
  });
};

const refreshTokenController = (req, res) => {
  const { refreshToken } = req.body;
  console.log(`[${new Date().toISOString()}] Refresh token request:`, refreshToken ? 'Token provided' : 'No token');

  if (!refreshToken) {
    return res.status(401).json({ message: 'Refresh token required' });
  }

  jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, (err, decoded) => {
    if (err) {
      console.error(`[${new Date().toISOString()}] Refresh token verification error:`, err.message);
      return res.status(401).json({ message: 'Invalid refresh token' });
    }
    console.log(`[${new Date().toISOString()}] Refresh token decoded:`, decoded);

    const newAccessToken = jwt.sign({ user_id: decoded.user_id }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });
    console.log(`[${new Date().toISOString()}] New access token generated:`, newAccessToken);

    return res.status(200).json({ message: 'Token refreshed', token: newAccessToken });
  });
};

const updateProfileController = (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  console.log(`[${new Date().toISOString()}] Update profile request, token:`, token ? 'Found' : 'Not found');

  if (!token) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    const profileData = {
      first_name: req.body.first_name,
      last_name: req.body.last_name,
      email: req.body.email,
      phone: req.body.phone,
      address: req.body.address,
      city: req.body.city,
      zip_code: req.body.zip_code,
      state: req.body.state,
      country: req.body.country,
    };

    updateProfile(decoded.user_id, profileData, (err) => {
      if (err) {
        console.error(`[${new Date().toISOString()}] Profile update error:`, err);
        return res.status(400).json({ message: err.message || 'Failed to update profile' });
      }
      console.log(`[${new Date().toISOString()}] Profile updated for user:`, decoded.user_id);
      return res.status(200).json({ message: 'Profile updated successfully' });
    });
  });
};

const sendForgotPasswordOtpController = (req, res) => {
  const { emailOrPhone } = req.body;
  console.log(`[${new Date().toISOString()}] Forgot password OTP request:`, { emailOrPhone });

  if (!emailOrPhone) {
    return res.status(400).json({ message: 'Email or phone is required' });
  }

  findByEmailOrPhone(emailOrPhone, (err, user) => {
    if (err) {
      console.error(`[${new Date().toISOString()}] Database error:`, err);
      return res.status(500).json({ message: 'Database error' });
    }
    if (!user) {
      console.log(`[${new Date().toISOString()}] User not found for:`, emailOrPhone);
      return res.status(400).json({ message: 'User not found' });
    }

    const otp = generateOtp();
    otpStore.set(user.email, { otp, user_id: user.user_id });
    console.log(`[${new Date().toISOString()}] Forgot password OTP generated:`, otp);

    sendOtp(user.email, user.phone, otp, (err) => {
      if (err) {
        console.error(`[${new Date().toISOString()}] OTP sending error:`, err);
        return res.status(500).json({ message: 'Failed to send OTP' });
      }
      setTimeout(() => otpStore.delete(user.email), 5 * 60 * 1000);
      return res.status(200).json({ message: 'OTP sent successfully' });
    });
  });
};

const resetPasswordController = (req, res) => {
  const { emailOrPhone, otp, newPassword } = req.body;
  console.log(`[${new Date().toISOString()}] Reset password request:`, { emailOrPhone, otp });

  findByEmailOrPhone(emailOrPhone, (err, user) => {
    if (err) {
      console.error(`[${new Date().toISOString()}] Database error:`, err);
      return res.status(500).json({ message: 'Database error' });
    }
    if (!user) {
      console.log(`[${new Date().toISOString()}] User not found`);
      return res.status(400).json({ message: 'User not found' });
    }

    if (!otpStore.has(user.email) || otpStore.get(user.email).otp !== otp) {
      console.log(`[${new Date().toISOString()}] Invalid or expired OTP`);
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    resetPassword(user.user_id, newPassword, (err) => {
      if (err) {
        console.error(`[${new Date().toISOString()}] Password reset error:`, err);
        return res.status(400).json({ message: err.message || 'Failed to reset password' });
      }
      otpStore.delete(user.email);
      console.log(`[${new Date().toISOString()}] Password reset successful for user:`, user.user_id);
      return res.status(200).json({ message: 'Password reset successfully' });
    });
  });
};

const validateToken = async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const query = 'SELECT email, phone FROM users WHERE userId = ?';
    db.query(query, [decoded.userId], (err, results) => {
      if (err || results.length === 0) {
        return res.status(401).json({ message: 'Invalid token' });
      }
      const user = results[0];
      res.status(200).json({ user });
    });
  } catch (err) {
    console.error('Token validation error:', err);
    res.status(401).json({ message: 'Invalid or expired token' });
  }
};

module.exports = {
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
  validateToken
};