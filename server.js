const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
require('dotenv').config();

// ✅ ADD RAZORPAY HERE
const Razorpay = require('razorpay');
const crypto = require('crypto');

const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');

// ============= CLOUDINARY CONFIGURATION =============

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

console.log('\n☁️ CLOUDINARY CONFIGURATION:');
console.log('='.repeat(50));
console.log('Cloud Name:', process.env.CLOUDINARY_CLOUD_NAME ? '✅ Set' : '❌ Missing');
console.log('API Key:', process.env.CLOUDINARY_API_KEY ? '✅ Set' : '❌ Missing');
console.log('API Secret:', process.env.CLOUDINARY_API_SECRET ? '✅ Set' : '❌ Missing');
console.log('='.repeat(50) + '\n');

// ============= RAZORPAY CONFIGURATION =============

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID || 'rzp_test_RclhbuLUaa6vsq',
  key_secret: process.env.RAZORPAY_KEY_SECRET || 'V2tdfQAgjgYqrggJrjCQQguZ'
});

console.log('\n💳 RAZORPAY CONFIGURATION:');
console.log('='.repeat(50));
console.log('Key ID:', process.env.RAZORPAY_KEY_ID ? '✅ Set' : '⚠️  Using test key');
console.log('Key Secret:', process.env.RAZORPAY_KEY_SECRET ? '✅ Set' : '⚠️  Using test secret');
console.log('='.repeat(50) + '\n');

// ✅ ADD THIS - Configure Multer Storage for Cloudinary
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'learnhub-videos',
    resource_type: 'video',
    allowed_formats: ['mp4', 'mov', 'avi', 'mkv', 'webm'],
    transformation: [{ quality: 'auto' }]
  }
});

// ✅ ADD THIS - Configure Multer Storage for Images (Course Thumbnails)
const imageStorage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'learnhub-course-thumbnails',
    resource_type: 'image',
    allowed_formats: ['jpg', 'jpeg', 'png', 'webp'],
    transformation: [{ width: 800, height: 500, crop: 'limit', quality: 'auto' }]
  }
});

const uploadImage = multer({
  storage: imageStorage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB
  },
  fileFilter: (req, file, cb) => {
    console.log('📁 Image filter - MIME type:', file.mimetype);
    
    const allowedTypes = [
      'image/jpeg',
      'image/jpg',
      'image/png',
      'image/webp'
    ];
    
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`Invalid file type: ${file.mimetype}. Only JPG, PNG, and WEBP are allowed.`));
    }
  }
});

// NOW you can use 'storage' in multer
const upload = multer({
  storage: storage,  // ✅ Now this works!
  limits: {
    fileSize: 100 * 1024 * 1024 // 100MB
  },
  fileFilter: (req, file, cb) => {
    console.log('📁 File filter - MIME type:', file.mimetype);
    
    const allowedTypes = [
      'video/mp4',
      'video/quicktime', // .mov
      'video/x-msvideo', // .avi
      'video/x-matroska', // .mkv
      'video/webm'
    ];
    
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`Invalid file type: ${file.mimetype}. Only MP4, MOV, AVI, MKV, and WEBM are allowed.`));
    }
  }
});

const app = express();

app.use(cors({
  origin: [
    "https://learnhub-gamma-flame.vercel.app",
    "https://learnhub-gamma-flame.vercel.app/",
    https://learnhub-backend-szlb.onrender.com,
    "http://localhost:5173"
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'Cache-Control',
    'Expires',
    'Pragma'
  ],
  exposedHeaders: ['Content-Length', 'Content-Type']
}));


// ✅ ADD THESE LINES HERE (after CORS, before MongoDB connection)
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ MongoDB Connected Successfully'))
.catch((err) => console.error('❌ MongoDB Connection Error:', err));

// ============= ERROR HANDLING MIDDLEWARE =============

// Multer error handler
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    console.error('❌ Multer Error:', err.message);
    
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ 
        success: false,
        message: 'File too large. Maximum size is 100MB',
        error: err.message 
      });
    }
    
    return res.status(400).json({ 
      success: false,
      message: 'File upload error',
      error: err.message 
    });
  }
  
  if (err) {
    console.error('❌ Server Error:', err);
    return res.status(500).json({ 
      success: false,
      message: 'Server error',
      error: err.message 
    });
  }
  
  next();
});

// User Schema
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  phone: {
    type: String,
    unique: true,
    sparse: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  role: {
  type: String,
  enum: ['student', 'instructor', 'admin'], // added admin role
  default: 'student'
},
  userId: { 
    type: String, 
    unique: true, 
    sparse: true 
  },
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  enrolledCourses: [{
  courseId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Course'
  },
  progress: {
    type: Number,
    default: 0
  },
  enrolledAt: {
    type: Date,
    default: Date.now
  },
  // ✅ ADD THESE TWO FIELDS
  paymentId: {
    type: String,
    default: null
  },
  orderId: {
    type: String,
    default: null
  },
  originalPrice: Number, // ✅ ADD THIS - Original course price before discount
  amount: Number,        // ✅ UPDATE THIS - Actual amount paid after discount
}],
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// OTP Schema
const otpSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    lowercase: true,
    trim: true
  },
  otp: {
    type: String,
    required: true
  },
  purpose: {
    type: String,
    enum: ['registration', 'password-reset', 'admin-password-reset'], // ✅ ADD THIS
    required: true
  },
  expiresAt: {
    type: Date,
    required: true,
    index: { expires: 0 }
  },
  verified: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Lecture Schema
const lectureSchema = new mongoose.Schema({
  courseId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Course',
    required: true
  },
  title: {
    type: String,
    required: true
  },
  description: {
    type: String,
    default: ''
  },
  videoUrl: {
    type: String,
    required: true
  },
  duration: {
    type: String,
    default: '0h 0m'  // ✅ Add default value
  },
   thumbnail: {  // ADD THIS FIELD
    type: String,
    default: null
  },
  order: {
    type: Number,
    default: 0
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Course Schema
const courseSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true
  },
  instructor: {
    type: String,
    required: true
  },
  instructorId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  category: {
    type: String,
    required: true
  },
  rating: {
    type: Number,
    default: 0
  },
  reviews: {
    type: Number,
    default: 0
  },
  students: {
    type: Number,
    default: 0
  },
  duration: {
    type: String,
    required: true
  },
  price: {
    type: Number,
    required: true
  },
discount: {
  type: Number,
  default: 0,
  min: 0,
  max: 100
},
  image: {
    type: String,
    required: true
  },
  description: {
    type: String,
    required: true
  },
  lessons: {
    type: Number,
    default: 0
  },
  level: {
    type: String,
    enum: ['Beginner', 'Intermediate', 'Advanced'],
    required: true
  },
  bestseller: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Quiz Schema - REPLACE EXISTING
const quizSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true
  },
  description: {
    type: String,
    default: ''
  },
  courseId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Course',
    required: true
  },
  timerMinutes: {
    type: Number,
    required: true,
    min: 1
  },
  allowRetake: {
    type: Boolean,
    default: true
  },
  questions: [{
    questionText: {
      type: String,
      required: true
    },
    options: [{
      type: String,
      required: true
    }],
    correctAnswer: {
      type: Number,
      required: true
    },
    order: {
      type: Number,
      default: 0
    }
  }],
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Quiz Attempt Schema - ADD THIS NEW SCHEMA
const quizAttemptSchema = new mongoose.Schema({
  quizId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Quiz',
    required: true
  },
  studentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  courseId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Course',
    required: true
  },
  answers: [{
    questionIndex: Number,
    selectedAnswer: Number
  }],
  score: {
    type: Number,
    required: true
  },
  percentage: {
    type: Number,
    required: true
  },
  correctAnswers: {
    type: Number,
    required: true
  },
  totalQuestions: {
    type: Number,
    required: true
  },
  timeSpent: {
    type: Number, // in seconds
    required: true
  },
  submittedAt: {
    type: Date,
    default: Date.now
  }
});

const User = mongoose.model('User', userSchema);
const Course = mongoose.model('Course', courseSchema);
const Quiz = mongoose.model('Quiz', quizSchema);
const Lecture = mongoose.model('Lecture', lectureSchema);
const OTP = mongoose.model('OTP', otpSchema);
const QuizAttempt = mongoose.model('QuizAttempt', quizAttemptSchema); // ADD THIS LINE

// ============= BREVO EMAIL SERVICE =============

const shouldUseConsoleOTP = process.env.USE_CONSOLE_OTP === 'true' || !process.env.BREVO_API_KEY;

console.log('\n📧 EMAIL CONFIGURATION:');
console.log('='.repeat(50));
console.log('API Key Present:', !!process.env.BREVO_API_KEY);
console.log('Email Mode:', shouldUseConsoleOTP ? '🧪 CONSOLE' : '✅ BREVO API');
console.log('Sender Email:', process.env.BREVO_SENDER_EMAIL || 'righvipatel@gmail.com');
console.log('Sender Name:', process.env.BREVO_SENDER_NAME || 'LearnHub');
console.log('='.repeat(50) + '\n');

// Generate 6-digit OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Send email via Brevo API v3
const sendBrevoEmail = async (to, subject, htmlContent) => {
  try {
    console.log('\n📧 Sending email via Brevo API...');
    console.log('To:', to);
    console.log('Subject:', subject);
    // Don't log email content for security
    
    const response = await axios({
      method: 'POST',
      url: 'https://api.brevo.com/v3/smtp/email',
      headers: {
        'accept': 'application/json',
        'api-key': process.env.BREVO_API_KEY,
        'content-type': 'application/json'
      },
      data: {
        sender: {
          name: process.env.BREVO_SENDER_NAME || 'LearnHub',
          email: process.env.BREVO_SENDER_EMAIL || 'righvipatel@gmail.com'
        },
        to: [{ email: to }],
        subject: subject,
        htmlContent: htmlContent
      },
      timeout: 15000
    });

    console.log('✅ Email sent successfully!');
    console.log('Message ID:', response.data.messageId);
    
    return { 
      success: true, 
      messageId: response.data.messageId 
    };
  } catch (error) {
    console.error('\n❌ BREVO EMAIL ERROR:');
    
    if (error.response) {
      console.error('Status:', error.response.status);
      console.error('Data:', JSON.stringify(error.response.data, null, 2));
    } else if (error.request) {
      console.error('No response received:', error.message);
    } else {
      console.error('Error:', error.message);
    }
    
    return { 
      success: false, 
      error: error.response?.data || error.message,
      statusCode: error.response?.status
    };
  }
};

// Send OTP email
const sendOTPEmail = async (email, otp, purpose, userName = null) => {
  // Development mode: only show that OTP was generated, not the code itself
  if (shouldUseConsoleOTP) {
    console.log('\n' + '='.repeat(50));
    console.log('🔐 OTP Generated for:', email);
    console.log('📝 Purpose:', purpose);
    console.log('⏱️  Expires: 10 minutes');
    console.log('⚠️  OTP sent to user\'s email (not displayed for security)');
    console.log('='.repeat(50) + '\n');
    return { success: true, messageId: 'console-mode' };
  }

  // Production mode: send via Brevo API
  const purposeText = {
    'registration': 'verify your email and complete registration',
    'password-reset': 'reset your password'
  };

  const purposeTitle = {
    'registration': 'Welcome to LearnHub!',
    'password-reset': 'Password Reset Request'
  };

  // Greeting based on user name
  const greeting = userName ? `Hi ${userName}! 👋` : 'Hello there! 👋';

  const htmlContent = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>LearnHub - Email Verification</title>
    </head>
    <body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f5f7fa;">
      <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="background-color: #f5f7fa; padding: 40px 0;">
        <tr>
          <td align="center">
            <!-- Main Container -->
            <table role="presentation" cellpadding="0" cellspacing="0" width="600" style="background-color: #ffffff; border-radius: 16px; box-shadow: 0 4px 24px rgba(0, 0, 0, 0.08); overflow: hidden;">
              
              <!-- Header with Gradient -->
              <tr>
                <td style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 48px 40px; text-align: center;">
                  <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: 700; letter-spacing: -0.5px;">
                    🎓 LearnHub
                  </h1>
                  <p style="margin: 12px 0 0 0; color: rgba(255, 255, 255, 0.95); font-size: 16px; font-weight: 500;">
                    ${purposeTitle[purpose]}
                  </p>
                </td>
              </tr>

              <!-- Main Content -->
              <tr>
                <td style="padding: 48px 40px;">
                  <h2 style="margin: 0 0 16px 0; color: #1a1a1a; font-size: 24px; font-weight: 600;">
                    ${greeting}
                  </h2>
                  
                  <p style="margin: 0 0 24px 0; color: #4a5568; font-size: 16px; line-height: 1.6;">
                    You're receiving this email to <strong>${purposeText[purpose]}</strong>. Please use the verification code below to continue:
                  </p>

                  <!-- OTP Box with Compact Fancy Design -->
                  <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="margin: 32px 0;">
                    <tr>
                      <td align="center">
                        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 8px; padding: 20px 40px; display: inline-block; box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);">
                          <div style="font-family: 'Courier New', monospace; font-size: 32px; font-weight: 700; color: #ffffff; letter-spacing: 10px; text-shadow: 0 2px 4px rgba(0, 0, 0, 0.2); user-select: all;">
                            ${otp}
                          </div>
                        </div>
                      </td>
                    </tr>
                  </table>

                  <!-- Expiry Notice -->
                  <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="margin: 24px 0; background-color: #fef3c7; border-left: 4px solid #f59e0b; border-radius: 8px;">
                    <tr>
                      <td style="padding: 16px 20px;">
                        <p style="margin: 0; color: #92400e; font-size: 14px; line-height: 1.5;">
                          ⏱️ <strong>Quick Action Required:</strong> This code expires in <strong>10 minutes</strong>. Please use it promptly.
                        </p>
                      </td>
                    </tr>
                  </table>

                  <p style="margin: 32px 0 0 0; color: #4a5568; font-size: 15px; line-height: 1.6;">
                    If you didn't request this verification code, please ignore this email. Your account remains secure.
                  </p>

                  <!-- Signature -->
                  <div style="margin-top: 40px; padding-top: 32px; border-top: 2px solid #e5e7eb;">
                    <p style="margin: 0 0 8px 0; color: #4a5568; font-size: 15px;">
                      Best regards,
                    </p>
                    <p style="margin: 0; color: #1a1a1a; font-size: 16px; font-weight: 600;">
                      The LearnHub Team
                    </p>
                  </div>
                </td>
              </tr>

              <!-- Footer -->
              <tr>
                <td style="background-color: #f9fafb; padding: 32px 40px; border-top: 1px solid #e5e7eb;">
                  <table role="presentation" cellpadding="0" cellspacing="0" width="100%">
                    <tr>
                      <td align="center">
                        <p style="margin: 0 0 12px 0; color: #6b7280; font-size: 13px; line-height: 1.5;">
                          This is an automated message from LearnHub. Please do not reply to this email.
                        </p>

                        <p style="margin: 16px 0 0 0; color: #9ca3af; font-size: 12px;">
                          © ${new Date().getFullYear()} LearnHub. All rights reserved.
                        </p>
                        <p style="margin: 8px 0 0 0; color: #9ca3af; font-size: 11px;">
                          LearnHub Learning Platform | Empowering Education Worldwide
                        </p>
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>

            </table>
          </td>
        </tr>
      </table>
    </body>
    </html>
  `;

  return await sendBrevoEmail(
    email, 
    `${otp} is your LearnHub verification code`, 
    htmlContent
  );
};

// ============= MIDDLEWARE =============

const authMiddleware = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ message: 'Authentication required' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

const instructorMiddleware = async (req, res, next) => {
  if (req.user.role !== 'instructor') {
    return res.status(403).json({ message: 'Access denied. Instructor role required.' });
  }
  next();
};

const validateObjectId = (id) => {
  if (!mongoose.Types.ObjectId.isValid(id)) {
    return null;
  }
  return new mongoose.Types.ObjectId(id);
};

// ✅ ADD THIS NEW FUNCTION
const calculateCourseDuration = async (courseId) => {
  try {
    const lectures = await Lecture.find({ courseId });
    const quizzes = await Quiz.find({ courseId });
    
    let totalMinutes = 0;
    
    // Calculate lecture durations
    lectures.forEach(lecture => {
      if (lecture.duration) {
        // Parse HH:MM:SS format
        const parts = lecture.duration.split(':').map(p => parseInt(p) || 0);
        if (parts.length === 3) {
          totalMinutes += parts[0] * 60 + parts[1] + Math.ceil(parts[2] / 60);
        }
      }
    });
    
    // Add quiz times (assuming avg 2 min per question)
    quizzes.forEach(quiz => {
      if (quiz.timerMinutes) {
        totalMinutes += parseInt(quiz.timerMinutes);
      }
    });
    
    // Convert to hours and minutes
    const hours = Math.floor(totalMinutes / 60);
    const minutes = totalMinutes % 60;
    
    if (hours > 0) {
      return minutes > 0 ? `${hours}h ${minutes}m` : `${hours}h`;
    } else {
      return `${minutes}m`;
    }
  } catch (error) {
    console.error('Error calculating duration:', error);
    return '0h 0m';
  }
};

// ✅ ADD THIS NEW FUNCTION HERE (after validateObjectId)
const isValidVideoUrl = (url) => {
  if (!url) return { valid: false, message: 'Video URL is required' };
  
  const lowerUrl = url.toLowerCase().trim();
  
  // Block YouTube URLs
  if (lowerUrl.includes('youtube.com') || lowerUrl.includes('youtu.be')) {
    return { 
      valid: false, 
      message: '❌ YouTube links are not supported. Please upload video files directly using the "Upload Video" button below.' 
    };
  }
  
  // Block other streaming platforms
  if (lowerUrl.includes('vimeo.com') || lowerUrl.includes('dailymotion.com') || lowerUrl.includes('twitch.tv')) {
    return { 
      valid: false, 
      message: '❌ External video platforms are not supported. Please upload video files directly.' 
    };
  }
  
  // Check for direct video file or Cloudinary URL
  const isDirectVideo = lowerUrl.endsWith('.mp4') || 
                        lowerUrl.endsWith('.webm') || 
                        lowerUrl.endsWith('.ogg') || 
                        lowerUrl.endsWith('.mov') || 
                        lowerUrl.endsWith('.avi') ||
                        lowerUrl.endsWith('.mkv');
  
  const isCloudinaryUrl = lowerUrl.includes('cloudinary.com') && 
                          (lowerUrl.includes('/video/') || lowerUrl.includes('/raw/'));
  
  if (!isDirectVideo && !isCloudinaryUrl) {
    return { 
      valid: false, 
      message: '❌ Invalid video URL format. Must be a direct video file (ending in .mp4, .webm, .ogg, .mov) or a Cloudinary video URL.' 
    };
  }
  
  return { valid: true };
};

// Generate unique user ID
function generateUserId(name, role) {
  const namePrefix = name.substring(0, 3).toUpperCase().padEnd(3, 'X');
  const randomNum = Math.floor(Math.random() * 100).toString().padStart(2, '0');
  const roleId = role === 'instructor' ? 'I' : 'S';
  return `${namePrefix}${randomNum}${roleId}`;
}

// ============= OTP ROUTES =============

// Send OTP
app.post('/api/auth/send-otp', async (req, res) => {
  try {
    const { email, purpose, name } = req.body;

    console.log('\n🔐 OTP REQUEST');
    console.log('Email:', email);
    console.log('Name:', name || 'Not provided');
    console.log('Purpose:', purpose);

    if (!email) {
      return res.status(400).json({ message: 'Email is required' });
    }

    if (!['registration', 'password-reset'].includes(purpose)) {
      return res.status(400).json({ 
        message: 'Invalid purpose. Use "registration" or "password-reset"' 
      });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const existingUser = await User.findOne({ email: normalizedEmail });

    if (purpose === 'registration' && existingUser) {
      return res.status(400).json({ message: 'User already exists with this email' });
    }

    if (purpose === 'password-reset' && !existingUser) {
      return res.status(404).json({ message: 'User not found with this email' });
    }

    // Delete existing OTPs
    await OTP.deleteMany({ email: normalizedEmail, purpose });

    // Generate and save OTP
    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await new OTP({
      email: normalizedEmail,
      otp,
      purpose,
      expiresAt
    }).save();

    console.log('✅ OTP saved to database (OTP hidden for security)');

    // Send OTP email
    const emailResult = await sendOTPEmail(normalizedEmail, otp, purpose);

    if (!emailResult.success) {
      console.error('❌ Failed to send OTP email');
      return res.status(500).json({ 
        message: 'Failed to send OTP. Please check email configuration.',
        error: emailResult.error
      });
    }

    console.log('✅ OTP sent successfully\n');

    res.json({
      message: shouldUseConsoleOTP 
        ? 'OTP generated (check console)' 
        : 'OTP sent to your email',
      email: normalizedEmail,
      expiresIn: 600,
      mode: shouldUseConsoleOTP ? 'console' : 'email'
    });
  } catch (error) {
    console.error('❌ Error sending OTP:', error);
    res.status(500).json({ 
      message: 'Error sending OTP',
      error: error.message 
    });
  }
});

// Verify OTP
app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, otp, purpose } = req.body;

    console.log('\n🔍 OTP VERIFICATION');
    console.log('Email:', email);
    console.log('Purpose:', purpose);
    // Don't log the OTP code for security

    if (!email || !otp || !purpose) {
      return res.status(400).json({ 
        message: 'Email, OTP, and purpose are required' 
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    const otpDoc = await OTP.findOne({
      email: normalizedEmail,
      otp: otp.trim(),
      purpose,
      verified: false,
      expiresAt: { $gt: new Date() }
    });

    if (!otpDoc) {
      console.log('❌ Invalid or expired OTP');
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    otpDoc.verified = true;
    await otpDoc.save();

    if (purpose === 'password-reset') {
      await User.findOneAndUpdate(
        { email: normalizedEmail },
        { isEmailVerified: true }
      );
    }

    console.log('✅ OTP verified\n');

    res.json({
      message: 'OTP verified successfully',
      verified: true
    });
  } catch (error) {
    console.error('❌ Error verifying OTP:', error);
    res.status(500).json({ 
      message: 'Error verifying OTP',
      error: error.message 
    });
  }
});

// ============= AUTH ROUTES =============

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, phone, password, role, otp } = req.body;

    console.log('\n👤 REGISTRATION');
    console.log('Email:', email);
    console.log('Role:', role || 'student');

    if (!name || !email || !password || !otp) {
      return res.status(400).json({ 
        message: 'Name, email, password, and OTP are required' 
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Verify OTP
    const otpDoc = await OTP.findOne({
      email: normalizedEmail,
      otp: otp.trim(),
      purpose: 'registration',
      verified: true,
      expiresAt: { $gt: new Date() }
    });

    if (!otpDoc) {
      return res.status(400).json({ 
        message: 'Please verify your email with OTP first' 
      });
    }

    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser) {
      return res.status(400).json({ 
        message: 'User already exists with this email' 
      });
    }

    if (phone?.trim()) {
      const phoneExists = await User.findOne({ phone: phone.trim() });
      if (phoneExists) {
        return res.status(400).json({ 
          message: 'User already exists with this phone number' 
        });
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate unique userId
let userId = generateUserId(name.trim(), role || 'student');

// Ensure userId is unique (handle collision)
let userIdExists = await User.findOne({ userId });
while (userIdExists) {
  userId = generateUserId(name.trim(), role || 'student');
  userIdExists = await User.findOne({ userId });
}

const userData = {
  name: name.trim(),
  email: normalizedEmail,
  password: hashedPassword,
  role: role || 'student',
  userId, // ← ADD THIS LINE
  isEmailVerified: true
};

if (phone?.trim()) {
  userData.phone = phone.trim();
}

const user = new User(userData);
await user.save();

    await OTP.deleteMany({ email: normalizedEmail, purpose: 'registration' });

    const token = jwt.sign(
      { userId: user._id }, 
      process.env.JWT_SECRET, 
      { expiresIn: '7d' }
    );

    console.log('✅ User registered:', user.email, 'Role:', user.role, '\n');

res.status(201).json({
  message: 'Registration successful',
  token,
  user: {
    id: user._id,
    name: user.name,
    email: user.email,
    phone: user.phone,
    role: user.role,
    userId: user.userId, // ← ADD THIS LINE
    isEmailVerified: user.isEmailVerified
  }
});
  } catch (error) {
    console.error('❌ Registration error:', error);
    
    if (error.code === 11000) {
      const field = Object.keys(error.keyPattern)[0];
      return res.status(400).json({ 
        message: `User already exists with this ${field}` 
      });
    }
    
    res.status(500).json({ 
      message: 'Server error during registration',
      error: error.message 
    });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, phone, password, role } = req.body;

    if (!password) {
      return res.status(400).json({ message: 'Password is required' });
    }

    if (!email && !phone) {
      return res.status(400).json({ message: 'Email or phone is required' });
    }

    let query = {};
    if (email) {
      query.email = email.toLowerCase().trim();
    } else if (phone) {
      query.phone = phone.trim();
    }

    const user = await User.findOne(query);

    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    if (role && user.role !== role) {
      return res.status(401).json({ 
        message: `Please login as ${role}. This account is registered as ${user.role}.` 
      });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Generate userId if not exists (for old users)
if (!user.userId) {
  let userId = generateUserId(user.name, user.role);
  let userIdExists = await User.findOne({ userId });
  while (userIdExists) {
    userId = generateUserId(user.name, user.role);
    userIdExists = await User.findOne({ userId });
  }
  user.userId = userId;
  await user.save();
  console.log('✅ Generated userId for existing user:', userId);
}

    const token = jwt.sign(
      { userId: user._id }, 
      process.env.JWT_SECRET, 
      { expiresIn: '7d' }
    );

    console.log('✅ Login successful:', user.email);

    res.json({
  message: 'Login successful',
  token,
  user: {
    id: user._id,
    name: user.name,
    email: user.email,
    phone: user.phone,
    role: user.role,
    userId: user.userId, // ← ADD THIS LINE
    isEmailVerified: user.isEmailVerified
  }
});


  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ 
      message: 'Server error during login',
      error: error.message 
    });
  }
});

// Reset password
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
      return res.status(400).json({ 
        message: 'Email, OTP, and new password are required' 
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    const otpDoc = await OTP.findOne({
      email: normalizedEmail,
      otp: otp.trim(),
      purpose: 'password-reset',
      verified: true,
      expiresAt: { $gt: new Date() }
    });

    if (!otpDoc) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    user.password = hashedPassword;
    user.isEmailVerified = true;
    await user.save();

    await OTP.deleteMany({ email: normalizedEmail, purpose: 'password-reset' });

    console.log('✅ Password reset:', user.email);

    res.json({
      message: 'Password reset successfully'
    });
  } catch (error) {
    console.error('❌ Error resetting password:', error);
    res.status(500).json({ 
      message: 'Error resetting password',
      error: error.message 
    });
  }
});

// Change password
app.put('/api/user/change-password', authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ 
        message: 'Current password and new password are required' 
      });
    }

    const isPasswordValid = await bcrypt.compare(currentPassword, req.user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Current password is incorrect' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    req.user.password = hashedPassword;
    await req.user.save();

    console.log('✅ Password changed:', req.user.email);

    res.json({
      message: 'Password changed successfully'
    });
  } catch (error) {
    console.error('❌ Error changing password:', error);
    res.status(500).json({ 
      message: 'Error changing password',
      error: error.message 
    });
  }
});

// Get profile
app.get('/api/auth/profile', authMiddleware, async (req, res) => {
  try {
    res.json({
  user: {
    id: req.user._id,
    name: req.user.name,
    email: req.user.email,
    phone: req.user.phone,
    role: req.user.role,
    userId: req.user.userId, // ← ADD THIS LINE
    isEmailVerified: req.user.isEmailVerified,
    enrolledCourses: req.user.enrolledCourses
  }
});
  } catch (error) {
    res.status(500).json({ message: 'Error fetching profile' });
  }
});

// ============= ADMIN LOGIN ROUTE =============
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    // Find admin with role 'admin'
    const admin = await User.findOne({ email: email.toLowerCase().trim(), role: 'admin' });

    if (!admin) {
      return res.status(404).json({ message: 'Admin not found or not authorized' });
    }

    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: admin._id, role: admin.role },
      process.env.JWT_SECRET || 'supersecretkey',
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Admin login successful',
      token,
      admin: {
        id: admin._id,
        name: admin.name,
        email: admin.email,
        role: admin.role
      }
    });
  } catch (error) {
    console.error('❌ Error in admin login:', error);
    res.status(500).json({ message: 'Server error during admin login' });
  }
});


// ============= ADMIN ROUTES (ADD THIS SECTION) =============

// Admin middleware
const adminMiddleware = async (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Access denied. Admin role required.' });
  }
  next();
};

// Get all courses (admin)
app.get('/api/admin/courses', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const courses = await Course.find()
      .populate('instructorId', 'name email')
      .sort({ createdAt: -1 });
    
    res.json({ 
      success: true,
      courses 
    });
  } catch (error) {
    console.error('❌ Error fetching courses for admin:', error);
    res.status(500).json({ message: 'Error fetching courses' });
  }
});

// Get all students (admin)
app.get('/api/admin/students', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const students = await User.find({ role: 'student' })
      .select('name email userId enrolledCourses createdAt')
      .sort({ createdAt: -1 });
    
    res.json({ 
      success: true,
      students 
    });
  } catch (error) {
    console.error('❌ Error fetching students for admin:', error);
    res.status(500).json({ message: 'Error fetching students' });
  }
});

// Add this route to your backend (after other admin routes)

// Reset student password (admin only)
app.post('/api/admin/users/:id/reset-password', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const studentObjectId = validateObjectId(req.params.id);
    
    if (!studentObjectId) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid user ID format' 
      });
    }
    
    const { newPassword } = req.body;
    
    if (!newPassword) {
      return res.status(400).json({ 
        success: false,
        message: 'New password is required' 
      });
    }
    
    if (newPassword.length < 6) {
      return res.status(400).json({ 
        success: false,
        message: 'Password must be at least 6 characters' 
      });
    }
    
    const user = await User.findById(studentObjectId);
    
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found' 
      });
    }
    
    // Don't allow resetting admin passwords
    if (user.role === 'admin') {
      return res.status(403).json({ 
        success: false,
        message: 'Cannot reset admin passwords' 
      });
    }
    
    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();
    
    console.log('✅ Admin reset password for user:', user.email);
    
    res.json({ 
      success: true,
      message: 'Password reset successfully'
    });
  } catch (error) {
    console.error('❌ Error resetting password (admin):', error);
    res.status(500).json({ 
      success: false,
      message: 'Error resetting password',
      error: error.message 
    });
  }
});

// Get all instructors (admin)
app.get('/api/admin/instructors', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const instructors = await User.find({ role: 'instructor' })
      .select('name email userId createdAt')
      .sort({ createdAt: -1 });
    
    // Get course count for each instructor
    const instructorsWithCourses = await Promise.all(
      instructors.map(async (instructor) => {
        const coursesCreated = await Course.countDocuments({ instructorId: instructor._id });
        return {
          ...instructor.toObject(),
          coursesCreated
        };
      })
    );
    
    res.json({ 
      success: true,
      instructors: instructorsWithCourses 
    });
  } catch (error) {
    console.error('❌ Error fetching instructors for admin:', error);
    res.status(500).json({ message: 'Error fetching instructors' });
  }
});

// Get single instructor with populated course details (admin)
app.get('/api/admin/instructors/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const instructorObjectId = validateObjectId(req.params.id);
    
    if (!instructorObjectId) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid instructor ID format' 
      });
    }
    
    // ✅ FIX: Add 'role' to the select statement
    const instructor = await User.findById(instructorObjectId)
      .select('name email userId role createdAt updatedAt');
    
    if (!instructor) {
      return res.status(404).json({ 
        success: false,
        message: 'Instructor not found' 
      });
    }

    // ✅ FIX: Check role properly
    if (instructor.role !== 'instructor') {
      console.log('❌ User role:', instructor.role, '(expected: instructor)');
      return res.status(400).json({ 
        success: false,
        message: `User is not an instructor. Current role: ${instructor.role}` 
      });
    }

    // Fetch courses created by this instructor with full details
    const coursesCreated = await Course.find({ instructorId: instructorObjectId })
      .select('title description category level price image students lessons duration status createdAt')
      .sort({ createdAt: -1 });

    // Calculate statistics
    const totalStudents = coursesCreated.reduce((sum, course) => sum + (course.students || 0), 0);
    const activeCourses = coursesCreated.filter(c => c.status !== 'inactive').length;

    // Format the response
    const formattedInstructor = {
      _id: instructor._id,
      name: instructor.name,
      email: instructor.email,
      userId: instructor.userId,
      role: instructor.role, // ✅ Include role in response
      createdAt: instructor.createdAt,
      updatedAt: instructor.updatedAt,
      coursesCreated: coursesCreated,
      totalStudents: totalStudents,
      activeCourses: activeCourses
    };
    
    console.log('✅ Admin fetched instructor details:', instructor.email);
    console.log('👤 Role:', instructor.role);
    console.log('📚 Courses created:', coursesCreated.length);
    console.log('👥 Total students across all courses:', totalStudents);
    
    res.json({ 
      success: true,
      instructor: formattedInstructor
    });
  } catch (error) {
    console.error('❌ Error fetching instructor details:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error fetching instructor details',
      error: error.message 
    });
  }
});

// Delete course (admin)
app.delete('/api/admin/courses/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const objectId = validateObjectId(req.params.id);
    
    if (!objectId) {
      return res.status(400).json({ message: 'Invalid course ID format' });
    }
    
    const course = await Course.findById(objectId);
    
    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }
    
    // Delete all lectures for this course
    await Lecture.deleteMany({ courseId: objectId });
    
    // Delete all quizzes for this course
    await Quiz.deleteMany({ courseId: objectId });
    
    // Delete course
    await Course.findByIdAndDelete(objectId);
    
    console.log('✅ Admin deleted course:', course.title);
    
    res.json({ 
      success: true,
      message: 'Course deleted successfully'
    });
  } catch (error) {
    console.error('❌ Error deleting course (admin):', error);
    res.status(500).json({ message: 'Error deleting course' });
  }
});

// Delete user (admin) - for both students and instructors
app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const objectId = validateObjectId(req.params.id);
    
    if (!objectId) {
      return res.status(400).json({ message: 'Invalid user ID format' });
    }
    
    const user = await User.findById(objectId);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Don't allow deleting other admins
    if (user.role === 'admin') {
      return res.status(403).json({ message: 'Cannot delete admin users' });
    }
    
    // If instructor, delete their courses
    if (user.role === 'instructor') {
      const instructorCourses = await Course.find({ instructorId: objectId });
      for (const course of instructorCourses) {
        await Lecture.deleteMany({ courseId: course._id });
        await Quiz.deleteMany({ courseId: course._id });
      }
      await Course.deleteMany({ instructorId: objectId });
      console.log('✅ Deleted instructor and their courses');
    }
    
    // Delete user
    await User.findByIdAndDelete(objectId);
    
    console.log('✅ Admin deleted user:', user.email);
    
    res.json({ 
      success: true,
      message: 'User deleted successfully'
    });
  } catch (error) {
    console.error('❌ Error deleting user (admin):', error);
    res.status(500).json({ message: 'Error deleting user' });
  }
});

// Get dashboard statistics (admin)
app.get('/api/admin/statistics', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const totalCourses = await Course.countDocuments();
    const totalStudents = await User.countDocuments({ role: 'student' });
    const totalInstructors = await User.countDocuments({ role: 'instructor' });
    const totalEnrollments = await User.aggregate([
      { $unwind: '$enrolledCourses' },
      { $count: 'total' }
    ]);
    
    res.json({
      success: true,
      statistics: {
        totalCourses,
        totalStudents,
        totalInstructors,
        totalEnrollments: totalEnrollments[0]?.total || 0
      }
    });
  } catch (error) {
    console.error('❌ Error fetching admin statistics:', error);
    res.status(500).json({ message: 'Error fetching statistics' });
  }
});

// ============= ADMIN OTP PASSWORD RESET ROUTES =============

// Send OTP for admin password reset
app.post('/api/admin/send-reset-otp', async (req, res) => {
  try {
    const { email } = req.body;

    console.log('\n🔐 ADMIN PASSWORD RESET OTP REQUEST');
    console.log('Email:', email);

    if (!email) {
      return res.status(400).json({ 
        success: false,
        message: 'Email is required' 
      });
    }

    const normalizedEmail = email.toLowerCase().trim();
    
    // Find admin with role 'admin'
    const admin = await User.findOne({ 
      email: normalizedEmail, 
      role: 'admin' 
    });

    if (!admin) {
      return res.status(404).json({ 
        success: false,
        message: 'Admin not found with this email' 
      });
    }

    // Delete existing OTPs for this email
    await OTP.deleteMany({ email: normalizedEmail, purpose: 'admin-password-reset' });

    // Generate and save OTP
    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await new OTP({
      email: normalizedEmail,
      otp,
      purpose: 'admin-password-reset',
      expiresAt
    }).save();

    console.log('✅ Admin password reset OTP saved to database');

    // Send OTP email
    const emailResult = await sendOTPEmail(normalizedEmail, otp, 'password-reset', admin.name);

    if (!emailResult.success) {
      console.error('❌ Failed to send OTP email');
      return res.status(500).json({ 
        success: false,
        message: 'Failed to send OTP. Please check email configuration.',
        error: emailResult.error
      });
    }

    console.log('✅ Admin password reset OTP sent successfully\n');

    res.json({
      success: true,
      message: shouldUseConsoleOTP 
        ? 'OTP generated (check console)' 
        : 'OTP sent to your email',
      email: normalizedEmail,
      expiresIn: 600,
      mode: shouldUseConsoleOTP ? 'console' : 'email'
    });
  } catch (error) {
    console.error('❌ Error sending admin password reset OTP:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error sending OTP',
      error: error.message 
    });
  }
});

// Verify OTP for admin password reset
app.post('/api/admin/verify-reset-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;

    console.log('\n🔍 ADMIN PASSWORD RESET OTP VERIFICATION');
    console.log('Email:', email);

    if (!email || !otp) {
      return res.status(400).json({ 
        success: false,
        message: 'Email and OTP are required' 
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Verify admin exists
    const admin = await User.findOne({ 
      email: normalizedEmail, 
      role: 'admin' 
    });

    if (!admin) {
      return res.status(404).json({ 
        success: false,
        message: 'Admin not found with this email' 
      });
    }

    const otpDoc = await OTP.findOne({
      email: normalizedEmail,
      otp: otp.trim(),
      purpose: 'admin-password-reset',
      verified: false,
      expiresAt: { $gt: new Date() }
    });

    if (!otpDoc) {
      console.log('❌ Invalid or expired OTP');
      return res.status(400).json({ 
        success: false,
        message: 'Invalid or expired OTP' 
      });
    }

    otpDoc.verified = true;
    await otpDoc.save();

    console.log('✅ Admin password reset OTP verified\n');

    res.json({
      success: true,
      message: 'OTP verified successfully',
      verified: true
    });
  } catch (error) {
    console.error('❌ Error verifying admin password reset OTP:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error verifying OTP',
      error: error.message 
    });
  }
});

// Reset admin password with verified OTP (from login page)
app.post('/api/admin/reset-password-with-otp', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    console.log('\n🔐 ADMIN PASSWORD RESET WITH OTP');
    console.log('Email:', email);

    if (!email || !otp || !newPassword) {
      return res.status(400).json({ 
        success: false,
        message: 'Email, OTP, and new password are required' 
      });
    }

    // Validate password
    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{6,}$/;
    
    if (newPassword.length < 6) {
      return res.status(400).json({ 
        success: false,
        message: 'Password must be at least 6 characters' 
      });
    }
    
    if (!passwordRegex.test(newPassword)) {
      return res.status(400).json({ 
        success: false,
        message: 'Password must contain at least one letter, one number, and one special character (@$!%*#?&)' 
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Verify OTP
    const otpDoc = await OTP.findOne({
      email: normalizedEmail,
      otp: otp.trim(),
      purpose: 'admin-password-reset',
      verified: true,
      expiresAt: { $gt: new Date() }
    });

    if (!otpDoc) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid or expired OTP. Please verify OTP first.' 
      });
    }

    // Find admin
    const admin = await User.findOne({ 
      email: normalizedEmail, 
      role: 'admin' 
    });

    if (!admin) {
      return res.status(404).json({ 
        success: false,
        message: 'Admin not found with this email' 
      });
    }

    // Update password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    admin.password = hashedPassword;
    admin.isEmailVerified = true;
    await admin.save();

    // Delete used OTP
    await OTP.deleteMany({ email: normalizedEmail, purpose: 'admin-password-reset' });

    // Generate token for auto-login
    const token = jwt.sign(
      { userId: admin._id, role: admin.role },
      process.env.JWT_SECRET || 'supersecretkey',
      { expiresIn: '7d' }
    );

    console.log('✅ Admin password reset successful:', admin.email);

    res.json({
      success: true,
      message: 'Password reset successful',
      token,
      admin: {
        id: admin._id,
        name: admin.name,
        email: admin.email,
        role: admin.role
      }
    });
  } catch (error) {
    console.error('❌ Error resetting admin password:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error resetting password',
      error: error.message 
    });
  }
});

// Reset admin password from profile (authenticated admin)
app.put('/api/admin/change-password-with-otp', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    console.log('\n🔐 ADMIN PASSWORD CHANGE WITH OTP (PROFILE)');
    console.log('Email:', email);
    console.log('Admin:', req.user.email);

    if (!email || !otp || !newPassword) {
      return res.status(400).json({ 
        success: false,
        message: 'Email, OTP, and new password are required' 
      });
    }

    // Validate password
    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{6,}$/;
    
    if (newPassword.length < 6) {
      return res.status(400).json({ 
        success: false,
        message: 'Password must be at least 6 characters' 
      });
    }
    
    if (!passwordRegex.test(newPassword)) {
      return res.status(400).json({ 
        success: false,
        message: 'Password must contain at least one letter, one number, and one special character (@$!%*#?&)' 
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Verify OTP
    const otpDoc = await OTP.findOne({
      email: normalizedEmail,
      otp: otp.trim(),
      purpose: 'admin-password-reset',
      verified: true,
      expiresAt: { $gt: new Date() }
    });

    if (!otpDoc) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid or expired OTP. Please verify OTP first.' 
      });
    }

    // Ensure the email matches the logged-in admin
    if (req.user.email.toLowerCase() !== normalizedEmail) {
      return res.status(403).json({ 
        success: false,
        message: 'Email does not match your account' 
      });
    }

    // Update password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    req.user.password = hashedPassword;
    await req.user.save();

    // Delete used OTP
    await OTP.deleteMany({ email: normalizedEmail, purpose: 'admin-password-reset' });

    console.log('✅ Admin password changed successfully:', req.user.email);

    res.json({ 
      success: true,
      message: 'Password changed successfully'
    });
  } catch (error) {
    console.error('❌ Error changing admin password:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error changing password',
      error: error.message 
    });
  }
});

// ============= ADMIN ANALYTICS ROUTES =============

// Analytics Schema for storing historical data
const analyticsSchema = new mongoose.Schema({
  date: {
    type: Date,
    required: true,
    unique: true
  },
  totalRevenue: {
    type: Number,
    default: 0
  },
  totalStudents: {
    type: Number,
    default: 0
  },
  totalInstructors: {
    type: Number,
    default: 0
  },
  totalCourses: {
    type: Number,
    default: 0
  },
  newEnrollments: {
    type: Number,
    default: 0
  },
  revenueByCategory: [{
    category: String,
    revenue: Number
  }],
  topCourses: [{
    courseId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Course'
    },
    title: String,
    enrollments: Number,
    revenue: Number
  }],
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const Analytics = mongoose.model('Analytics', analyticsSchema);

// Get comprehensive analytics dashboard data
app.get('/api/admin/analytics/dashboard', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    console.log('\n📊 FETCHING ANALYTICS DASHBOARD DATA');
    
    const { period = '30days' } = req.query;
    
    // Determine number of days based on period
    let numberOfDays;
    if (period === '7days') {
      numberOfDays = 7;
    } else if (period === '30days') {
      numberOfDays = 30;
    } else if (period === '90days') {
      numberOfDays = 90;
    } else if (period === '1year') {
      numberOfDays = 365;
    } else {
      numberOfDays = 30; // default
    }
    
    const now = new Date();
    const startDate = new Date(now.getTime() - numberOfDays * 24 * 60 * 60 * 1000);

    // 1. Overall Statistics
    const totalStudents = await User.countDocuments({ role: 'student' });
    const totalInstructors = await User.countDocuments({ role: 'instructor' });
    const totalCourses = await Course.countDocuments();
    
    // Calculate total revenue from all enrollments
    const allUsers = await User.find({ role: 'student' });
    let totalRevenue = 0;
    let totalEnrollments = 0;
    
    allUsers.forEach(user => {
      user.enrolledCourses.forEach(ec => {
        if (ec.amount) {
          totalRevenue += ec.amount;
          totalEnrollments++;
        }
      });
    });

    // 2. Growth Statistics (compared to previous period)
    const previousPeriodStart = new Date(startDate.getTime() - numberOfDays * 24 * 60 * 60 * 1000);
    
    const currentPeriodStudents = await User.countDocuments({ 
      role: 'student',
      createdAt: { $gte: startDate }
    });
    
    const previousPeriodStudents = await User.countDocuments({ 
      role: 'student',
      createdAt: { 
        $gte: previousPeriodStart,
        $lt: startDate
      }
    });

    const studentGrowth = previousPeriodStudents > 0 
      ? ((currentPeriodStudents - previousPeriodStudents) / previousPeriodStudents * 100).toFixed(1)
      : 0;

    // 3. Revenue by Category
    const courses = await Course.find();
    const revenueByCategory = {};
    
    allUsers.forEach(user => {
      user.enrolledCourses.forEach(ec => {
        const course = courses.find(c => c._id.toString() === ec.courseId.toString());
        if (course && ec.amount) {
          if (!revenueByCategory[course.category]) {
            revenueByCategory[course.category] = 0;
          }
          revenueByCategory[course.category] += ec.amount;
        }
      });
    });

    const categoryData = Object.entries(revenueByCategory).map(([category, revenue]) => ({
      category,
      revenue,
      percentage: ((revenue / totalRevenue) * 100).toFixed(1)
    })).sort((a, b) => b.revenue - a.revenue);

    // 4. Top Performing Courses
    const courseEnrollments = {};
    const courseRevenue = {};
    
    allUsers.forEach(user => {
      user.enrolledCourses.forEach(ec => {
        const courseId = ec.courseId.toString();
        courseEnrollments[courseId] = (courseEnrollments[courseId] || 0) + 1;
        courseRevenue[courseId] = (courseRevenue[courseId] || 0) + (ec.amount || 0);
      });
    });

    const topCourses = await Promise.all(
      Object.entries(courseEnrollments)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 10)
        .map(async ([courseId, enrollments]) => {
          const course = await Course.findById(courseId);
          return {
            courseId,
            title: course?.title || 'Unknown',
            instructor: course?.instructor || 'Unknown',
            enrollments,
            revenue: courseRevenue[courseId] || 0,
            rating: course?.rating || 0,
            image: course?.image
          };
        })
    );

    // 5. Revenue Trend - UPDATED TO MATCH PERIOD
    const revenueTrend = [];
    for (let i = numberOfDays - 1; i >= 0; i--) {
      const date = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
      const dayStart = new Date(date.setHours(0, 0, 0, 0));
      const dayEnd = new Date(date.setHours(23, 59, 59, 999));
      
      let dayRevenue = 0;
      let dayEnrollments = 0;
      
      allUsers.forEach(user => {
        user.enrolledCourses.forEach(ec => {
          const enrollDate = new Date(ec.enrolledAt);
          if (enrollDate >= dayStart && enrollDate <= dayEnd && ec.amount) {
            dayRevenue += ec.amount;
            dayEnrollments++;
          }
        });
      });
      
      revenueTrend.push({
        date: dayStart.toISOString().split('T')[0],
        revenue: dayRevenue,
        enrollments: dayEnrollments
      });
    }

    // 6. Student Growth Trend - UPDATED TO MATCH PERIOD
    const studentTrend = [];
    for (let i = numberOfDays - 1; i >= 0; i--) {
      const date = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
      const dayStart = new Date(date.setHours(0, 0, 0, 0));
      const dayEnd = new Date(date.setHours(23, 59, 59, 999));
      
      const newStudents = await User.countDocuments({
        role: 'student',
        createdAt: { $gte: dayStart, $lte: dayEnd }
      });
      
      studentTrend.push({
        date: dayStart.toISOString().split('T')[0],
        students: newStudents
      });
    }

    // 7. Instructor Performance
    const instructorPerformance = await Promise.all(
      (await User.find({ role: 'instructor' }).limit(10)).map(async (instructor) => {
        const instructorCourses = await Course.find({ instructorId: instructor._id });
        let totalStudents = 0;
        let totalRevenue = 0;
        
        instructorCourses.forEach(course => {
          totalStudents += course.students || 0;
        });
        
        allUsers.forEach(user => {
          user.enrolledCourses.forEach(ec => {
            const course = instructorCourses.find(c => c._id.toString() === ec.courseId.toString());
            if (course && ec.amount) {
              totalRevenue += ec.amount;
            }
          });
        });
        
        return {
          instructorId: instructor._id,
          name: instructor.name,
          email: instructor.email,
          coursesCreated: instructorCourses.length,
          totalStudents,
          totalRevenue,
          averageRating: instructorCourses.reduce((sum, c) => sum + (c.rating || 0), 0) / instructorCourses.length || 0
        };
      })
    );

    // 8. Recent Activity
    const recentEnrollments = [];
    for (const user of allUsers.slice(0, 50)) {
      for (const ec of user.enrolledCourses) {
        const course = await Course.findById(ec.courseId);
        if (course) {
          recentEnrollments.push({
            studentName: user.name,
            studentEmail: user.email,
            courseTitle: course.title,
            amount: ec.amount || 0,
            enrolledAt: ec.enrolledAt
          });
        }
      }
    }
    recentEnrollments.sort((a, b) => new Date(b.enrolledAt) - new Date(a.enrolledAt));
    const recentActivity = recentEnrollments.slice(0, 20);

    console.log('✅ Analytics data compiled');
    console.log('📊 Period:', period, '(' + numberOfDays + ' days)');
    console.log('📊 Data points:', revenueTrend.length);
    console.log('📊 Total Revenue:', totalRevenue);
    console.log('👥 Total Students:', totalStudents);
    console.log('👨‍🏫 Total Instructors:', totalInstructors);
    console.log('📚 Total Courses:', totalCourses);

    res.json({
      success: true,
      overview: {
        totalRevenue,
        totalStudents,
        totalInstructors,
        totalCourses,
        totalEnrollments,
        studentGrowth: parseFloat(studentGrowth),
        averageRevenuePerStudent: totalStudents > 0 ? (totalRevenue / totalStudents).toFixed(2) : 0
      },
      revenueByCategory: categoryData,
      topCourses,
      revenueTrend,
      studentTrend,
      instructorPerformance: instructorPerformance.sort((a, b) => b.totalRevenue - a.totalRevenue),
      recentActivity,
      period,
      numberOfDays
    });
  } catch (error) {
    console.error('❌ Error fetching analytics:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error fetching analytics',
      error: error.message 
    });
  }
});

// Save daily analytics snapshot (run this daily via cron job)
app.post('/api/admin/analytics/snapshot', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    // Check if snapshot already exists for today
    const existing = await Analytics.findOne({ date: today });
    if (existing) {
      return res.json({ message: 'Snapshot already exists for today' });
    }

    const totalStudents = await User.countDocuments({ role: 'student' });
    const totalInstructors = await User.countDocuments({ role: 'instructor' });
    const totalCourses = await Course.countDocuments();
    
    const allUsers = await User.find({ role: 'student' });
    let totalRevenue = 0;
    let newEnrollments = 0;
    const revenueByCategory = {};
    
    const todayStart = new Date(today);
    const todayEnd = new Date(today);
    todayEnd.setHours(23, 59, 59, 999);
    
    allUsers.forEach(user => {
      user.enrolledCourses.forEach(ec => {
        if (ec.amount) {
          totalRevenue += ec.amount;
          
          const enrollDate = new Date(ec.enrolledAt);
          if (enrollDate >= todayStart && enrollDate <= todayEnd) {
            newEnrollments++;
          }
        }
      });
    });

    const snapshot = new Analytics({
      date: today,
      totalRevenue,
      totalStudents,
      totalInstructors,
      totalCourses,
      newEnrollments
    });

    await snapshot.save();
    
    res.json({ 
      success: true,
      message: 'Analytics snapshot saved',
      snapshot 
    });
  } catch (error) {
    console.error('❌ Error saving analytics snapshot:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error saving analytics',
      error: error.message 
    });
  }
});

// Get historical analytics data
app.get('/api/admin/analytics/history', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { days = 30 } = req.query;
    
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));
    startDate.setHours(0, 0, 0, 0);
    
    const history = await Analytics.find({
      date: { $gte: startDate }
    }).sort({ date: 1 });
    
    res.json({
      success: true,
      history
    });
  } catch (error) {
    console.error('❌ Error fetching analytics history:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error fetching history',
      error: error.message 
    });
  }
});

// ============= ADMIN COURSE UPDATE ROUTES =============

// Update course (admin)
app.put('/api/admin/courses/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const objectId = validateObjectId(req.params.id);
    
    if (!objectId) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid course ID format' 
      });
    }
    
    const course = await Course.findById(objectId);

    if (!course) {
      return res.status(404).json({ 
        success: false,
        message: 'Course not found' 
      });
    }

    const { title, description, category, level, price, duration, image, lessons, discount } = req.body;
    
    if (title !== undefined) course.title = title;
    if (description !== undefined) course.description = description;
    if (category !== undefined) course.category = category;
    if (level !== undefined) course.level = level;
    if (price !== undefined) course.price = price;
    if (discount !== undefined) course.discount = discount;
    if (duration !== undefined) course.duration = duration;
    if (image !== undefined) course.image = image;
    if (lessons !== undefined) course.lessons = lessons;
    
    course.updatedAt = Date.now();
    await course.save();

    console.log('✅ Admin updated course:', course.title);

    res.json({ 
      success: true,
      message: 'Course updated successfully',
      course 
    });
  } catch (error) {
    console.error('❌ Error updating course (admin):', error);
    res.status(500).json({ 
      success: false,
      message: 'Error updating course',
      error: error.message 
    });
  }
});

// Upload course thumbnail (admin)
app.post('/api/admin/courses/:id/upload-thumbnail', 
  authMiddleware, 
  adminMiddleware,
  (req, res, next) => {
    console.log('\n🖼️ ADMIN COURSE THUMBNAIL UPLOAD');
    console.log('Course ID:', req.params.id);
    console.log('Admin:', req.user?.email);
    next();
  },
  uploadImage.single('thumbnail'), 
  async (req, res) => {
    try {
      const objectId = validateObjectId(req.params.id);
      if (!objectId) {
        return res.status(400).json({ 
          success: false,
          message: 'Invalid course ID format' 
        });
      }

      const course = await Course.findById(objectId);
      if (!course) {
        return res.status(404).json({ 
          success: false,
          message: 'Course not found' 
        });
      }

      if (!req.file) {
        return res.status(400).json({ 
          success: false,
          message: 'No image file uploaded' 
        });
      }

      // Delete old Cloudinary image if exists
      if (course.image && course.image.includes('cloudinary.com')) {
        try {
          const publicIdMatch = course.image.match(/\/([^\/]+)\.(jpg|jpeg|png|webp)$/);
          if (publicIdMatch) {
            const oldPublicId = `learnhub-course-thumbnails/${publicIdMatch[1]}`;
            await cloudinary.uploader.destroy(oldPublicId);
            console.log('🗑️ Deleted old thumbnail');
          }
        } catch (err) {
          console.log('⚠️ Could not delete old thumbnail:', err.message);
        }
      }

      course.image = req.file.path;
      course.updatedAt = Date.now();
      await course.save();

      console.log('✅ Course thumbnail updated:', req.file.path, '\n');

      res.json({
        success: true,
        message: 'Thumbnail uploaded successfully',
        imageUrl: req.file.path,
        publicId: req.file.filename
      });
    } catch (error) {
      console.error('❌ Upload error:', error);
      
      if (req.file?.filename) {
        try {
          await cloudinary.uploader.destroy(req.file.filename);
        } catch (e) {}
      }
      
      res.status(500).json({ 
        success: false,
        message: 'Error uploading thumbnail',
        error: error.message 
      });
    }
  }
);

// Upload lecture thumbnail (admin and instructor)
app.post('/api/courses/:courseId/lectures/:lectureId/upload-thumbnail', 
  authMiddleware,
  (req, res, next) => {
    // Allow both instructors and admins
    if (req.user.role !== 'instructor' && req.user.role !== 'admin') {
      return res.status(403).json({ 
        success: false,
        message: 'Only instructors and admins can upload lecture thumbnails' 
      });
    }
    next();
  },
  (req, res, next) => {
    console.log('\n🖼️ LECTURE THUMBNAIL UPLOAD');
    console.log('Course ID:', req.params.courseId);
    console.log('Lecture ID:', req.params.lectureId);
    console.log('User:', req.user?.email);
    console.log('Role:', req.user?.role);
    next();
  },
  uploadImage.single('thumbnail'), 
  async (req, res) => {
    try {
      const courseObjectId = validateObjectId(req.params.courseId);
      const lectureObjectId = validateObjectId(req.params.lectureId);
      
      if (!courseObjectId || !lectureObjectId) {
        return res.status(400).json({ 
          success: false,
          message: 'Invalid course or lecture ID format' 
        });
      }

      const course = await Course.findById(courseObjectId);
      if (!course) {
        return res.status(404).json({ 
          success: false,
          message: 'Course not found' 
        });
      }

      // Check permissions
      const isInstructor = req.user.role === 'instructor' && 
                           course.instructorId.toString() === req.user._id.toString();
      const isAdmin = req.user.role === 'admin';

      if (!isInstructor && !isAdmin) {
        return res.status(403).json({ 
          success: false,
          message: 'You can only upload thumbnails for your own courses' 
        });
      }

      const lecture = await Lecture.findById(lectureObjectId);
      if (!lecture || lecture.courseId.toString() !== courseObjectId.toString()) {
        return res.status(404).json({ 
          success: false,
          message: 'Lecture not found' 
        });
      }

      if (!req.file) {
        return res.status(400).json({ 
          success: false,
          message: 'No image file uploaded' 
        });
      }

      // Delete old Cloudinary image if exists
      if (lecture.thumbnail && lecture.thumbnail.includes('cloudinary.com')) {
        try {
          const publicIdMatch = lecture.thumbnail.match(/\/([^\/]+)\.(jpg|jpeg|png|webp)$/);
          if (publicIdMatch) {
            const oldPublicId = `learnhub-course-thumbnails/${publicIdMatch[1]}`;
            await cloudinary.uploader.destroy(oldPublicId);
            console.log('🗑️ Deleted old lecture thumbnail');
          }
        } catch (err) {
          console.log('⚠️ Could not delete old thumbnail:', err.message);
        }
      }

      lecture.thumbnail = req.file.path;
      lecture.updatedAt = Date.now();
      await lecture.save();

      console.log('✅ Lecture thumbnail updated:', req.file.path, '\n');

      res.json({
        success: true,
        message: 'Lecture thumbnail uploaded successfully',
        thumbnailUrl: req.file.path,
        publicId: req.file.filename
      });
    } catch (error) {
      console.error('❌ Upload error:', error);
      
      if (req.file?.filename) {
        try {
          await cloudinary.uploader.destroy(req.file.filename);
        } catch (e) {}
      }
      
      res.status(500).json({ 
        success: false,
        message: 'Error uploading lecture thumbnail',
        error: error.message 
      });
    }
  }
);

// ============= COURSE ROUTES =============

// Get all courses
app.get('/api/courses', async (req, res) => {
  try {
    const { category, search } = req.query;
    
    let query = {};
    
    if (category && category !== 'all') {
      query.category = category;
    }
    
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { instructor: { $regex: search, $options: 'i' } }
      ];
    }

    const courses = await Course.find(query).sort({ createdAt: -1 });
    res.json({ courses });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching courses' });
  }
});

// Get single course
app.get('/api/courses/:id', async (req, res) => {
  try {
    const objectId = validateObjectId(req.params.id);
    
    if (!objectId) {
      return res.status(400).json({ message: 'Invalid course ID format' });
    }

    const course = await Course.findById(objectId);
    
    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }

    res.json({ course });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching course' });
  }
});

// ============= ADMIN STUDENT DETAIL & UNENROLL ROUTES =============

// Get single student with populated course details (admin)
app.get('/api/admin/students/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const studentObjectId = validateObjectId(req.params.id);
    
    if (!studentObjectId) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid student ID format' 
      });
    }
    
    const student = await User.findById(studentObjectId)
      .populate({
        path: 'enrolledCourses.courseId',
        select: 'title description instructor category level price image students lessons duration instructorId'
      })
      .select('name email userId enrolledCourses createdAt updatedAt');
    
    if (!student) {
      return res.status(404).json({ 
        success: false,
        message: 'Student not found' 
      });
    }

    // Format the response to ensure course data is properly structured
    const formattedStudent = {
      _id: student._id,
      name: student.name,
      email: student.email,
      userId: student.userId,
      createdAt: student.createdAt,
      updatedAt: student.updatedAt,
      enrolledCourses: student.enrolledCourses.map(ec => {
        const course = ec.courseId;
        return {
          courseId: course ? {
            _id: course._id,
            title: course.title || 'Course Title',
            description: course.description || '',
            instructor: course.instructor || 'Unknown',
            category: course.category || 'General',
            level: course.level || 'Beginner',
            price: course.price || 0,
            image: course.image || '',
            students: course.students || 0,
            lessons: course.lessons || 0,
            duration: course.duration || '',
            instructorId: course.instructorId
          } : null,
          progress: ec.progress || 0,
          enrolledAt: ec.enrolledAt,
          paymentId: ec.paymentId,
          orderId: ec.orderId,
          originalPrice: ec.originalPrice,
          amount: ec.amount,
          _id: ec._id
        };
      }).filter(ec => ec.courseId !== null)
    };
    
    console.log('✅ Admin fetched student details:', student.email);
    console.log('📚 Enrolled courses:', formattedStudent.enrolledCourses.length);
    
    res.json({ 
      success: true,
      student: formattedStudent
    });
  } catch (error) {
    console.error('❌ Error fetching student details:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error fetching student details',
      error: error.message 
    });
  }
});

// Unenroll student from course (admin)
app.delete('/api/admin/students/:studentId/unenroll/:courseId', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const studentObjectId = validateObjectId(req.params.studentId);
    const courseObjectId = validateObjectId(req.params.courseId);
    
    if (!studentObjectId || !courseObjectId) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid student or course ID format' 
      });
    }
    
    const student = await User.findById(studentObjectId);
    
    if (!student) {
      return res.status(404).json({ 
        success: false,
        message: 'Student not found' 
      });
    }
    
    const course = await Course.findById(courseObjectId);
    
    if (!course) {
      return res.status(404).json({ 
        success: false,
        message: 'Course not found' 
      });
    }
    
    // Check if student is enrolled
    const enrollmentIndex = student.enrolledCourses.findIndex(
      ec => ec.courseId.toString() === courseObjectId.toString()
    );
    
    if (enrollmentIndex === -1) {
      return res.status(404).json({ 
        success: false,
        message: 'Student is not enrolled in this course' 
      });
    }
    
    // Remove enrollment
    student.enrolledCourses.splice(enrollmentIndex, 1);
    await student.save();
    
    // Decrease course student count
    if (course.students > 0) {
      course.students -= 1;
      await course.save();
    }
    
    console.log('✅ Admin unenrolled student:', student.email, 'from course:', course.title);
    
    res.json({ 
      success: true,
      message: 'Student unenrolled successfully'
    });
  } catch (error) {
    console.error('❌ Error unenrolling student:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error unenrolling student',
      error: error.message 
    });
  }
});

// ============= LECTURE ROUTES =============

// Get lectures - UPDATED TO ALLOW ADMIN ACCESS
app.get('/api/courses/:id/lectures', authMiddleware, async (req, res) => {
  try {
    const objectId = validateObjectId(req.params.id);
    
    if (!objectId) {
      return res.status(400).json({ message: 'Invalid course ID format' });
    }

    const course = await Course.findById(objectId);
    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }

    const isInstructor = req.user.role === 'instructor' && 
                         course.instructorId.toString() === req.user._id.toString();
    
    const isEnrolled = req.user.role === 'student' && 
                       req.user.enrolledCourses.some(
                         ec => ec.courseId.toString() === objectId.toString()
                       );

    // ✅ ADD THIS LINE - Allow admin access
    const isAdmin = req.user.role === 'admin';

    // ✅ UPDATE THIS CONDITION - Include isAdmin
    if (!isInstructor && !isEnrolled && !isAdmin) {
      return res.status(403).json({ 
        message: 'Access denied. Enroll in course or be the instructor to view lectures.' 
      });
    }

    const lectures = await Lecture.find({ courseId: objectId }).sort({ order: 1, createdAt: 1 });
    
    res.json({ lectures });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching lectures' });
  }
});

// Add lecture - UPDATE THIS
app.post('/api/courses/:id/lectures', authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== 'instructor' && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Only instructors and admins can add lectures' });
    }
    
    const objectId = validateObjectId(req.params.id);
    
    if (!objectId) {
      return res.status(400).json({ message: 'Invalid course ID format' });
    }

    const course = await Course.findById(objectId);
    
    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }

    if (course.instructorId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'You can only add lectures to your own courses' });
    }

    const { title, description, videoUrl, duration, thumbnail } = req.body;

    if (!title || !videoUrl || !duration) {
      return res.status(400).json({ 
        message: 'Title, video URL, and duration are required' 
      });
    }

    console.log('🔍 Validating video URL:', videoUrl);
    const validation = isValidVideoUrl(videoUrl);
    if (!validation.valid) {
      console.log('❌ Validation failed:', validation.message);
      return res.status(400).json({ message: validation.message });
    }
    console.log('✅ Video URL validated successfully');

    const lectureCount = await Lecture.countDocuments({ courseId: objectId });

    const lecture = new Lecture({
      courseId: objectId,
      title,
      description: description || '',
      videoUrl,
      duration,
      thumbnail: thumbnail || null,
      order: lectureCount + 1
    });

    await lecture.save();

    // ✅ UPDATE: Calculate and update course duration
    const newDuration = await calculateCourseDuration(objectId);
    course.duration = newDuration;
    course.lessons = lectureCount + 1;
    await course.save();

    console.log('✅ Lecture added:', lecture.title);
    console.log('⏱️  Course duration updated to:', newDuration);

    res.status(201).json({ 
      message: 'Lecture added successfully',
      lecture,
      courseDuration: newDuration  // ✅ Return updated duration
    });
  } catch (error) {
    console.error('❌ Error adding lecture:', error);
    res.status(500).json({ message: 'Error adding lecture', error: error.message });
  }
});

// Update lecture - CHANGE THIS
app.put('/api/courses/:courseId/lectures/:lectureId', authMiddleware, async (req, res) => {
  try {
    const { courseId, lectureId } = req.params;
    
    const courseObjectId = validateObjectId(courseId);
    const lectureObjectId = validateObjectId(lectureId);
    
    if (!courseObjectId || !lectureObjectId) {
      return res.status(400).json({ message: 'Invalid ID format' });
    }

    const course = await Course.findById(courseObjectId);
    
    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }

    // ✅ ADD THIS - Allow admin OR instructor
    const isInstructor = req.user.role === 'instructor' && 
                         course.instructorId.toString() === req.user._id.toString();
    const isAdmin = req.user.role === 'admin';

    if (!isInstructor && !isAdmin) {
      return res.status(403).json({ message: 'You can only update lectures in your own courses' });
    }

    const lecture = await Lecture.findById(lectureObjectId);
    
    if (!lecture || lecture.courseId.toString() !== courseObjectId.toString()) {
      return res.status(404).json({ message: 'Lecture not found' });
    }

    const { title, description, videoUrl, duration, order, thumbnail } = req.body;
    
    if (videoUrl !== undefined) {
      console.log('🔍 Validating video URL for update:', videoUrl);
      const validation = isValidVideoUrl(videoUrl);
      if (!validation.valid) {
        console.log('❌ Validation failed:', validation.message);
        return res.status(400).json({ message: validation.message });
      }
      console.log('✅ Video URL validated successfully');
      lecture.videoUrl = videoUrl;
    }
    
    if (title !== undefined) lecture.title = title;
    if (description !== undefined) lecture.description = description;
    if (duration !== undefined) lecture.duration = duration;
    if (order !== undefined) lecture.order = order;
    if (thumbnail !== undefined) lecture.thumbnail = thumbnail;
    
    lecture.updatedAt = Date.now();
    await lecture.save();

    console.log('✅ Lecture updated:', lecture.title, 'by', req.user.role);

    res.json({ 
      message: 'Lecture updated successfully',
      lecture 
    });
  } catch (error) {
    console.error('❌ Error updating lecture:', error);
    res.status(500).json({ message: 'Error updating lecture', error: error.message });
  }
});

// Delete lecture - CHANGE THIS
app.delete('/api/courses/:courseId/lectures/:lectureId', authMiddleware, async (req, res) => {
  try {
    const { courseId, lectureId } = req.params;
    
    const courseObjectId = validateObjectId(courseId);
    const lectureObjectId = validateObjectId(lectureId);
    
    if (!courseObjectId || !lectureObjectId) {
      return res.status(400).json({ message: 'Invalid ID format' });
    }

    const course = await Course.findById(courseObjectId);
    
    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }

    // ✅ ADD THIS - Allow admin OR instructor
    const isInstructor = req.user.role === 'instructor' && 
                         course.instructorId.toString() === req.user._id.toString();
    const isAdmin = req.user.role === 'admin';

    if (!isInstructor && !isAdmin) {
      return res.status(403).json({ message: 'You can only delete lectures from your own courses' });
    }

    const lecture = await Lecture.findById(lectureObjectId);
    
    if (!lecture || lecture.courseId.toString() !== courseObjectId.toString()) {
      return res.status(404).json({ message: 'Lecture not found' });
    }

    await Lecture.findByIdAndDelete(lectureObjectId);

    const lectureCount = await Lecture.countDocuments({ courseId: courseObjectId });
    course.lessons = lectureCount;
    await course.save();

    console.log('✅ Lecture deleted by', req.user.role);

    res.json({ 
      message: 'Lecture deleted successfully'
    });
  } catch (error) {
    console.error('❌ Error deleting lecture:', error);
    res.status(500).json({ message: 'Error deleting lecture' });
  }
});

// ============= VIDEO UPLOAD ROUTE (FIXED) =============

app.post('/api/courses/:id/lectures/upload-video', 
  authMiddleware, 
  instructorMiddleware,
  (req, res, next) => {
    // Pre-upload logging
    console.log('\n📹 VIDEO UPLOAD REQUEST');
    console.log('Course ID:', req.params.id);
    console.log('User:', req.user?.email);
    console.log('Content-Type:', req.headers['content-type']);
    console.log('Content-Length:', req.headers['content-length']);
    next();
  },
  upload.single('video'), 
  async (req, res) => {
    try {
      console.log('📦 Multer processed file:', !!req.file);
      
      // Validate course ID
      const objectId = validateObjectId(req.params.id);
      if (!objectId) {
        return res.status(400).json({ 
          success: false,
          message: 'Invalid course ID format' 
        });
      }

      // Find course
      const course = await Course.findById(objectId);
      if (!course) {
        return res.status(404).json({ 
          success: false,
          message: 'Course not found' 
        });
      }

      // Verify ownership
      if (course.instructorId.toString() !== req.user._id.toString()) {
        return res.status(403).json({ 
          success: false,
          message: 'You can only upload videos to your own courses' 
        });
      }

      // Check if file exists
      if (!req.file) {
        console.error('❌ No file received');
        return res.status(400).json({ 
          success: false,
          message: 'No video file uploaded. Please select a video file.' 
        });
      }

      // Success response
      console.log('✅ Video uploaded successfully');
      console.log('📹 URL:', req.file.path);
      console.log('🆔 Public ID:', req.file.filename);
      console.log('📦 Size:', (req.file.size / (1024 * 1024)).toFixed(2), 'MB\n');

      res.status(200).json({
        success: true,
        message: 'Video uploaded successfully',
        videoUrl: req.file.path,
        publicId: req.file.filename,
        format: req.file.format,
        size: req.file.size,
        duration: req.file.duration // Cloudinary provides this
      });
    } catch (error) {
      console.error('❌ Upload error:', error);
      
      // Cleanup on failure
      if (req.file?.filename) {
        try {
          await cloudinary.uploader.destroy(req.file.filename, { 
            resource_type: 'video' 
          });
          console.log('🗑️ Cleaned up failed upload');
        } catch (cleanupError) {
          console.error('Cleanup error:', cleanupError);
        }
      }
      
      res.status(500).json({ 
        success: false,
        message: 'Error uploading video to cloud storage',
        error: error.message 
      });
    }
  }
);

// Delete video from Cloudinary
app.delete('/api/cloudinary/video/:publicId', authMiddleware, instructorMiddleware, async (req, res) => {
  try {
    const publicId = req.params.publicId;
    
    if (!publicId) {
      return res.status(400).json({ message: 'Public ID is required' });
    }

    const result = await cloudinary.uploader.destroy(publicId, { 
      resource_type: 'video' 
    });

    console.log('🗑️ Video deleted from Cloudinary:', publicId);

    res.json({
      success: true,
      message: 'Video deleted successfully',
      result
    });
  } catch (error) {
    console.error('❌ Error deleting video:', error);
    res.status(500).json({ 
      message: 'Error deleting video',
      error: error.message 
    });
  }
});

// Upload lecture thumbnail (admin/instructor)
app.post('/api/courses/:courseId/lectures/:lectureId/upload-thumbnail', 
  authMiddleware,
  (req, res, next) => {
    // Allow both instructors and admins
    if (req.user.role !== 'instructor' && req.user.role !== 'admin') {
      return res.status(403).json({ 
        success: false,
        message: 'Only instructors and admins can upload lecture thumbnails' 
      });
    }
    next();
  },
  (req, res, next) => {
    console.log('\n🖼️ LECTURE THUMBNAIL UPLOAD');
    console.log('Course ID:', req.params.courseId);
    console.log('Lecture ID:', req.params.lectureId);
    console.log('User:', req.user?.email);
    console.log('Role:', req.user?.role);
    next();
  },
  uploadImage.single('thumbnail'), 
  async (req, res) => {
    try {
      const courseObjectId = validateObjectId(req.params.courseId);
      const lectureObjectId = validateObjectId(req.params.lectureId);
      
      if (!courseObjectId || !lectureObjectId) {
        return res.status(400).json({ 
          success: false,
          message: 'Invalid course or lecture ID format' 
        });
      }

      const course = await Course.findById(courseObjectId);
      if (!course) {
        return res.status(404).json({ 
          success: false,
          message: 'Course not found' 
        });
      }

      // Check permissions
      const isInstructor = req.user.role === 'instructor' && 
                           course.instructorId.toString() === req.user._id.toString();
      const isAdmin = req.user.role === 'admin';

      if (!isInstructor && !isAdmin) {
        return res.status(403).json({ 
          success: false,
          message: 'You can only upload thumbnails for your own courses' 
        });
      }

      const lecture = await Lecture.findById(lectureObjectId);
      if (!lecture || lecture.courseId.toString() !== courseObjectId.toString()) {
        return res.status(404).json({ 
          success: false,
          message: 'Lecture not found' 
        });
      }

      if (!req.file) {
        return res.status(400).json({ 
          success: false,
          message: 'No image file uploaded' 
        });
      }

      // Delete old Cloudinary image if exists
      if (lecture.thumbnail && lecture.thumbnail.includes('cloudinary.com')) {
        try {
          const publicIdMatch = lecture.thumbnail.match(/\/([^\/]+)\.(jpg|jpeg|png|webp)$/);
          if (publicIdMatch) {
            const oldPublicId = `learnhub-course-thumbnails/${publicIdMatch[1]}`;
            await cloudinary.uploader.destroy(oldPublicId);
            console.log('🗑️ Deleted old lecture thumbnail');
          }
        } catch (err) {
          console.log('⚠️ Could not delete old thumbnail:', err.message);
        }
      }

      lecture.thumbnail = req.file.path;
      lecture.updatedAt = Date.now();
      await lecture.save();

      console.log('✅ Lecture thumbnail updated:', req.file.path, '\n');

      res.json({
        success: true,
        message: 'Lecture thumbnail uploaded successfully',
        thumbnailUrl: req.file.path,
        publicId: req.file.filename
      });
    } catch (error) {
      console.error('❌ Upload error:', error);
      
      if (req.file?.filename) {
        try {
          await cloudinary.uploader.destroy(req.file.filename);
        } catch (e) {}
      }
      
      res.status(500).json({ 
        success: false,
        message: 'Error uploading lecture thumbnail',
        error: error.message 
      });
    }
  }
);

// ============= STUDENT ROUTES =============

// Enroll in course
app.post('/api/courses/:id/enroll', authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== 'student') {
      return res.status(403).json({ message: 'Only students can enroll in courses' });
    }

    const objectId = validateObjectId(req.params.id);
    
    if (!objectId) {
      return res.status(400).json({ message: 'Invalid course ID format' });
    }

    const course = await Course.findById(objectId);

    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }

    const alreadyEnrolled = req.user.enrolledCourses.some(
      ec => ec.courseId.toString() === objectId.toString()
    );

    if (alreadyEnrolled) {
      return res.status(400).json({ message: 'Already enrolled in this course' });
    }

    req.user.enrolledCourses.push({
      courseId: objectId,
      progress: 0
    });

    course.students += 1;

    await req.user.save();
    await course.save();

    res.json({ 
      message: 'Successfully enrolled in course',
      course 
    });
  } catch (error) {
    res.status(500).json({ message: 'Error enrolling in course' });
  }
});

// Get enrolled courses
app.get('/api/user/enrolled-courses', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).populate('enrolledCourses.courseId');
    
    const enrolledCourses = user.enrolledCourses.map(ec => {
      if (ec.courseId) {
        return {
          ...ec.courseId.toObject(),
          progress: ec.progress,
          enrolledAt: ec.enrolledAt
        };
      }
      return null;
    }).filter(course => course !== null);

    res.json({ enrolledCourses });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching enrolled courses' });
  }
});

// Update progress
app.patch('/api/courses/:id/progress', authMiddleware, async (req, res) => {
  try {
    const { progress } = req.body;
    const objectId = validateObjectId(req.params.id);
    
    if (!objectId) {
      return res.status(400).json({ message: 'Invalid course ID format' });
    }

    const enrolledCourse = req.user.enrolledCourses.find(
      ec => ec.courseId.toString() === objectId.toString()
    );

    if (!enrolledCourse) {
      return res.status(404).json({ message: 'Not enrolled in this course' });
    }

    enrolledCourse.progress = progress;
    await req.user.save();

    res.json({ 
      message: 'Progress updated successfully',
      progress 
    });
  } catch (error) {
    res.status(500).json({ message: 'Error updating progress' });
  }
});

// Get enrolled students for a course (for instructors and admins)
app.get('/api/courses/:id/enrolled-students', authMiddleware, async (req, res) => {
  try {
    const objectId = validateObjectId(req.params.id);
    
    if (!objectId) {
      return res.status(400).json({ message: 'Invalid course ID format' });
    }

    const course = await Course.findById(objectId);
    
    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }

    // ✅ Allow both instructor (course owner) AND admin
    const isInstructor = req.user.role === 'instructor' && 
                         course.instructorId.toString() === req.user._id.toString();
    const isAdmin = req.user.role === 'admin';

    if (!isInstructor && !isAdmin) {
      return res.status(403).json({ 
        message: 'You can only view students for your own courses' 
      });
    }

    // Find all users who have this course in their enrolledCourses
    const enrolledStudents = await User.find({
      'enrolledCourses.courseId': objectId,
      role: 'student'
    }).select('name email userId enrolledCourses createdAt');

    // Format the response with enrollment details
    const students = enrolledStudents.map(student => {
      const enrollment = student.enrolledCourses.find(
        ec => ec.courseId.toString() === objectId.toString()
      );
      
      return {
        _id: student._id,
        name: student.name,
        email: student.email,
        userId: student.userId,
        enrolledAt: enrollment?.enrolledAt || student.createdAt,
        progress: enrollment?.progress || 0
      };
    });

    res.json({ 
      students,
      count: students.length
    });
  } catch (error) {
    console.error('Error fetching enrolled students:', error);
    res.status(500).json({ message: 'Error fetching enrolled students' });
  }
});

// ============= INSTRUCTOR ROUTES =============

// Get instructor courses
app.get('/api/instructor/courses', authMiddleware, instructorMiddleware, async (req, res) => {
  try {
    const courses = await Course.find({ instructorId: req.user._id }).sort({ createdAt: -1 });
    res.json({ courses });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching courses' });
  }
});

// Create course
app.post('/api/instructor/courses', authMiddleware, instructorMiddleware, async (req, res) => {
  try {
    const { title, description, category, level, price, duration, image, lessons, discount } = req.body;

    // ✅ FIX: Validate required fields
    if (!title || !description || !price) {
      return res.status(400).json({ 
        success: false,
        message: 'Title, description, and price are required' 
      });
    }

    // ✅ FIX: Validate price
    if (price <= 0) {
      return res.status(400).json({ 
        success: false,
        message: 'Price must be greater than 0' 
      });
    }

    const course = new Course({
      title: title.trim(),
      description: description.trim(),
      category: category || 'development',
      level: level || 'Beginner',
      price: parseFloat(price),
      duration: duration || '0h 0m', // ✅ Will be calculated from lectures
      image: image || 'https://images.unsplash.com/photo-1516321318423-f06f85e504b3?w=400&h=250&fit=crop',
      lessons: parseInt(lessons) || 0,
      discount: discount ? parseInt(discount) : 0,
      instructor: req.user.name,      // ✅ Instructor name
      instructorId: req.user._id,     // ✅ Instructor ID reference
      rating: 0,
      reviews: 0,
      students: 0,
      bestseller: false
    });

    await course.save();

    console.log('✅ Course created:', course.title, 'by', req.user.name);

    // ✅ FIX: Return proper response format
    res.status(201).json({ 
      success: true,
      message: 'Course created successfully',
      course: {
        _id: course._id,
        title: course.title,
        description: course.description,
        category: course.category,
        level: course.level,
        price: course.price,
        discount: course.discount,
        duration: course.duration,
        image: course.image,
        lessons: course.lessons,
        instructor: course.instructor,
        instructorId: course.instructorId,
        rating: course.rating,
        students: course.students,
        createdAt: course.createdAt
      }
    });
  } catch (error) {
    console.error('❌ Error creating course:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error creating course',
      error: error.message 
    });
  }
});

/// Update course (instructors and admins)
app.put('/api/instructor/courses/:id', authMiddleware, async (req, res) => {
  try {
    const objectId = validateObjectId(req.params.id);
    
    if (!objectId) {
      return res.status(400).json({ message: 'Invalid course ID format' });
    }
    
    const course = await Course.findById(objectId);

    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }

    const isInstructor = req.user.role === 'instructor' && 
                         course.instructorId.toString() === req.user._id.toString();
    const isAdmin = req.user.role === 'admin';

    if (!isInstructor && !isAdmin) {
      return res.status(403).json({ message: 'You can only update your own courses' });
    }

    const { title, description, category, level, price, duration, image, lessons, discount } = req.body;
    
    if (title !== undefined) course.title = title;
    if (description !== undefined) course.description = description;
    if (category !== undefined) course.category = category;
    if (level !== undefined) course.level = level;
    if (price !== undefined) course.price = price;
    if (discount !== undefined) course.discount = discount;
    if (duration !== undefined) course.duration = duration;
    if (image !== undefined) course.image = image;
    if (lessons !== undefined) course.lessons = lessons;
    
    course.updatedAt = Date.now();
    await course.save();

    res.json({ 
      message: 'Course updated successfully',
      course 
    });
  } catch (error) {
    res.status(500).json({ message: 'Error updating course' });
  }
});

// Delete course
app.delete('/api/instructor/courses/:id', authMiddleware, instructorMiddleware, async (req, res) => {
  try {
    const objectId = validateObjectId(req.params.id);
    
    if (!objectId) {
      return res.status(400).json({ message: 'Invalid course ID format' });
    }
    
    const course = await Course.findById(objectId);

    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }

    if (course.instructorId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'You can only delete your own courses' });
    }

    await Lecture.deleteMany({ courseId: objectId });
    await Course.findByIdAndDelete(objectId);

    res.json({ 
      message: 'Course deleted successfully'
    });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting course' });
  }
});

// ============= QUIZ ROUTES =============

// Create quiz (for instructors)
app.post('/api/courses/:id/quizzes', authMiddleware, instructorMiddleware, async (req, res) => {
  try {
    const courseObjectId = validateObjectId(req.params.id);
    
    if (!courseObjectId) {
      return res.status(400).json({ message: 'Invalid course ID format' });
    }

    const course = await Course.findById(courseObjectId);
    
    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }

    if (course.instructorId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'You can only create quizzes for your own courses' });
    }

    const { title, description, timerMinutes, allowRetake, questions } = req.body;

    if (!title || !timerMinutes || !questions || questions.length === 0) {
      return res.status(400).json({ 
        message: 'Title, timer, and at least one question are required' 
      });
    }

    // Validate questions
    for (let i = 0; i < questions.length; i++) {
      const q = questions[i];
      if (!q.questionText || !q.options || q.options.length < 2 || q.correctAnswer === undefined) {
        return res.status(400).json({ 
          message: `Question ${i + 1} is incomplete or invalid` 
        });
      }
    }

    // ✅ ADD THIS: Validate correctAnswer index is within filtered options range
    console.log('\n📋 VALIDATING QUIZ QUESTIONS:');
    for (let i = 0; i < questions.length; i++) {
      const q = questions[i];
      const filteredOptions = q.options.filter(opt => opt && opt.trim());
      
      console.log(`Question ${i + 1}:`);
      console.log('  Original options:', q.options.length);
      console.log('  After filter:', filteredOptions.length);
      console.log('  Correct answer index:', q.correctAnswer);
      
      if (q.correctAnswer >= filteredOptions.length) {
        return res.status(400).json({ 
          message: `Question ${i + 1}: Correct answer index (${q.correctAnswer}) is invalid after removing empty options. Please ensure all options are filled or adjust the correct answer.` 
        });
      }
    }
    console.log('✅ All questions validated\n');

  const quiz = new Quiz({
  title,
  description: description || '',
  courseId: courseObjectId,
  timerMinutes,
  allowRetake: allowRetake !== undefined ? allowRetake : true,
  questions: questions.map((q, index) => {
    // ✅ Filter out empty options
    const filteredOptions = q.options.filter(opt => opt && opt.trim());
    
    // ✅ Find the original correct answer text
    const correctAnswerText = q.options[q.correctAnswer];
    
    // ✅ Find its new index in filtered array
    const newCorrectIndex = filteredOptions.findIndex(opt => opt === correctAnswerText);
    
    return {
      questionText: q.questionText,
      options: filteredOptions,  // ✅ Store only filled options
      correctAnswer: newCorrectIndex >= 0 ? newCorrectIndex : 0,  // ✅ Adjusted index
      order: q.order !== undefined ? q.order : index
    };
  }),
  createdBy: req.user._id
});

    await quiz.save();

    console.log('✅ Quiz created:', quiz.title);

    res.status(201).json({ 
      message: 'Quiz created successfully',
      quiz 
    });
  } catch (error) {
    console.error('❌ Error creating quiz:', error);
    res.status(500).json({ message: 'Error creating quiz', error: error.message });
  }
});

// Get single quiz with all details (for instructors to review/edit)
app.get('/api/courses/:courseId/quizzes/:quizId', authMiddleware, async (req, res) => {
  try {
    const courseObjectId = validateObjectId(req.params.courseId);
    const quizObjectId = validateObjectId(req.params.quizId);
    
    if (!courseObjectId || !quizObjectId) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid ID format' 
      });
    }

    const course = await Course.findById(courseObjectId);
    if (!course) {
      return res.status(404).json({ 
        success: false,
        message: 'Course not found' 
      });
    }

    // Allow admin OR instructor
    const isInstructor = req.user.role === 'instructor' && 
                         course.instructorId.toString() === req.user._id.toString();
    const isAdmin = req.user.role === 'admin';

    if (!isInstructor && !isAdmin) {
      return res.status(403).json({ 
        success: false,
        message: 'You can only view quizzes for your own courses' 
      });
    }

    const quiz = await Quiz.findById(quizObjectId);
    
    if (!quiz || quiz.courseId.toString() !== courseObjectId.toString()) {
      return res.status(404).json({ 
        success: false,
        message: 'Quiz not found' 
      });
    }

    console.log('✅ Quiz fetched for review:', quiz.title, 'by', req.user.role);

    res.json({ 
      success: true,
      quiz 
    });
  } catch (error) {
    console.error('❌ Error fetching quiz:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error fetching quiz', 
      error: error.message 
    });
  }
});

// Get quizzes for a course - UPDATED TO ALLOW ADMIN ACCESS
app.get('/api/courses/:id/quizzes', authMiddleware, async (req, res) => {
  try {
    const courseObjectId = validateObjectId(req.params.id);
    
    if (!courseObjectId) {
      return res.status(400).json({ message: 'Invalid course ID format' });
    }

    const course = await Course.findById(courseObjectId);
    
    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }

    // ✅ For admin, show all quiz details including correct answers
    if (req.user.role === 'admin') {
      const quizzes = await Quiz.find({ courseId: courseObjectId })
        .sort({ createdAt: -1 });
      return res.json({ quizzes });
    }

    // For students/instructors, hide correct answers
    const quizzes = await Quiz.find({ courseId: courseObjectId })
      .select('-questions.correctAnswer')
      .sort({ createdAt: -1 });

    res.json({ quizzes });
  } catch (error) {
    console.error('❌ Error fetching quizzes:', error);
    res.status(500).json({ message: 'Error fetching quizzes' });
  }
});

// Get student's available quizzes (from enrolled courses)
app.get('/api/student/quizzes', authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== 'student') {
      return res.status(403).json({ message: 'Only students can access this endpoint' });
    }

    // Get enrolled course IDs
    const enrolledCourseIds = req.user.enrolledCourses.map(ec => ec.courseId);

    // Find quizzes for enrolled courses
    const quizzes = await Quiz.find({ courseId: { $in: enrolledCourseIds } })
      .populate('courseId', 'title')
      .sort({ createdAt: -1 });

    // Get student's quiz attempts
    const attempts = await QuizAttempt.find({ 
      studentId: req.user._id,
      quizId: { $in: quizzes.map(q => q._id) }
    }).sort({ submittedAt: -1 });

    // Format response with attempt info
    const quizzesWithAttempts = quizzes.map(quiz => {
      const lastAttempt = attempts.find(a => a.quizId.toString() === quiz._id.toString());
      
      return {
        _id: quiz._id,
        title: quiz.title,
        description: quiz.description,
        courseId: quiz.courseId._id,
        courseTitle: quiz.courseId.title,
        timerMinutes: quiz.timerMinutes,
        allowRetake: quiz.allowRetake,
        totalQuestions: quiz.questions.length,
        lastAttempt: lastAttempt ? {
          score: lastAttempt.score,
          percentage: lastAttempt.percentage,
          correctAnswers: lastAttempt.correctAnswers,
          submittedAt: lastAttempt.submittedAt
        } : null
      };
    });

    res.json({ quizzes: quizzesWithAttempts });
  } catch (error) {
    console.error('❌ Error fetching student quizzes:', error);
    res.status(500).json({ message: 'Error fetching quizzes' });
  }
});

// Get single quiz for taking (students)
app.get('/api/quizzes/:id/take', authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== 'student') {
      return res.status(403).json({ message: 'Only students can take quizzes' });
    }

    const quizObjectId = validateObjectId(req.params.id);
    
    if (!quizObjectId) {
      return res.status(400).json({ message: 'Invalid quiz ID format' });
    }

    const quiz = await Quiz.findById(quizObjectId)
      .select('-questions.correctAnswer') // Don't send correct answers
      .populate('courseId', 'title');

    if (!quiz) {
      return res.status(404).json({ message: 'Quiz not found' });
    }

    // Check if student is enrolled
    const isEnrolled = req.user.enrolledCourses.some(
      ec => ec.courseId.toString() === quiz.courseId._id.toString()
    );

    if (!isEnrolled) {
      return res.status(403).json({ message: 'You must be enrolled in the course to take this quiz' });
    }

    // Check previous attempts
    const previousAttempts = await QuizAttempt.find({
      quizId: quizObjectId,
      studentId: req.user._id
    }).sort({ submittedAt: -1 });

    if (previousAttempts.length > 0 && !quiz.allowRetake) {
      return res.status(403).json({ 
        message: 'Retake not allowed for this quiz',
        lastAttempt: previousAttempts[0]
      });
    }

    res.json({ 
      quiz,
      previousAttempts: previousAttempts.length
    });
  } catch (error) {
    console.error('❌ Error fetching quiz:', error);
    res.status(500).json({ message: 'Error fetching quiz' });
  }
});

// Submit quiz (students)
app.post('/api/quizzes/:id/submit', authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== 'student') {
      return res.status(403).json({ message: 'Only students can submit quizzes' });
    }

    const quizObjectId = validateObjectId(req.params.id);
    
    if (!quizObjectId) {
      return res.status(400).json({ message: 'Invalid quiz ID format' });
    }

    const { answers, timeSpent } = req.body;

    if (!answers || !Array.isArray(answers)) {
      return res.status(400).json({ message: 'Answers are required' });
    }

    // Get quiz with correct answers
    const quiz = await Quiz.findById(quizObjectId);

    if (!quiz) {
      return res.status(404).json({ message: 'Quiz not found' });
    }

    // Check if student is enrolled
    const isEnrolled = req.user.enrolledCourses.some(
      ec => ec.courseId.toString() === quiz.courseId.toString()
    );

    if (!isEnrolled) {
      return res.status(403).json({ message: 'You must be enrolled in the course to submit this quiz' });
    }

    // Check if retake is allowed
    const previousAttempt = await QuizAttempt.findOne({
      quizId: quizObjectId,
      studentId: req.user._id
    });

    if (previousAttempt && !quiz.allowRetake) {
      return res.status(403).json({ message: 'Retake not allowed for this quiz' });
    }

   // Calculate score with validation
let correctAnswers = 0;
const totalQuestions = quiz.questions.length;

console.log('\n🎯 SCORING QUIZ SUBMISSION');
console.log('Quiz:', quiz.title);
console.log('Total Questions:', totalQuestions);
console.log('Answers Received:', answers.length);

answers.forEach((answer, idx) => {
  const question = quiz.questions[answer.questionIndex];
  
  if (!question) {
    console.log(`⚠️  Answer ${idx + 1}: Question index ${answer.questionIndex} not found`);
    return;
  }
  
  console.log(`\n📝 Question ${answer.questionIndex + 1}:`);
  console.log('   Question Text:', question.questionText.substring(0, 60) + '...');
  console.log('   Options Count:', question.options.length);
  console.log('   Stored Correct Answer Index (0-based):', question.correctAnswer);
  console.log('   Student Selected Index (0-based):', answer.selectedAnswer);
  
  // ✅ ADD VALIDATION: Ensure indices are within bounds
  if (answer.selectedAnswer < 0 || answer.selectedAnswer >= question.options.length) {
    console.log('   ❌ INVALID - Student answer index out of bounds');
    return;
  }
  
  if (question.correctAnswer < 0 || question.correctAnswer >= question.options.length) {
    console.log('   ❌ INVALID - Correct answer index out of bounds');
    return;
  }
  
  console.log('   Correct Option:', question.options[question.correctAnswer]);
  console.log('   Student Selected:', question.options[answer.selectedAnswer]);
  
  // ✅ COMPARE AS NUMBERS (both should be 0-based)
  const correctIdx = parseInt(question.correctAnswer);
  const studentIdx = parseInt(answer.selectedAnswer);
  
  console.log('   Comparing:', correctIdx, '===', studentIdx);
  
  if (correctIdx === studentIdx) {
    correctAnswers++;
    console.log('   ✅ CORRECT');
  } else {
    console.log('   ❌ WRONG');
  }
});

console.log('\n📊 FINAL SCORE:');
console.log('   Correct:', correctAnswers);
console.log('   Total:', totalQuestions);

    const percentage = Math.round((correctAnswers / totalQuestions) * 100);

    // Save attempt
    const attempt = new QuizAttempt({
      quizId: quizObjectId,
      studentId: req.user._id,
      courseId: quiz.courseId,
      answers,
      score: correctAnswers,
      percentage,
      correctAnswers,
      totalQuestions,
      timeSpent: timeSpent || 0
    });

    await attempt.save();

    console.log('✅ Quiz submitted:', req.user.email, 'Score:', percentage + '%\n');

    res.json({
      message: 'Quiz submitted successfully',
      result: {
        score: correctAnswers,
        percentage,
        correctAnswers,
        totalQuestions,
        passed: percentage >= 60
      },
      attemptId: attempt._id
    });
  } catch (error) {
    console.error('❌ Error submitting quiz:', error);
    res.status(500).json({ message: 'Error submitting quiz', error: error.message });
  }
});

// Get quiz results with correct answers (after submission)
app.get('/api/quiz-attempts/:id/results', authMiddleware, async (req, res) => {
  try {
    const attemptObjectId = validateObjectId(req.params.id);
    
    if (!attemptObjectId) {
      return res.status(400).json({ message: 'Invalid attempt ID format' });
    }

    const attempt = await QuizAttempt.findById(attemptObjectId)
      .populate({
        path: 'quizId',
        select: 'title questions courseId'
      });

    if (!attempt) {
      return res.status(404).json({ message: 'Quiz attempt not found' });
    }

    // Verify ownership
    if (attempt.studentId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'You can only view your own quiz results' });
    }

    res.json({ 
      attempt,
      quiz: attempt.quizId
    });
  } catch (error) {
    console.error('❌ Error fetching quiz results:', error);
    res.status(500).json({ message: 'Error fetching quiz results' });
  }
});

// Get quiz with correct answers (for review after submission)
app.get('/api/quizzes/:id/review', authMiddleware, async (req, res) => {
  try {
    const quizObjectId = validateObjectId(req.params.id);
    
    if (!quizObjectId) {
      return res.status(400).json({ message: 'Invalid quiz ID format' });
    }

    const quiz = await Quiz.findById(quizObjectId);

    if (!quiz) {
      return res.status(404).json({ message: 'Quiz not found' });
    }

    // Verify student has attempted this quiz
    const attempt = await QuizAttempt.findOne({
      quizId: quizObjectId,
      studentId: req.user._id
    });

    if (!attempt) {
      return res.status(403).json({ 
        message: 'You must complete the quiz first to review answers' 
      });
    }

    // Return quiz with correct answers for review
    res.json({ 
      quiz: {
        _id: quiz._id,
        title: quiz.title,
        questions: quiz.questions.map(q => ({
          questionText: q.questionText,
          options: q.options,
          correctAnswer: q.correctAnswer // Now we include the correct answer
        }))
      }
    });
  } catch (error) {
    console.error('❌ Error fetching quiz for review:', error);
    res.status(500).json({ message: 'Error fetching quiz' });
  }
});

// Update quiz (instructors and admins)
app.put('/api/courses/:courseId/quizzes/:quizId', authMiddleware, async (req, res) => {
  try {
    const courseObjectId = validateObjectId(req.params.courseId);
    const quizObjectId = validateObjectId(req.params.quizId);
    
    if (!courseObjectId || !quizObjectId) {
      return res.status(400).json({ message: 'Invalid ID format' });
    }

    const course = await Course.findById(courseObjectId);
    
    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }

    // ✅ Allow admin OR instructor
    const isInstructor = req.user.role === 'instructor' && 
                         course.instructorId.toString() === req.user._id.toString();
    const isAdmin = req.user.role === 'admin';

    if (!isInstructor && !isAdmin) {
      return res.status(403).json({ message: 'You can only update quizzes in your own courses' });
    }

    const quiz = await Quiz.findById(quizObjectId);
    
    if (!quiz || quiz.courseId.toString() !== courseObjectId.toString()) {
      return res.status(404).json({ message: 'Quiz not found' });
    }

    const { title, description, timerMinutes, allowRetake, questions } = req.body;
    
    if (title !== undefined) quiz.title = title;
    if (description !== undefined) quiz.description = description;
    if (timerMinutes !== undefined) quiz.timerMinutes = timerMinutes;
    if (allowRetake !== undefined) quiz.allowRetake = allowRetake;
if (questions !== undefined) {
  // ✅ ADD VALIDATION HERE
  console.log('\n📋 VALIDATING QUIZ QUESTIONS FOR UPDATE:');
  for (let i = 0; i < questions.length; i++) {
    const q = questions[i];
    const filteredOptions = q.options.filter(opt => opt && opt.trim());
    
    console.log(`Question ${i + 1}:`);
    console.log('  Original options:', q.options.length);
    console.log('  After filter:', filteredOptions.length);
    console.log('  Correct answer index:', q.correctAnswer);
    
    if (q.correctAnswer >= filteredOptions.length) {
      return res.status(400).json({ 
        message: `Question ${i + 1}: Correct answer index (${q.correctAnswer}) is invalid after removing empty options.`
      });
    }
  }
  console.log('✅ All questions validated\n');

  quiz.questions = questions.map((q, index) => {
    // ✅ ADD THIS FILTERING LOGIC
    const filteredOptions = q.options.filter(opt => opt && opt.trim());
    const correctAnswerText = q.options[q.correctAnswer];
    const newCorrectIndex = filteredOptions.findIndex(opt => opt === correctAnswerText);
    
    return {
      questionText: q.questionText,
      options: filteredOptions,  // ✅ Store only filled options
      correctAnswer: newCorrectIndex >= 0 ? newCorrectIndex : 0,  // ✅ Adjusted index
      order: q.order !== undefined ? q.order : index
    };
  });
}
    
    quiz.updatedAt = Date.now();
    await quiz.save();

    console.log('✅ Quiz updated:', quiz.title, 'by', req.user.role);

    res.json({ 
      message: 'Quiz updated successfully',
      quiz 
    });
  } catch (error) {
    console.error('❌ Error updating quiz:', error);
    res.status(500).json({ message: 'Error updating quiz', error: error.message });
  }
});

// Delete quiz - CHANGE THIS
app.delete('/api/courses/:courseId/quizzes/:quizId', authMiddleware, async (req, res) => {
  try {
    const courseObjectId = validateObjectId(req.params.courseId);
    const quizObjectId = validateObjectId(req.params.quizId);
    
    if (!courseObjectId || !quizObjectId) {
      return res.status(400).json({ message: 'Invalid ID format' });
    }

    const course = await Course.findById(courseObjectId);
    
    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }

    // ✅ ADD THIS - Allow admin OR instructor
    const isInstructor = req.user.role === 'instructor' && 
                         course.instructorId.toString() === req.user._id.toString();
    const isAdmin = req.user.role === 'admin';

    if (!isInstructor && !isAdmin) {
      return res.status(403).json({ message: 'You can only delete quizzes from your own courses' });
    }

    const quiz = await Quiz.findById(quizObjectId);
    
    if (!quiz || quiz.courseId.toString() !== courseObjectId.toString()) {
      return res.status(404).json({ message: 'Quiz not found' });
    }

    // Delete all attempts for this quiz
    await QuizAttempt.deleteMany({ quizId: quizObjectId });
    
    // Delete quiz
    await Quiz.findByIdAndDelete(quizObjectId);

    console.log('✅ Quiz deleted:', quiz.title, 'by', req.user.role);

    res.json({ 
      message: 'Quiz deleted successfully'
    });
  } catch (error) {
    console.error('❌ Error deleting quiz:', error);
    res.status(500).json({ message: 'Error deleting quiz' });
  }
});

// ============= PAYMENT ROUTES (RAZORPAY) =============

// Create Razorpay Order
app.post('/api/payment/create-order', authMiddleware, async (req, res) => {
  try {
    const { courseId, amount, originalPrice } = req.body; // ✅ ADD originalPrice

    if (!courseId || !amount) {
      return res.status(400).json({ 
        success: false, 
        message: 'Course ID and amount are required' 
      });
    }

    // Verify course exists
    const courseObjectId = validateObjectId(courseId);
    if (!courseObjectId) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid course ID format' 
      });
    }

    const course = await Course.findById(courseObjectId);
    if (!course) {
      return res.status(404).json({ 
        success: false, 
        message: 'Course not found' 
      });
    }

    // Check if already enrolled
    const alreadyEnrolled = req.user.enrolledCourses.some(
      ec => ec.courseId.toString() === courseObjectId.toString()
    );

    if (alreadyEnrolled) {
      return res.status(400).json({ 
        success: false, 
        message: 'Already enrolled in this course' 
      });
    }

   // Create Razorpay order
const options = {
  amount: Math.round(amount * 100), // Convert to paise (smallest currency unit)
  currency: 'INR',
  receipt: `rcpt_${Date.now().toString().slice(-10)}`, // ✅ Max 40 chars
  notes: {
    courseId: courseId,
    userId: req.user._id.toString(),
    courseName: course.title,
    originalPrice: originalPrice || course.price // ✅ Store original price in notes
  }
};

    const order = await razorpay.orders.create(options);

    console.log('✅ Razorpay order created:', order.id);
    console.log('💰 Original Price:', originalPrice || course.price); // ✅ Log for debugging

    res.json({
      success: true,
      orderId: order.id,
      amount: order.amount,
      currency: order.currency,
      courseId: courseId
    });
  } catch (error) {
    console.error('❌ Error creating Razorpay order:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to create payment order', 
      error: error.message 
    });
  }
});

// Verify Payment and Enroll
app.post('/api/payment/verify', authMiddleware, async (req, res) => {
  try {
    const { 
      razorpay_order_id, 
      razorpay_payment_id, 
      razorpay_signature,
      courseId,
      originalPrice // ✅ ADD originalPrice
    } = req.body;

    console.log('\n💳 VERIFYING PAYMENT');
    console.log('Order ID:', razorpay_order_id);
    console.log('Payment ID:', razorpay_payment_id);
    console.log('Course ID:', courseId);
    console.log('💰 Original Price:', originalPrice); // ✅ Log for debugging

    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature || !courseId) {
      return res.status(400).json({ 
        success: false, 
        message: 'Missing payment verification details' 
      });
    }

    // Verify signature
    const body = razorpay_order_id + '|' + razorpay_payment_id;
    const expectedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET || 'V2tdfQAgjgYqrggJrjCQQguZ')
      .update(body.toString())
      .digest('hex');

    const isAuthentic = expectedSignature === razorpay_signature;

    if (!isAuthentic) {
      console.log('❌ Payment verification failed - Invalid signature');
      return res.status(400).json({ 
        success: false, 
        message: 'Payment verification failed - Invalid signature' 
      });
    }

    console.log('✅ Payment signature verified');

    // Payment is successful, enroll user in course
    const courseObjectId = validateObjectId(courseId);
    if (!courseObjectId) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid course ID format' 
      });
    }

    const course = await Course.findById(courseObjectId);
    if (!course) {
      return res.status(404).json({ 
        success: false, 
        message: 'Course not found' 
      });
    }

    // Check if already enrolled
    const alreadyEnrolled = req.user.enrolledCourses.some(
      ec => ec.courseId.toString() === courseObjectId.toString()
    );

    if (alreadyEnrolled) {
      console.log('⚠️  User already enrolled in course');
      return res.status(400).json({ 
        success: false, 
        message: 'Already enrolled in this course' 
      });
    }

    // ✅ Calculate pricing for enrollment record
    const storedOriginalPrice = originalPrice || course.price;
    const discount = Math.round(storedOriginalPrice * 0.3);
    const amountPaid = storedOriginalPrice - discount;

    // Add to enrolled courses with originalPrice
    req.user.enrolledCourses.push({
      courseId: courseObjectId,
      enrolledAt: new Date(),
      paymentId: razorpay_payment_id,
      orderId: razorpay_order_id,
      originalPrice: storedOriginalPrice, // ✅ STORE ORIGINAL PRICE
      amount: amountPaid, // ✅ STORE AMOUNT PAID
      progress: 0
    });
    await req.user.save();

    // Increment course student count
    course.students = (course.students || 0) + 1;
    await course.save();

    console.log('✅ User enrolled successfully:', req.user.email);
    console.log('📚 Course:', course.title);
    console.log('💰 Pricing - Original:', storedOriginalPrice, 'Discount:', discount, 'Paid:', amountPaid);
    console.log('👥 Total students:', course.students, '\n');

    res.json({
      success: true,
      message: 'Payment verified and enrollment successful',
      enrolledCourse: {
        courseId: course._id,
        title: course.title,
        enrolledAt: new Date()
      }
    });
  } catch (error) {
    console.error('❌ Error verifying payment:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Payment verification error', 
      error: error.message 
    });
  }
});

// Get Payment History
app.get('/api/payment/history', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .populate('enrolledCourses.courseId', 'title instructor image price');
    
    const payments = user.enrolledCourses
      .filter(ec => ec.paymentId) // Only paid courses
      .map(ec => ({
        courseId: ec.courseId._id,
        courseTitle: ec.courseId.title,
        courseImage: ec.courseId.image,
        instructor: ec.courseId.instructor,
        price: ec.originalPrice || ec.courseId.price, // ✅ Use stored originalPrice
        amountPaid: ec.amount, // ✅ Show amount actually paid
        paymentId: ec.paymentId,
        orderId: ec.orderId,
        enrolledAt: ec.enrolledAt,
        progress: ec.progress
      }));

    res.json({
      success: true,
      payments,
      totalSpent: payments.reduce((sum, p) => sum + (p.amountPaid || 0), 0) // ✅ Sum amountPaid, not price
    });
  } catch (error) {
    console.error('❌ Error fetching payment history:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch payment history', 
      error: error.message 
    });
  }
});

// ==================== PDF RECEIPT ROUTE (FIXED PRICING LOGIC) ==================== //
const PDFDocument = require('pdfkit');

app.get('/api/payment/receipt/:orderId', authMiddleware, async (req, res) => {
  try {
    const { orderId } = req.params;
    console.log('\n📄 GENERATING RECEIPT');
    console.log('Order ID:', orderId);
    console.log('User:', req.user.email);

    // Fetch user and their enrolled courses
    const user = await User.findById(req.user._id)
      .populate('enrolledCourses.courseId', 'title instructor price image category');

    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    // Find enrollment
    const enrollment = user.enrolledCourses.find(ec => ec.orderId === orderId);
    if (!enrollment)
      return res.status(404).json({ success: false, message: 'Receipt not found for this order' });

    const course = enrollment.courseId || {};
    
    // ✅ FIX: Use the actual course price as original price (set by instructor)
    const originalPrice = Number(course.price ?? 0);
    // Calculate discount (30% of original)
    const discount = Math.round(originalPrice * 0.3);
    // Calculate paid amount (original - discount)
    const paidPrice = originalPrice - discount;

    console.log('💰 Pricing Breakdown:');
    console.log('   Original Price:', originalPrice);
    console.log('   Discount (30%):', discount);
    console.log('   Amount Paid:', paidPrice);

    // Format with "Rs"
    const fmt = new Intl.NumberFormat('en-IN', { maximumFractionDigits: 0 });
    const fmtRupee = v => `Rs ${fmt.format(v)}`;

    // Format date/time
    const enrolledAt = new Date(enrollment.enrolledAt);
    const formattedDate = enrolledAt.toLocaleDateString('en-IN', {
      day: '2-digit', month: 'short', year: 'numeric', timeZone: 'Asia/Kolkata'
    });
    const formattedTime = enrolledAt.toLocaleTimeString('en-IN', {
      hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true, timeZone: 'Asia/Kolkata'
    });

    const now = new Date();
    const generatedIST = now.toLocaleString('en-IN', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: true, timeZone: 'Asia/Kolkata'
    });

    // Create PDF
    const doc = new PDFDocument({ size: 'A4', margins: { top: 60, bottom: 60, left: 55, right: 55 } });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=LearnHub-Receipt-${orderId}.pdf`);
    doc.pipe(res);

    // Header
    doc.fontSize(22).fillColor('#4f46e5').font('Helvetica-Bold').text('LearnHub', 50, 50);
    doc.fontSize(9).fillColor('#6b7280').font('Helvetica').text('Learning Platform', 50, 74);
    doc.fontSize(18).fillColor('#111').font('Helvetica-Bold').text('PAYMENT RECEIPT', 0, 50, { align: 'right' });

    doc.moveTo(50, 105).lineTo(545, 105).strokeColor('#E8E8FF').lineWidth(1.5).stroke();

    // Receipt Details
    doc.fontSize(12).fillColor('#111').font('Helvetica-Bold').text('Receipt Details', 50, 120);
    let startY = 140;
    const lineH = 18;

    doc.fontSize(10).fillColor('#4b5563').font('Helvetica').text('Receipt Number:', 50, startY);
    doc.font('Helvetica-Bold').fillColor('#000').text(orderId, 180, startY);

    doc.font('Helvetica').fillColor('#4b5563').text('Date & Time:', 50, startY + lineH);
    doc.font('Helvetica-Bold').fillColor('#000').text(`${formattedDate} at ${formattedTime} IST`, 180, startY + lineH);

    doc.font('Helvetica').fillColor('#4b5563').text('Payment ID:', 50, startY + lineH * 2);
    doc.font('Helvetica-Bold').fillColor('#000').text(enrollment.paymentId || 'N/A', 180, startY + lineH * 2);

    doc.font('Helvetica').fillColor('#4b5563').text('Payment Status:', 50, startY + lineH * 3);
    doc.font('Helvetica-Bold').fillColor('#10b981').text('PAID', 180, startY + lineH * 3);

    // Customer details box
    const custTop = startY + lineH * 5 + 20;
    doc.fontSize(12).fillColor('#4f46e5').font('Helvetica-Bold').text('Customer Details', 50, custTop - 20);
    doc.rect(50, custTop, 504, 70).fillAndStroke('#f8fafc', '#e6eaf0');
    doc.fontSize(10).fillColor('#111').font('Helvetica-Bold').text(`Name: `, 60, custTop + 10);
    doc.font('Helvetica').fontSize(10).fillColor('#111').text(user.name || 'N/A', 120, custTop + 10);
    doc.font('Helvetica').fontSize(10).fillColor('#111').text(`Email: ${user.email}`, 60, custTop + 30);
    doc.font('Helvetica-Bold').fontSize(10).fillColor('#111').text(`Student ID: ${user._id.toString().slice(-8).toUpperCase()}`, 60, custTop + 50);

    // Course details box
    const courseTop = custTop + 100;
    doc.fontSize(12).fillColor('#4f46e5').font('Helvetica-Bold').text('Course Details', 50, courseTop - 20);
    doc.rect(50, courseTop, 504, 95).fillAndStroke('#f0fff6', '#cfeedb');
    doc.fontSize(11).fillColor('#111').font('Helvetica-Bold').text(course.title || 'N/A', 60, courseTop + 10);
    doc.fontSize(10).fillColor('#6b7280').font('Helvetica').text('Instructor:', 60, courseTop + 38);
    doc.font('Helvetica-Bold').fillColor('#111').text(course.instructor || 'N/A', 130, courseTop + 38);
    doc.font('Helvetica').fillColor('#6b7280').text('Category:', 60, courseTop + 56);
    doc.font('Helvetica-Bold').fillColor('#111').text(course.category || 'General', 130, courseTop + 56);
    doc.font('Helvetica').fillColor('#6b7280').text('Access:', 60, courseTop + 72);
    doc.font('Helvetica-Bold').fillColor('#10b981').text('Lifetime Access Granted', 130, courseTop + 72);

    // Payment summary box
    const summaryTop = courseTop + 130;
    doc.fontSize(12).fillColor('#4f46e5').font('Helvetica-Bold').text('Payment Summary', 50, summaryTop - 20);
    doc.rect(50, summaryTop, 504, 100).fillAndStroke('#f7fff8', '#d9f0df');

    let y = summaryTop + 18;
    const labelX = 60;
    const valueX = 190;

    doc.fontSize(10).fillColor('#111').font('Helvetica-Bold').text('Original Price:', labelX, y);
    doc.font('Helvetica-Bold').fillColor('#10b981').text(fmtRupee(originalPrice), valueX, y);

    y += 22;
    doc.font('Helvetica-Bold').fillColor('#111').text('Discount (30%):', labelX, y);
    doc.font('Helvetica-Bold').fillColor('#10b981').text(`- ${fmtRupee(discount)}`, valueX, y);

    y += 16;
    doc.moveTo(60, y + 5).lineTo(532, y + 5).strokeColor('#e9f6ee').lineWidth(1).stroke();

    y += 18;
    doc.fontSize(11).fillColor('#111').font('Helvetica-Bold').text('Amount Paid:', labelX, y);
    doc.font('Helvetica-Bold').fillColor('#10b981').text(fmtRupee(paidPrice), valueX, y);

    // Footer
    const footerTop = y + 70;
    doc.moveTo(50, footerTop).lineTo(545, footerTop).strokeColor('#efefef').lineWidth(1).stroke();

    doc.fontSize(9).fillColor('#6b7280').font('Helvetica').text('Thank you for choosing LearnHub!', 0, footerTop + 12, { align: 'center' });
    doc.fontSize(8).fillColor('#9ca3af').text('This is a computer-generated receipt and does not require a signature.', 0, footerTop + 26, { align: 'center' });
    doc.fontSize(8).fillColor('#9ca3af').text('For any queries, contact support@learnhub.com', 0, footerTop + 38, { align: 'center' });
    doc.fontSize(7).fillColor('#cfcfcf').text(`Generated on ${generatedIST} (IST)`, 0, footerTop + 52, { align: 'center' });

    // Finalize
    doc.end();

    console.log('✅ Receipt generated successfully');
    console.log('📅 Enrollment (IST):', `${formattedDate} at ${formattedTime}`);
    console.log('🕒 PDF Generated (IST):', generatedIST, '\n');
  } catch (err) {
    console.error('❌ Error generating receipt:', err);
    res.status(500).json({ success: false, message: 'Failed to generate receipt', error: err.message });
  }
});



// ============= UTILITY ROUTES =============

// Seed courses
app.post('/api/admin/seed-courses', async (req, res) => {
  try {
    const sampleCourses = [
      {
        title: 'Complete Web Development Bootcamp',
        instructor: 'Priya Sharma',
        category: 'development',
        rating: 4.8,
        reviews: 2430,
        students: 8500,
        duration: '52 hours',
        price: 499,
        image: 'https://images.unsplash.com/photo-1498050108023-c5249f4df085?w=400&h=250&fit=crop',
        description: 'Master web development from scratch with HTML, CSS, JavaScript, React, Node.js, and more.',
        lessons: 245,
        level: 'Beginner',
        bestseller: true
      },
      {
        title: 'UI/UX Design Masterclass',
        instructor: 'Rahul Verma',
        category: 'design',
        rating: 4.7,
        reviews: 1890,
        students: 6200,
        duration: '38 hours',
        price: 449,
        image: 'https://images.unsplash.com/photo-1561070791-2526d30994b5?w=400&h=250&fit=crop',
        description: 'Learn professional UI/UX design principles, Figma, user research, and design thinking.',
        lessons: 180,
        level: 'Intermediate',
        bestseller: true
      },
      {
        title: 'Python for Data Science',
        instructor: 'Dr. Amit Kumar',
        category: 'data-science',
        rating: 4.9,
        reviews: 3543,
        students: 12500,
        duration: '45 hours',
        price: 549,
        image: 'https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?w=400&h=250&fit=crop',
        description: 'Comprehensive Python course covering data analysis, visualization, and machine learning.',
        lessons: 210,
        level: 'Beginner'
      }
    ];

    await Course.insertMany(sampleCourses);
    res.json({ message: 'Sample courses created successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error seeding courses' });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'Server running', 
    timestamp: new Date(),
    mongodb: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
    emailMode: shouldUseConsoleOTP ? 'console' : 'brevo-api'
  });
});

// 🌱 Create default admin (for first-time setup)
app.get('/api/admin/seed', async (req, res) => {
  try {
    const email = 'admin@learnhub.com';
    const existing = await User.findOne({ email });

    if (existing) {
      return res.json({ message: 'Admin already exists', email });
    }

    const hashed = await bcrypt.hash('Admin@123', 10);
    const admin = new User({
      name: 'Super Admin',
      email,
      password: hashed,
      role: 'admin'
    });

    await admin.save();
    res.json({ message: '✅ Admin created successfully', email, password: 'Admin@123' });
  } catch (error) {
    console.error('Error creating admin:', error);
    res.status(500).json({ message: 'Failed to create admin' });
  }
});


// Start server
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log('\n' + '='.repeat(60));
  console.log('🚀 LEARNHUB SERVER STARTED');
  console.log('='.repeat(60));
  console.log(`📍 Port: ${PORT}`);
  console.log(`🌐 API: http://localhost:${PORT}`);
  console.log(`📚 Features: Courses, Lectures, Quizzes, OTP Auth`);
  console.log(`📧 Email: ${shouldUseConsoleOTP ? '🧪 Console Mode' : '✅ Brevo API'}`);
  if (!shouldUseConsoleOTP) {
    console.log(`✉️  Sender: ${process.env.BREVO_SENDER_NAME || 'LearnHub'} <${process.env.BREVO_SENDER_EMAIL}>`);
  } else {
    console.log(`💡 Enable email: Add BREVO_API_KEY to .env`);
  }
  console.log('='.repeat(60) + '\n');
});
