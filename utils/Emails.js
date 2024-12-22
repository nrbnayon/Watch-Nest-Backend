// Import necessary modules
const nodemailer = require("nodemailer");
const User = require("../models/User"); // Replace with actual path to User model
const Otp = require("../models/Otp"); // Replace with actual path to Otp model
const { generateOTP } = require("../utils/otpUtils"); // Replace with actual OTP generation utility
const authLimiter = require("../middlewares/authLimiter"); // Replace with actual middleware path

// Nodemailer transporter configuration
const transporter = nodemailer.createTransport({
  service: "gmail",
  host: "smtp.gmail.com",
  secure: true,
  auth: {
    user: process.env.EMAIL,
    pass: process.env.PASSWORD,
  },
});

// Function to send an email
exports.sendMail = async (receiverEmail, subject, body) => {
  try {
    if (!process.env.EMAIL || !process.env.PASSWORD) {
      throw new Error("Email credentials are missing.");
    }

    const info = await transporter.sendMail({
      from: "\uD83D\uDC8C Watch Nest" || process.env.EMAIL,
      to: receiverEmail,
      subject: subject,
      html: body,
    });

    return {
      success: true,
      message: `\uD83C\uDF89 Email sent to ${receiverEmail}`,
    };
  } catch (error) {
    return { success: false, error: error.message };
  }
};

// const nodemailer = require("nodemailer");

// // Create a transporter object using Gmail as the service
// const transporter = nodemailer.createTransport({
//   service: "gmail",
//   host: "smtp.gmail.com",
//   secure: true,
//   auth: {
//     user: process.env.EMAIL,
//     pass: process.env.PASSWORD,
//   },
// });

// // Function to send an email
// exports.sendMail = async (receiverEmail, subject, body) => {
//   try {
//     // Ensure email and password are available
//     if (!process.env.EMAIL || !process.env.PASSWORD) {
//       throw new Error("Email credentials are missing.");
//     }

//     // Send the email using the transport object
//     const info = await transporter.sendMail({
//       from: "Watch Nest",
//       // from: "Watch Nest" || process.env.EMAIL,
//       to: receiverEmail,
//       subject: subject,
//       html: body,
//     });

//     // console.log(`Email sent: ${info.messageId}`);
//     return { success: true, message: `Email sent to ${receiverEmail}` };
//   } catch (error) {
//     // Log the error
//     // console.error(`Error sending email: ${error.message}`);

//     // Return a failure message
//     return { success: false, error: error.message };
//   }
// };
