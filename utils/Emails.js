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
//       from: "Watch Nest" || process.env.EMAIL,
//       // from: "Watch Nest" || process.env.EMAIL,
//       to: receiverEmail,
//       subject: subject,
//       html: body,
//     });

//     console.log(`Email sent: ${info.messageId}`);
//     return { success: true, message: `Email sent to ${receiverEmail}` };
//   } catch (error) {
//     // Log the error
//     console.error(`Error sending email: ${error.message}`);

//     // Return a failure message
//     return { success: false, error: error.message };
//   }
// };

// Import necessary modules
const nodemailer = require("nodemailer");

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
      from: '"📬 Watch Nest" <no-reply@watchnest.com>',
      to: receiverEmail,
      subject: subject,
      html: body,
    });

    // Log or use the info object for debugging
    // console.log("Email sent info:", info);

    return {
      success: true,
      message: `🎉 Email sent to ${receiverEmail}`,
      info: info,
    };
  } catch (error) {
    return { success: false, error: error.message };
  }
};
