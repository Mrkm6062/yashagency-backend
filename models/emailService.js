import nodemailer from 'nodemailer';

// Configure your email transporter
// IMPORTANT: Use environment variables for credentials in production
const transporter = nodemailer.createTransport({
  service: 'Gmail', // Or your email provider
  auth: {
    user: process.env.EMAIL_USER, // Your email address
    pass: process.env.EMAIL_PASS  // Your email password or app-specific password
  }
});

const sendOTPEmail = async (to, otp) => {
  const mailOptions = {
    from: `"Yash Agency" <${process.env.EMAIL_USER}>`,
    to: to,
    subject: 'Your OTP for Yash Agency',
    text: `
Welcome to Yash Agency!

Your One-Time Password (OTP) for account verification is: ${otp}

This OTP is valid for 10 minutes.
    `
  };
  await transporter.sendMail(mailOptions);
};

export { sendOTPEmail };