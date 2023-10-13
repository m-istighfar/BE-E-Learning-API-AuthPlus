const crypto = require("crypto");
const nodemailer = require("nodemailer");
const User = require("../models/user");
const bcrypt = require("bcrypt");

const requestPasswordReset = async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    return res
      .status(400)
      .json({ error: "No account with that email address exists." });
  }

  const resetToken = crypto.randomBytes(20).toString("hex");
  const resetPasswordExpires = Date.now() + 3600000; // 1 hour

  user.resetPasswordToken = resetToken;
  user.resetPasswordExpires = resetPasswordExpires;
  await user.save();

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: "daiqijb105@gmail.com",
      pass: "elrvbtfvypzvosdr",
    },
  });

  const mailOptions = {
    from: "daiqijb105@gmail.com",
    to: user.email,
    subject: "Password Reset Request",
    text: `Please click on the following link, or paste this into your browser to complete the process within one hour:\n\nhttp://localhost:3000/reset-password/${resetToken}\n\n If you did not request this, please ignore this email and your password will remain unchanged.\n`,
  };

  transporter.sendMail(mailOptions, (err) => {
    if (err) {
      console.error("Mail send error:", err);
      return res.status(500).json({
        error: "Internal error occurred, failed to send reset email.",
      });
    }
    res.status(200).json({ message: "Password reset email sent." });
  });
};

const resetPassword = async (req, res) => {
  const { resetToken } = req.params;
  const { newPassword } = req.body;

  console.log("Token from URL:", resetToken);

  const user = await User.findOne({
    resetPasswordToken: resetToken,
    resetPasswordExpires: { $gt: Date.now() },
  });

  if (!user) {
    return res
      .status(400)
      .json({ error: "Password reset token is invalid or has expired." });
  }

  try {
    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Assign the hashed password to the user's password field
    user.password = hashedPassword;

    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.status(200).json({ message: "Password successfully reset." });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
};

module.exports = {
  requestPasswordReset,
  resetPassword,
};
