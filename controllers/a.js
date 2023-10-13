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