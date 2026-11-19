const nodemailer = require('nodemailer');

const SMTP_HOST = process.env.SMTP_HOST || 'smtp.gmail.com';
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '465', 10);
const SMTP_SECURE = process.env.SMTP_SECURE !== 'false';
const SMTP_USER = process.env.SMTP_USER || 'ramasamy.gokila@gmail.com';
const SMTP_PASS = (process.env.SMTP_PASS || '').trim().replace(/\s+/g, '');
const FROM_NAME = process.env.STORE_FROM_NAME || 'Sreekrishna Textiles';
const FROM_EMAIL = process.env.STORE_FROM_EMAIL || `"${FROM_NAME}" <${SMTP_USER}>`;

let transporter = null;

function getTransporter() {
  if (!SMTP_PASS) return null;
  if (!transporter) {
    transporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_SECURE,
      auth: {
        user: SMTP_USER,
        pass: SMTP_PASS,
      },
      connectionTimeout: 10000,
      greetingTimeout: 10000,
      socketTimeout: 15000,
    });
  }
  return transporter;
}

async function sendMail({ to, subject, html, text }) {
  const t = getTransporter();
  if (!t) {
    console.log(`\n========================================================`);
    console.log(`[SMTP DEV MODE] Email to: ${to}`);
    console.log(`[SMTP DEV MODE] Subject: ${subject}`);
    console.log(`[SMTP DEV MODE] Note: SMTP_PASS is not configured in .env yet.`);
    console.log(`========================================================\n`);
    return { simulated: true, to, subject };
  }
  return await t.sendMail({
    from: FROM_EMAIL,
    to,
    subject,
    text: text || html.replace(/<[^>]+>/g, ' '),
    html,
  });
}

async function sendOtpEmail({ to, otp, purpose = 'forgot_password', name = '' }) {
  let title = 'Your Verification Code';
  let actionText = 'Use the 6-digit verification code below to verify your account.';
  let subject = `[Sreekrishna Textiles] ${otp} is your verification code`;

  if (purpose === 'signup') {
    title = 'Verify Your Email Address';
    actionText = 'Welcome to Sreekrishna Textiles! Use the 6-digit verification code below to verify your email and complete your account registration:';
    subject = `[Sreekrishna Textiles] ${otp} is your account verification code`;
  } else if (purpose === 'forgot_password') {
    title = 'Password Reset Verification Code';
    actionText = 'You requested to reset your password for your Sreekrishna Textiles account.';
    subject = `[Sreekrishna Textiles] ${otp} is your password reset code`;
  } else if (purpose === 'login') {
    title = 'Your Login Verification Code';
    actionText = 'Use the 6-digit verification code below to log in to your Sreekrishna Textiles account without a password.';
    subject = `[Sreekrishna Textiles] ${otp} is your login code`;
  }

  const html = `
    <!DOCTYPE html>
    <html>
    <head><meta charset="utf-8"></head>
    <body style="margin:0;padding:24px;background-color:#f9f4ef;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#2c1b18;">
      <div style="max-width:520px;margin:0 auto;background:#ffffff;border-radius:14px;overflow:hidden;box-shadow:0 6px 24px rgba(90,15,42,0.08);border:1px solid #ebd8ca;">
        <div style="background:linear-gradient(135deg, #5a0f2a 0%, #2a0814 100%);padding:28px 24px;text-align:center;">
          <h1 style="margin:0;color:#f6d289;font-size:24px;letter-spacing:1px;font-family:Georgia,serif;">SREEKRISHNA TEXTILES</h1>
          <p style="margin:4px 0 0;color:#fcecd2;font-size:12px;letter-spacing:2px;text-transform:uppercase;">Tradition Meets Elegance</p>
        </div>
        <div style="padding:32px 28px;">
          <h2 style="margin:0 0 12px;color:#5a0f2a;font-size:20px;">${title}</h2>
          <p style="margin:0 0 20px;color:#555;font-size:14px;line-height:1.6;">
            Hello${name ? ' ' + name : ''},<br>${actionText}
          </p>
          <div style="background:#fcf6f0;border:2px dashed #b3122a;border-radius:10px;padding:20px;text-align:center;margin:24px 0;">
            <span style="font-size:12px;color:#8c6252;text-transform:uppercase;letter-spacing:1.5px;display:block;margin-bottom:8px;font-weight:600;">Verification Code</span>
            <span style="font-size:36px;font-weight:700;letter-spacing:8px;color:#b3122a;font-family:monospace;display:inline-block;">${otp}</span>
          </div>
          <p style="margin:0 0 16px;color:#777;font-size:13px;line-height:1.5;">
            ⏱ This code is valid for <b>10 minutes</b>. For security reasons, do not share this code with anyone.
          </p>
          <p style="margin:0;color:#999;font-size:12px;line-height:1.4;">
            If you did not request this verification code, please ignore this email or contact our support team.
          </p>
        </div>
        <div style="background:#faf5f0;padding:16px 28px;text-align:center;border-top:1px solid #f0e2d8;font-size:11.5px;color:#8a7065;">
          Sreekrishna Textiles • Kovai Road, Pollachi - 642002 • +91 9976392317
        </div>
      </div>
    </body>
    </html>
  `;

  return await sendMail({
    to,
    subject,
    html,
  });
}

module.exports = {
  sendMail,
  sendOtpEmail,
  isConfigured: () => Boolean(process.env.SMTP_PASS && process.env.SMTP_PASS.trim()),
};
