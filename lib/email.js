const nodemailer = require('nodemailer');

/**
 * Send an email with optional PDF attachment.
 *
 * Configure via env vars:
 *   SMTP_HOST     — SMTP server (e.g. live.smtp.mailtrap.io)
 *   SMTP_PORT     — SMTP port (default 587)
 *   SMTP_USER     — SMTP username
 *   SMTP_PASS     — SMTP password
 *   FROM_EMAIL    — sender address
 *
 * If SMTP_PASS is not set, falls back to console.log for local dev.
 */
async function sendPOEmail({ to, subject, text, attachment }) {
  const smtpPass = process.env.SMTP_PASS;

  if (!smtpPass) {
    // Dev fallback: log instead of send
    console.log('─'.repeat(50));
    console.log(`📧 EMAIL TO: ${to}`);
    console.log(`   Subject: ${subject}`);
    console.log(`   Body: ${text}`);
    if (attachment) {
      console.log(`   Attachment: ${attachment.filename} (${attachment.content.length} bytes)`);
    }
    console.log('─'.repeat(50));
    return;
  }

  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'live.smtp.mailtrap.io',
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER || 'api',
      pass: smtpPass,
    },
    connectionTimeout: 8000,
    greetingTimeout: 8000,
    socketTimeout: 12000,
  });

  await transporter.sendMail({
    from: process.env.FROM_EMAIL || 'purchase-orders@stockyshift.com',
    to,
    subject,
    text,
    ...(attachment ? {
      attachments: [{ filename: attachment.filename, content: attachment.content }],
    } : {}),
  });
}

module.exports = { sendPOEmail };
