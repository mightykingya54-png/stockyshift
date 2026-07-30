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
    if (process.env.NODE_ENV === 'production') {
      // Fail loudly — silently dropping email in production means POs marked
      // 'sent' that never went out and merchants who never get stock alerts.
      throw new Error('SMTP_PASS is not configured; cannot send email in production');
    }
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
    port: parseInt(process.env.SMTP_PORT || '2525'),
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER || 'api',
      pass: smtpPass,
    },
    connectionTimeout: 8000,
    greetingTimeout: 8000,
    socketTimeout: 12000,
  });

  try {
    await transporter.sendMail({
      from: process.env.FROM_EMAIL || 'purchase-orders@stockyshift.com',
      to,
      subject,
      text,
      ...(attachment ? {
        attachments: [{ filename: attachment.filename, content: attachment.content }],
      } : {}),
    });
    console.log(`[Email] Sent to ${to} — subject: "${subject}"`);
  } catch (err) {
    console.error(`[Email] Failed to send to ${to}: ${err.message}`);
    if (err.response) console.error('[Email] Server response:', err.response);
    throw err;
  }
}

module.exports = { sendPOEmail };
