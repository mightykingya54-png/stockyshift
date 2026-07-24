const nodemailer = require('nodemailer');

/**
 * Send a PO email with PDF attachment.
 * Falls back to a log-based approach if no SendGrid key is configured,
 * so you can develop without sending real emails.
 */
async function sendPOEmail({ to, subject, text, attachment }) {
  const apiKey = process.env.SENDGRID_API_KEY;

  if (!apiKey) {
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
    host: 'smtp.sendgrid.net',
    port: 587,
    auth: { user: 'apikey', pass: apiKey },
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
