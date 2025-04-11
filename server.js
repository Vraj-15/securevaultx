const express = require('express');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');

const app = express();
const port = 3000;

app.get('/generate-mfa', (req, res) => {
  // 1. Generate MFA secret
  const secret = speakeasy.generateSecret({
    name: "SecureVaultX", // this will show up in the Authenticator app
  });

  // 2. Convert secret to QR Code Data URL
  qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
    if (err) {
      return res.send("Error generating QR code.");
    }

    // 3. Send the HTML with embedded QR Code
    res.send(`
      <h3>Scan this QR Code with Microsoft Authenticator:</h3>
      <img src="${data_url}" />
      <p>Secret (for dev/test only): <code>${secret.base32}</code></p>
    `);
  });
});

app.listen(port, () => {
  console.log(`✅ MFA server running at http://localhost:${port}`);
});
