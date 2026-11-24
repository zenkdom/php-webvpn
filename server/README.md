# 🌐 PHP-WebVPN Backend Server

This directory contains the lightweight backend components to deploy onto any standard PHP web hosting environment (cPanel, DirectAdmin, shared hosting, free hosting, Apache, or Nginx).

---

## 📁 Files Included

- **`proxy.php`** — Core proxy execution engine powered by PHP cURL.
- **`index.php`** — Convenient entrypoint for subfolder deployments (e.g., `https://your-domain.com/vpn/`).
- **`.htaccess`** — Apache web server optimizations (execution limits, output buffering disable, mod_deflate gzip compression).

---

## ⚡ Quick Deployment (30 Seconds)

### 1. Set Your Secret Key
Open `proxy.php` in any text editor and change `secret_key` in the `$CONFIG` array:
```php
$CONFIG = [
    'secret_key'  => 'YourSuperSecretKeyGoesHere',
    'allow_test'  => true,
    'max_timeout' => 60,
    'verify_ssl'  => false,
];
```
> [!IMPORTANT]
> Always change the secret key before deploying! Any request without this key triggers an authentic `404 Not Found` decoy page to stay undetected by automated scanners and DPI firewalls.

### 2. Upload to Your Hosting
Upload `proxy.php` and `.htaccess` (plus `index.php` if desired) using FTP, SFTP, or your hosting File Manager:
- **Root directory:** e.g., `public_html/proxy.php` -> Accessible at `https://your-domain.com/proxy.php`
- **Subdirectory:** e.g., `public_html/vpn/proxy.php` -> Accessible at `https://your-domain.com/vpn/`

### 3. Verify Health Check
Open the test URL in your browser:
```text
https://your-domain.com/proxy.php?test=1&key=YourSuperSecretKeyGoesHere
```
You should receive a JSON status report:
```json
{
  "status": "ok",
  "message": "PHP-WebVPN Backend is operational and ready!",
  "php_version": "8.x.x",
  "curl_loaded": true,
  "server_ip": "x.x.x.x"
}
```
If you see this, your backend is ready to handle traffic!
