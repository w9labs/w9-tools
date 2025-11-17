# First Principal: No guide, no .md files, no explainations. Just do what I tell you.
# W9 - Short Link & File Sharer
# Stack: Frontend: React + Vite; Backend: Rust + Axum
# The project will be deployed using install.sh script on my VPS. not this local, don't prompt to run on local.
# Alwways update Auto-setup install.sh script (If needed).
# Update sitemap.xml and robots.txt after create any newpages or transition.


Simplifize the install.sh script:
- check update - build frontend - backend. start. nginx services start. simple.
```
shayneeo@x1:~/W9$ git pull && sudo DOMAIN=w9.se BASE_URL=https://w9.se ./deploy/install.sh
remote: Enumerating objects: 7, done.
remote: Counting objects: 100% (7/7), done.
remote: Compressing objects: 100% (1/1), done.
remote: Total 4 (delta 2), reused 4 (delta 2), pack-reused 0 (from 0)
Unpacking objects: 100% (4/4), 498 bytes | 249.00 KiB/s, done.
From https://github.com/ShayNeeo/W9
   2d68081..233d1a0  main       -> origin/main
Updating 2d68081..233d1a0
Fast-forward
 deploy/install.sh | 5 +++++
 1 file changed, 5 insertions(+)
Repo root: /home/shayneeo/W9
Stopping existing w9 service
Temporarily disabling w9 to avoid auto-restarts
Building release (as user: shayneeo)
Installing system packages...
Hit:1 https://deb.debian.org/debian sid InRelease
Reading package lists... Done
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
build-essential is already the newest version (12.12).
pkg-config is already the newest version (1.8.1-4).
libsqlite3-dev is already the newest version (3.46.1-8).
ca-certificates is already the newest version (20250419).
curl is already the newest version (8.17.0-2).
git is already the newest version (1:2.51.0-1).
nodejs is already the newest version (20.19.5+dfsg+~cs20.19.24-1).
npm is already the newest version (9.2.0~ds1-3).
openssl is already the newest version (3.5.4-1).
nginx is already the newest version (1.28.0-6).
ufw is already the newest version (0.36.2-9).
Solving dependencies... Done
0 upgraded, 0 newly installed, 0 to remove and 81 not upgraded.
Building backend release (as user: shayneeo)
    Finished `release` profile [optimized] target(s) in 0.13s
Building frontend...

up to date, audited 31 packages in 762ms

4 packages are looking for funding
  run `npm fund` for details

2 moderate severity vulnerabilities

To address all issues (including breaking changes), run:
  npm audit fix --force

Run `npm audit` for details.

> w9-frontend@0.0.0 build
> tsc -b && vite build

vite v5.4.21 building for production...
✓ 31 modules transformed.
dist/index.html                   0.39 kB │ gzip:  0.26 kB
dist/assets/index-9WusT_-b.css    1.52 kB │ gzip:  0.62 kB
dist/assets/index-Sr-nNy_0.js   147.55 kB │ gzip: 47.65 kB
✓ built in 1.65s
Frontend built to /home/shayneeo/W9/frontend/dist
Installing binary to /opt/w9/w9
Installing frontend to /var/www/w9
✓ Frontend installed
Updating /etc/default/w9 (ENV_OVERWRITE enabled)
Writing systemd unit /etc/systemd/system/w9.service
Reloading systemd and enabling service
Created symlink '/etc/systemd/system/multi-user.target.wants/w9.service' → '/etc/systemd/system/w9.service'.
Configuring nginx for frontend + API on w9.se
Ensuring self-signed certificate in /etc/nginx/ssl/w9.se
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
✓ Nginx config valid
Skipping adding existing rule
Skipping adding existing rule (v6)
Starting (or restarting) w9 service
Waiting for service to start...
✓ Service is running
✓ Service is listening on port 10105
Verifying backend health...
✓ Backend health check passed
● w9.service - w9 - Link & file sharer service
     Loaded: loaded (/etc/systemd/system/w9.service; enabled; preset: enabled)
     Active: activating (auto-restart) (Result: exit-code) since Mon 2025-11-17 11:13:54 UTC; 1s ago
 Invocation: 95ff75deb05c44be809e3429adb47f83
    Process: 3997 ExecStart=/opt/w9/w9 (code=exited, status=1/FAILURE)
   Main PID: 3997 (code=exited, status=1/FAILURE)
   Mem peak: 2M
        CPU: 13ms
Reloading nginx (if installed)
Synchronizing state of nginx.service with SysV service script with /usr/lib/systemd/systemd-sysv-install.
Executing: /usr/lib/systemd/systemd-sysv-install enable nginx
✓ Nginx is running
Verifying nginx → backend connectivity...
✓ Nginx can reach backend successfully

🔍 DNS & Cloudflare Proxy Diagnostics:
  VPS Public IP: 162.43.30.192
  Testing domain access via HTTP...
  ⚠️  Domain returned HTTP 301
./deploy/install.sh: line 599: DNS_RESULT: unbound variable

✓ Done! Service is running.

========== Installation Summary ==========
Domain:      w9.se
Backend:     /opt/w9/w9 (port 10105)
Frontend:    /var/www/w9
Data:        /opt/w9/data
Uploads:     /opt/w9/uploads
Nginx:       Port 80
SSL:         Cloudflare (auto)

Routes:
  /              → Frontend
  /api/*         → Backend API
  /admin/*       → Backend Admin
  /r/:code       → Redirect
  /s/:code       → Short link
  /files/*       → Uploads

📊 Diagnostic Commands:
  Service status:  sudo systemctl status w9
  Service logs:    sudo journalctl -u w9 -f
  Nginx logs:      sudo journalctl -u nginx -f
  Backend health:  curl http://127.0.0.1:10105/health
  Via nginx:       curl http://127.0.0.1/health
  Check port:      ss -tln | grep 10105

🔍 Troubleshooting Cloudflare 521:

If proxy is ON (orange cloud 🔒) and you get 521 error:
  1. Go to Cloudflare Dashboard → SSL/TLS → Overview
  2. Set SSL/TLS encryption mode to 'Flexible'
     - Flexible: Cloudflare ↔ Visitors: HTTPS, Cloudflare ↔ Origin: HTTP
     - Full/Full Strict: Requires HTTPS on origin (port 443) - will cause 521
  3. Wait 1-2 minutes for changes to propagate
  4. Test: curl https://w9.se/health

If proxy is OFF (gray cloud ⚙️) and domain doesn't work:
  1. Check DNS resolution: dig +short w9.se @8.8.8.8
     - Should show your VPS IP (not Cloudflare IPs like 104.x.x.x)
  2. Wait 5-10 minutes for DNS propagation
  3. Clear DNS cache:
     - Linux: sudo systemd-resolve --flush-caches
     - Browser: Use incognito/private mode
  4. Test domain directly: curl -v http://w9.se/health

General diagnostics:
  1. Verify backend: sudo systemctl status w9
  2. Check backend logs: sudo journalctl -u w9 -n 50
  3. Test backend directly: curl http://127.0.0.1:10105/health
  4. Test via nginx (IP): curl http://127.0.0.1/health
  5. Test via nginx (domain): curl -H 'Host: w9.se' http://127.0.0.1/health
  6. Verify nginx config: sudo nginx -t
  7. Check firewall: sudo ufw status
  8. Check nginx access logs: sudo tail -f /var/log/nginx/access.log

========================================
shayneeo@x1:~/W9$ 
```