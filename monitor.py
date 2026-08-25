#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Qeema Website Monitor
----------------------
Comprehensive monitoring for a single website:
- Uptime / HTTP status / response time
- SSL certificate expiry
- Broken internal links
- Content-change detection
- Basic SEO checks (title, meta description, H1, viewport)
- Security headers
- Domain expiry (best-effort via WHOIS)

State (previous hash, previous broken links, last-alert timestamps, etc.)
is persisted in data/state.json, which the GitHub Actions workflow commits
back to the repo after every run so history survives between runs.

Configuration is via environment variables (see README.md):
  SITE_URL   - the page to monitor (default: https://qeema.net/home)
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, ALERT_TO - email alerting
"""

import os
import re
import sys
import json
import time
import ssl
import socket
import hashlib
import smtplib
import datetime
from email.mime.text import MIMEText
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
SITE_URL = os.environ.get("SITE_URL", "https://qeema.net/home")
BASE_DOMAIN = urlparse(SITE_URL).netloc
STATE_FILE = "data/state.json"
HISTORY_FILE = "data/history.csv"
TIMEOUT = 15
MAX_LINKS_TO_CHECK = 60
SSL_WARN_DAYS = 14
DOMAIN_WARN_DAYS = 30
SLOW_RESPONSE_MS = 5000

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")
ALERT_TO = os.environ.get("ALERT_TO")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; QeemaMonitorBot/1.0; +https://github.com/)"
}

# --------------------------------------------------------------------------
# State helpers
# --------------------------------------------------------------------------


def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False, default=str)


def log_history(now_iso, ok, status_code, response_ms):
    os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)
    is_new = not os.path.exists(HISTORY_FILE)
    with open(HISTORY_FILE, "a", encoding="utf-8") as f:
        if is_new:
            f.write("timestamp_utc,ok,status_code,response_ms\n")
        f.write(f"{now_iso},{ok},{status_code},{response_ms}\n")


# --------------------------------------------------------------------------
# Email
# --------------------------------------------------------------------------


def send_email(subject, body):
    if not (SMTP_USER and SMTP_PASS and ALERT_TO):
        print("!! SMTP not configured - skipping email. Message was:\n")
        print(subject)
        print(body)
        return
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = ALERT_TO
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=TIMEOUT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, [ALERT_TO], msg.as_string())
        print(f"Email sent to {ALERT_TO}: {subject}")
    except Exception as e:
        print(f"!! Failed to send email: {e}")


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------


def check_uptime():
    result = {
        "ok": False,
        "status_code": None,
        "response_ms": None,
        "error": None,
        "html": None,
        "headers": {},
    }
    try:
        start = time.time()
        r = requests.get(SITE_URL, timeout=TIMEOUT, allow_redirects=True, headers=HEADERS)
        elapsed_ms = round((time.time() - start) * 1000)
        result["status_code"] = r.status_code
        result["response_ms"] = elapsed_ms
        result["ok"] = r.status_code < 400
        result["headers"] = dict(r.headers)
        if result["ok"]:
            result["html"] = r.text
    except Exception as e:
        result["error"] = str(e)
    return result


def check_ssl():
    result = {"ok": True, "expires_at": None, "days_left": None, "error": None}
    host = BASE_DOMAIN
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        expires = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (expires - datetime.datetime.utcnow()).days
        result["expires_at"] = expires.isoformat()
        result["days_left"] = days_left
        result["ok"] = days_left > SSL_WARN_DAYS
    except Exception as e:
        result["error"] = str(e)
        result["ok"] = False
    return result


def extract_internal_links(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        full = urljoin(base_url, href)
        parsed = urlparse(full)
        if parsed.scheme not in ("http", "https"):
            continue
        if parsed.netloc == BASE_DOMAIN:
            links.add(full.split("#")[0])
    return links


def check_broken_links(html):
    broken = []
    links = list(extract_internal_links(html, SITE_URL))[:MAX_LINKS_TO_CHECK]
    for link in links:
        status = None
        error = None
        try:
            r = requests.head(link, timeout=TIMEOUT, allow_redirects=True, headers=HEADERS)
            status = r.status_code
            if status >= 400 or status == 405:
                r = requests.get(link, timeout=TIMEOUT, allow_redirects=True, headers=HEADERS)
                status = r.status_code
        except Exception as e:
            error = str(e)
        if error or (status is not None and status >= 400):
            broken.append({"url": link, "status": status, "error": error})
    return broken, len(links)


def check_seo(html):
    soup = BeautifulSoup(html, "html.parser")
    issues = []
    title = (soup.title.string or "").strip() if soup.title and soup.title.string else ""
    if not title:
        issues.append("لا يوجد عنوان (title) للصفحة")
    meta_desc = soup.find("meta", attrs={"name": "description"})
    if not meta_desc or not (meta_desc.get("content") or "").strip():
        issues.append("لا يوجد meta description")
    if not soup.find_all("h1"):
        issues.append("لا يوجد عنصر H1 في الصفحة")
    if not soup.find("meta", attrs={"name": "viewport"}):
        issues.append("لا يوجد meta viewport (مهم للتجاوب مع الموبايل)")
    return issues, title


def check_security_headers(headers):
    wanted = [
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Content-Security-Policy",
        "Referrer-Policy",
    ]
    header_keys = {h.lower() for h in headers.keys()}
    return [h for h in wanted if h.lower() not in header_keys]


def content_hash(html):
    normalized = re.sub(r"\s+", " ", html or "").strip()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def check_domain_expiry():
    result = {"days_left": None, "error": None}
    try:
        import whois  # python-whois

        w = whois.whois(BASE_DOMAIN)
        exp = w.expiration_date
        if isinstance(exp, list):
            exp = exp[0]
        if exp:
            if isinstance(exp, datetime.datetime):
                days_left = (exp - datetime.datetime.utcnow()).days
            else:
                days_left = None
            result["days_left"] = days_left
    except Exception as e:
        result["error"] = str(e)
    return result


def check_http_redirects_to_https():
    """Best-effort check that the plain-http version redirects to https."""
    http_url = "http://" + BASE_DOMAIN + "/"
    try:
        r = requests.get(http_url, timeout=TIMEOUT, allow_redirects=True, headers=HEADERS)
        return r.url.startswith("https://")
    except Exception:
        return None  # inconclusive, don't alert on this


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def main():
    state = load_state()
    now = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    alerts = []
    info_notes = []

    # 1) Uptime / performance --------------------------------------------------
    uptime = check_uptime()
    prev_up = state.get("last_up")

    if not uptime["ok"]:
        alerts.append(
            f"🔴 الموقع مش راضي يرد أو رجّع خطأ.\n"
            f"   الرابط: {SITE_URL}\n"
            f"   Status code: {uptime['status_code']}\n"
            f"   الخطأ: {uptime['error']}"
        )
    else:
        if prev_up is False:
            alerts.insert(0, f"✅ الموقع رجع شغال تاني بعد ما كان واقع (status {uptime['status_code']}).")
        if uptime["response_ms"] and uptime["response_ms"] > SLOW_RESPONSE_MS:
            alerts.append(f"🟠 وقت استجابة بطيء جدًا: {uptime['response_ms']}ms (أكبر من {SLOW_RESPONSE_MS}ms)")

    # 2) SSL certificate ---------------------------------------------------
    ssl_res = check_ssl()
    already_warned_ssl = state.get("ssl_warned_at_days")
    if ssl_res["error"]:
        alerts.append(f"🔴 مشكلة أثناء فحص شهادة SSL: {ssl_res['error']}")
    elif not ssl_res["ok"]:
        # only alert once per distinct "days_left" bucket to avoid repeating every run
        if already_warned_ssl != ssl_res["days_left"]:
            alerts.append(
                f"🟠 شهادة SSL هتنتهي خلال {ssl_res['days_left']} يوم (بتاريخ {ssl_res['expires_at']})."
            )
            state["ssl_warned_at_days"] = ssl_res["days_left"]
    else:
        state["ssl_warned_at_days"] = None

    # 3) Broken links / SEO / security headers / content diff --------------
    seo_issues, title = [], ""
    missing_headers = []
    if uptime.get("html"):
        broken, total_checked = check_broken_links(uptime["html"])
        prev_broken_urls = set(state.get("broken_links", []))
        current_broken_urls = {b["url"] for b in broken}
        new_broken = [b for b in broken if b["url"] not in prev_broken_urls]
        fixed_urls = prev_broken_urls - current_broken_urls

        if new_broken:
            lines = "\n".join(
                f"   - {b['url']} -> {b.get('status') or b.get('error')}" for b in new_broken
            )
            alerts.append(
                f"🟠 لينكات مكسورة جديدة ({len(new_broken)} من إجمالي {total_checked} تم فحصهم):\n{lines}"
            )
        if fixed_urls:
            info_notes.append(f"✅ اتصلحت {len(fixed_urls)} لينك كانوا مكسورين قبل كده.")

        state["broken_links"] = list(current_broken_urls)

        seo_issues, title = check_seo(uptime["html"])
        missing_headers = check_security_headers(uptime["headers"])

        new_hash = content_hash(uptime["html"])
        old_hash = state.get("content_hash")
        if old_hash and old_hash != new_hash:
            info_notes.append("ℹ️ اتغير محتوى الصفحة الرئيسية عن آخر فحص (تغيير في المحتوى).")
        state["content_hash"] = new_hash

    # 4) Domain expiry (best-effort) ---------------------------------------
    domain = check_domain_expiry()
    already_warned_domain = state.get("domain_warned_at_days")
    if domain["days_left"] is not None and domain["days_left"] < DOMAIN_WARN_DAYS:
        if already_warned_domain != domain["days_left"]:
            alerts.append(f"🟠 الدومين {BASE_DOMAIN} هينتهي خلال {domain['days_left']} يوم!")
            state["domain_warned_at_days"] = domain["days_left"]
    elif domain["days_left"] is not None:
        state["domain_warned_at_days"] = None

    # 5) HTTP -> HTTPS redirect check --------------------------------------
    redirects_ok = check_http_redirects_to_https()
    if redirects_ok is False and not state.get("http_redirect_warned"):
        info_notes.append("ℹ️ رابط http:// (بدون S) مش بيعمل redirect تلقائي لـ https://.")
        state["http_redirect_warned"] = True
    elif redirects_ok:
        state["http_redirect_warned"] = False

    # 6) Daily digest for slow-moving, non-urgent issues (SEO / headers) ---
    today = datetime.date.today().isoformat()
    if state.get("last_digest_date") != today and (seo_issues or missing_headers):
        digest_parts = []
        if seo_issues:
            digest_parts.append("مشاكل SEO أساسية:\n" + "\n".join(f"   - {i}" for i in seo_issues))
        if missing_headers:
            digest_parts.append(
                "Security headers ناقصة:\n" + "\n".join(f"   - {h}" for h in missing_headers)
            )
        info_notes.append("📋 ملخص يومي:\n" + "\n\n".join(digest_parts))
        state["last_digest_date"] = today

    # Persist state + history -----------------------------------------------
    state["last_up"] = uptime["ok"]
    state["last_check"] = now
    save_state(state)
    log_history(now, uptime["ok"], uptime["status_code"], uptime["response_ms"])

    # Send alerts -------------------------------------------------------------
    if alerts:
        subject = f"🚨 تنبيه مراقبة {BASE_DOMAIN} - {len(alerts)} حاجة محتاجة انتباه"
        body = f"وقت الفحص: {now}\nالرابط: {SITE_URL}\n\n" + "\n\n".join(alerts)
        if info_notes:
            body += "\n\n---\nملاحظات إضافية:\n\n" + "\n\n".join(info_notes)
        send_email(subject, body)
    elif info_notes:
        subject = f"ℹ️ ملاحظات مراقبة {BASE_DOMAIN}"
        body = f"وقت الفحص: {now}\nالرابط: {SITE_URL}\n\n" + "\n\n".join(info_notes)
        send_email(subject, body)
    else:
        print(
            f"[{now}] كل حاجة تمام. status={uptime['status_code']} "
            f"response={uptime['response_ms']}ms ssl_days_left={ssl_res['days_left']}"
        )

    # Non-zero exit only on hard failure, so it's visible in the Actions tab
    if not uptime["ok"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
