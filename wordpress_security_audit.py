#!/usr/bin/env python3
# wordpress_security_audit.py - Script untuk audit keamanan instalasi WordPress

import os
import sys
import requests
import urllib3
import json
import re
import subprocess
import datetime
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

# Nonaktifkan peringatan SSL untuk permintaan yang menggunakan SSL dengan sertifikat yang tidak diverifikasi
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WordPressSecurityAudit:
    def __init__(self, wp_url=None, wp_path=None):
        self.wp_url = wp_url
        self.wp_path = wp_path
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.output_file = f"wp_security_audit_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        self.report = {
            "timestamp": self.timestamp,
            "wp_url": wp_url,
            "wp_path": wp_path,
            "wordpress_version": None,
            "server_info": {},
            "file_permissions": {},
            "config_security": {},
            "plugin_vulnerabilities": [],
            "theme_vulnerabilities": [],
            "open_directories": [],
            "exposed_sensitive_files": [],
            "security_headers": {},
            "wp_admin_protection": {},
            "database_security": {},
            "user_enumeration": False,
            "recommendations": []
        }

    def run_audit(self):
        """Menjalankan seluruh audit keamanan WordPress"""
        print("[+] Memulai Audit Keamanan WordPress...")

        if not self.wp_url and not self.wp_path:
            print("[-] Error: Harap berikan URL WordPress atau jalur instalasi WordPress lokal")
            sys.exit(1)

        if self.wp_url:
            # Verifikasi URL WordPress
            if not self.verify_wordpress_site():
                print("[-] Error: URL yang diberikan bukan situs WordPress yang valid")
                sys.exit(1)

            self.check_wordpress_version_remote()
            self.check_security_headers()
            self.check_wp_admin_protection()
            self.check_exposed_sensitive_files()
            self.check_directory_listing()
            self.check_user_enumeration()

        if self.wp_path:
            # Verifikasi jalur instalasi WordPress
            if not self.verify_wordpress_path():
                print("[-] Error: Jalur yang diberikan bukan instalasi WordPress yang valid")
                sys.exit(1)

            self.check_wordpress_version_local()
            self.check_file_permissions()
            self.check_wp_config_security()
            self.check_plugins_security()
            self.check_themes_security()
            self.check_database_security()

        self.generate_recommendations()
        self.save_report()
        print(f"[+] Audit selesai. Laporan tersimpan di: {self.output_file}")

    def verify_wordpress_site(self):
        """Memverifikasi bahwa URL adalah situs WordPress"""
        print("[+] Memverifikasi situs WordPress...")

        try:
            response = requests.get(f"{self.wp_url}/wp-login.php", verify=False, timeout=10)
            return "WordPress" in response.text
        except Exception as e:
            print(f"[-] Error saat memverifikasi situs WordPress: {e}")
            return False

    def verify_wordpress_path(self):
        """Memverifikasi jalur instalasi WordPress lokal"""
        print("[+] Memverifikasi jalur instalasi WordPress...")

        wp_login = os.path.join(self.wp_path, "wp-login.php")
        wp_config = os.path.join(self.wp_path, "wp-config.php")

        return os.path.exists(wp_login) and os.path.exists(wp_config)

    def check_wordpress_version_remote(self):
        """Memeriksa versi WordPress dari situs jarak jauh"""
        print("[+] Memeriksa versi WordPress (remote)...")

        try:
            # Metode 1: Dari meta generator di halaman utama
            response = requests.get(self.wp_url, verify=False, timeout=10)
            version_match = re.search(r'<meta name="generator" content="WordPress (\d+\.\d+(\.\d+)?)', response.text)

            if version_match:
                self.report["wordpress_version"] = version_match.group(1)
                print(f"[+] Versi WordPress terdeteksi: {self.report['wordpress_version']}")
                return

            # Metode 2: Dari feed RSS
            rss_url = f"{self.wp_url}/feed/"
            response = requests.get(rss_url, verify=False, timeout=10)

            if response.status_code == 200:
                try:
                    version_match = re.search(r'<generator>https://wordpress.org/\?v=(\d+\.\d+(\.\d+)?)</generator>', response.text)
                    if version_match:
                        self.report["wordpress_version"] = version_match.group(1)
                        print(f"[+] Versi WordPress terdeteksi: {self.report['wordpress_version']}")
                        return
                except Exception:
                    pass

            # Metode 3: Dari readme.html
            readme_url = f"{self.wp_url}/readme.html"
            response = requests.get(readme_url, verify=False, timeout=10)

            if response.status_code == 200:
                version_match = re.search(r'<br />\s*[vV]ersion (\d+\.\d+(\.\d+)?)', response.text)
                if version_match:
                    self.report["wordpress_version"] = version_match.group(1)
                    print(f"[+] Versi WordPress terdeteksi: {self.report['wordpress_version']}")
                    return

            self.report["wordpress_version"] = "Tidak dapat mendeteksi"
            print("[-] Tidak dapat mendeteksi versi WordPress")

        except Exception as e:
            print(f"[-] Error saat memeriksa versi WordPress: {e}")
            self.report["wordpress_version"] = "Error"

    def check_wordpress_version_local(self):
        """Memeriksa versi WordPress dari instalasi lokal"""
        print("[+] Memeriksa versi WordPress (lokal)...")

        try:
            # Metode 1: Dari file version.php
            version_file = os.path.join(self.wp_path, "wp-includes", "version.php")

            if os.path.exists(version_file):
                with open(version_file, 'r') as f:
                    content = f.read()
                    version_match = re.search(r"\$wp_version\s*=\s*'(\d+\.\d+(\.\d+)?)'", content)

                    if version_match:
                        self.report["wordpress_version"] = version_match.group(1)
                        print(f"[+] Versi WordPress terdeteksi: {self.report['wordpress_version']}")
                        return

            # Metode 2: Dari readme.html
            readme_file = os.path.join(self.wp_path, "readme.html")

            if os.path.exists(readme_file):
                with open(readme_file, 'r') as f:
                    content = f.read()
                    version_match = re.search(r'<br />\s*[vV]ersion (\d+\.\d+(\.\d+)?)', content)

                    if version_match:
                        self.report["wordpress_version"] = version_match.group(1)
                        print(f"[+] Versi WordPress terdeteksi: {self.report['wordpress_version']}")
                        return

            self.report["wordpress_version"] = "Tidak dapat mendeteksi"
            print("[-] Tidak dapat mendeteksi versi WordPress")

        except Exception as e:
            print(f"[-] Error saat memeriksa versi WordPress: {e}")
            self.report["wordpress_version"] = "Error"

    def check_security_headers(self):
        """Memeriksa header keamanan situs"""
        print("[+] Memeriksa header keamanan...")

        try:
            response = requests.get(self.wp_url, verify=False, timeout=10)
            headers = response.headers

            security_headers = {
                "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Tidak ada"),
                "Content-Security-Policy": headers.get("Content-Security-Policy", "Tidak ada"),
                "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Tidak ada"),
                "X-Frame-Options": headers.get("X-Frame-Options", "Tidak ada"),
                "X-XSS-Protection": headers.get("X-XSS-Protection", "Tidak ada"),
                "Referrer-Policy": headers.get("Referrer-Policy", "Tidak ada"),
                "Feature-Policy": headers.get("Feature-Policy", "Tidak ada"),
                "Permissions-Policy": headers.get("Permissions-Policy", "Tidak ada")
            }

            self.report["security_headers"] = security_headers

            # Menambahkan rekomendasi berdasarkan header yang hilang
            if security_headers["Strict-Transport-Security"] == "Tidak ada":
                self.report["recommendations"].append(
                    "Tambahkan header Strict-Transport-Security untuk mengamankan koneksi HTTPS"
                )

            if security_headers["Content-Security-Policy"] == "Tidak ada":
                self.report["recommendations"].append(
                    "Tambahkan header Content-Security-Policy untuk mencegah XSS dan injeksi data"
                )

            if security_headers["X-Content-Type-Options"] == "Tidak ada":
                self.report["recommendations"].append(
                    "Tambahkan header X-Content-Type-Options untuk mencegah MIME-sniffing"
                )

            if security_headers["X-Frame-Options"] == "Tidak ada":
                self.report["recommendations"].append(
                    "Tambahkan header X-Frame-Options untuk mencegah clickjacking"
                )

        except Exception as e:
            print(f"[-] Error saat memeriksa header keamanan: {e}")
            self.report["security_headers"] = {"Error": str(e)}

    def check_wp_admin_protection(self):
        """Memeriksa perlindungan area wp-admin"""
        print("[+] Memeriksa perlindungan wp-admin...")

        try:
            response = requests.get(f"{self.wp_url}/wp-admin/", verify=False, timeout=10, allow_redirects=False)

            self.report["wp_admin_protection"] = {
                "status_code": response.status_code,
                "requires_authentication": response.status_code in [301, 302, 401, 403, 404],
                "redirect_location": response.headers.get("Location", "Tidak ada")
            }

            if response.status_code == 200:
                self.report["recommendations"].append(
                    "Tambahkan perlindungan tambahan untuk direktori wp-admin (gunakan .htaccess atau plugin keamanan)"
                )

        except Exception as e:
            print(f"[-] Error saat memeriksa perlindungan wp-admin: {e}")
            self.report["wp_admin_protection"] = {"Error": str(e)}

    def check_exposed_sensitive_files(self):
        """Memeriksa file sensitif yang terekspos"""
        print("[+] Memeriksa file sensitif yang terekspos...")

        sensitive_files = [
            "wp-config.php",
            "wp-config-sample.php",
            ".htaccess",
            "readme.html",
            "license.txt",
            "wp-content/debug.log",
            "error_log"
        ]

        for file in sensitive_files:
            try:
                response = requests.get(f"{self.wp_url}/{file}", verify=False, timeout=5)

                if response.status_code == 200:
                    self.report["exposed_sensitive_files"].append({
                        "file": file,
                        "status_code": response.status_code,
                        "size": len(response.content)
                    })

                    self.report["recommendations"].append(
                        f"Blokir akses ke file sensitif: {file}"
                    )

            except Exception as e:
                print(f"[-] Error saat memeriksa file {file}: {e}")
                continue

    def check_directory_listing(self):
        """Memeriksa listing direktori yang terbuka"""
        print("[+] Memeriksa directory listing...")

        directories = [
            "wp-content/",
            "wp-content/plugins/",
            "wp-content/themes/",
            "wp-content/uploads/",
            "wp-includes/"
        ]

        for directory in directories:
            try:
                response = requests.get(f"{self.wp_url}/{directory}", verify=False, timeout=5)

                # Jika terdapat link di halaman yang menunjuk ke file atau direktori
                if response.status_code == 200 and "Index of" in response.text:
                    self.report["open_directories"].append({
                        "directory": directory,
                        "status": "Terbuka"
                    })

                    self.report["recommendations"].append(
                        f"Nonaktifkan directory listing untuk: {directory}"
                    )

            except Exception as e:
                print(f"[-] Error saat memeriksa directory {directory}: {e}")
                continue

    def check_user_enumeration(self):
        """Memeriksa kemungkinan enumerasi pengguna"""
        print("[+] Memeriksa kemungkinan enumerasi pengguna...")

        try:
            # Coba mendapatkan author dengan ID=1
            response = requests.get(f"{self.wp_url}/?author=1", verify=False, timeout=10, allow_redirects=True)

            # Cek apakah redirect ke halaman author
            if response.status_code == 200 and "/author/" in response.url:
                self.report["user_enumeration"] = True
                self.report["recommendations"].append(
                    "Nonaktifkan enumerasi pengguna untuk mencegah serangan brute force"
                )
            else:
                self.report["user_enumeration"] = False

        except Exception as e:
            print(f"[-] Error saat memeriksa enumerasi pengguna: {e}")
            self.report["user_enumeration"] = "Error"

    def check_file_permissions(self):
        """Memeriksa izin file instalasi WordPress"""
        print("[+] Memeriksa izin file...")

        critical_files = {
            "wp-config.php": "400",
            ".htaccess": "644"
        }

        directories = {
            "wp-content/": "755",
            "wp-content/plugins/": "755",
            "wp-content/themes/": "755",
            "wp-content/uploads/": "755",
            "wp-includes/": "755"
        }

        # Periksa file kritis
        for file, recommended_perm in critical_files.items():
            file_path = os.path.join(self.wp_path, file)

            if os.path.exists(file_path):
                current_perm = oct(os.stat(file_path).st_mode)[-3:]

                self.report["file_permissions"][file] = {
                    "current": current_perm,
                    "recommended": recommended_perm,
                    "secure": current_perm <= recommended_perm
                }

                if current_perm > recommended_perm:
                    self.report["recommendations"].append(
                        f"Ubah izin file {file} dari {current_perm} menjadi {recommended_perm}"
                    )

        # Periksa direktori
        for directory, recommended_perm in directories.items():
            dir_path = os.path.join(self.wp_path, directory)

            if os.path.exists(dir_path):
                current_perm = oct(os.stat(dir_path).st_mode)[-3:]

                self.report["file_permissions"][directory] = {
                    "current": current_perm,
                    "recommended": recommended_perm,
                    "secure": current_perm <= recommended_perm
                }

                if current_perm > recommended_perm:
                    self.report["recommendations"].append(
                        f"Ubah izin direktori {directory} dari {current_perm} menjadi {recommended_perm}"
                    )

    def check_wp_config_security(self):
        """Memeriksa keamanan konfigurasi wp-config.php"""
        print("[+] Memeriksa keamanan wp-config.php...")

        config_path = os.path.join(self.wp_path, "wp-config.php")

        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    content = f.read()

                    # Periksa kunci keamanan
                    security_keys = [
                        "AUTH_KEY",
                        "SECURE_AUTH_KEY",
                        "LOGGED_IN_KEY",
                        "NONCE_KEY",
                        "AUTH_SALT",
                        "SECURE_AUTH_SALT",
                        "LOGGED_IN_SALT",
                        "NONCE_SALT"
                    ]

                    keys_found = 0
                    default_keys = 0

                    for key in security_keys:
                        if re.search(rf"define\s*\(\s*['\"]({key})['\"]", content):
                            keys_found += 1

                            # Cek apakah kunci default atau pendek
                            key_match = re.search(rf"define\s*\(\s*['\"]({key})['\"],\s*['\"](.*?)['\"]\s*\)", content)
                            if key_match and (key_match.group(2) == "put your unique phrase here" or len(key_match.group(2)) < 20):
                                default_keys += 1

                    # Periksa konfigurasi keamanan lainnya
                    debug_mode = re.search(r"define\s*\(\s*['\"]WP_DEBUG['\"],\s*true", content, re.IGNORECASE) is not None
                    table_prefix = "wp_"
                    prefix_match = re.search(r"\$table_prefix\s*=\s*['\"](.*?)['\"]", content)

                    if prefix_match:
                        table_prefix = prefix_match.group(1)

                    self.report["config_security"] = {
                        "security_keys_defined": keys_found,
                        "security_keys_total": len(security_keys),
                        "default_keys": default_keys,
                        "debug_mode": debug_mode,
                        "table_prefix": table_prefix,
                        "using_default_prefix": table_prefix == "wp_"
                    }

                    # Tambahkan rekomendasi
                    if keys_found < len(security_keys):
                        self.report["recommendations"].append(
                            "Tambahkan semua kunci keamanan WordPress di wp-config.php"
                        )

                    if default_keys > 0:
                        self.report["recommendations"].append(
                            "Ganti kunci keamanan default dengan kunci acak yang kuat"
                        )

                    if debug_mode:
                        self.report["recommendations"].append(
                            "Nonaktifkan WP_DEBUG di lingkungan produksi"
                        )

                    if table_prefix == "wp_":
                        self.report["recommendations"].append(
                            "Ubah prefix tabel database dari default 'wp_' ke nilai kustom"
                        )

            except Exception as e:
                print(f"[-] Error saat memeriksa wp-config.php: {e}")
                self.report["config_security"] = {"Error": str(e)}

    def check_plugins_security(self):
        """Memeriksa keamanan plugin yang terinstall"""
        print("[+] Memeriksa keamanan plugin...")

        plugins_dir = os.path.join(self.wp_path, "wp-content", "plugins")

        if os.path.exists(plugins_dir):
            try:
                # Dapatkan daftar plugin yang terinstall
                plugins = [name for name in os.listdir(plugins_dir) if os.path.isdir(os.path.join(plugins_dir, name))]

                for plugin in plugins:
                    plugin_dir = os.path.join(plugins_dir, plugin)

                    # Periksa versi plugin
                    version = "Unknown"

                    # Cek dari file readme.txt
                    readme_path = os.path.join(plugin_dir, "readme.txt")
                    if os.path.exists(readme_path):
                        with open(readme_path, 'r', errors='ignore') as f:
                            content = f.read()
                            version_match = re.search(r"Stable tag:\s*([\d\.]+)", content)

                            if version_match:
                                version = version_match.group(1)

                    # Cek dari file utama plugin
                    if version == "Unknown":
                        for file in os.listdir(plugin_dir):
                            if file.endswith(".php"):
                                try:
                                    with open(os.path.join(plugin_dir, file), 'r', errors='ignore') as f:
                                        content = f.read(1000)  # Hanya baca 1000 karakter pertama
                                        version_match = re.search(r"Version:\s*([\d\.]+)", content)

                                        if version_match:
                                            version = version_match.group(1)
                                            break
                                except:
                                    continue

                    self.report["plugin_vulnerabilities"].append({
                        "name": plugin,
                        "version": version,
                        "status": "Perlu diverifikasi",
                        "vulnerabilities": "Tidak diketahui - Periksa di wpvulndb.com atau plugin.vulnweb.com"
                    })

                # Tambahkan rekomendasi umum untuk plugin
                self.report["recommendations"].append(
                    "Verifikasi keamanan semua plugin yang terinstall secara teratur dan pastikan selalu diperbarui"
                )

                # Periksa plugin yang tidak aktif
                inactive_plugins = []
                for plugin in plugins:
                    if os.path.exists(os.path.join(plugins_dir, plugin, "." + plugin)):
                        inactive_plugins.append(plugin)

                if inactive_plugins:
                    self.report["recommendations"].append(
                        f"Hapus plugin yang tidak aktif: {', '.join(inactive_plugins)}"
                    )

            except Exception as e:
                print(f"[-] Error saat memeriksa plugin: {e}")

    def check_themes_security(self):
        """Memeriksa keamanan tema yang terinstall"""
        print("[+] Memeriksa keamanan tema...")

        themes_dir = os.path.join(self.wp_path, "wp-content", "themes")

        if os.path.exists(themes_dir):
            try:
                # Dapatkan daftar tema yang terinstall
                themes = [name for name in os.listdir(themes_dir) if os.path.isdir(os.path.join(themes_dir, name))]

                for theme in themes:
                    theme_dir = os.path.join(themes_dir, theme)

                    # Periksa versi tema
                    version = "Unknown"

                    # Cek dari file style.css
                    style_path = os.path.join(theme_dir, "style.css")
                    if os.path.exists(style_path):
                        with open(style_path, 'r', errors='ignore') as f:
                            content = f.read(1000)  # Hanya baca 1000 karakter pertama
                            version_match = re.search(r"Version:\s*([\d\.]+)", content)

                            if version_match:
                                version = version_match.group(1)

                    self.report["theme_vulnerabilities"].append({
                        "name": theme,
                        "version": version,
                        "status": "Perlu diverifikasi",
                        "vulnerabilities": "Tidak diketahui - Periksa di wpvulndb.com"
                    })

                # Tambahkan rekomendasi umum untuk tema
                self.report["recommendations"].append(
                    "Verifikasi keamanan semua tema yang terinstall secara teratur dan pastikan selalu diperbarui"
                )

                # Periksa tema default yang tidak digunakan
                default_themes = ["twentytwenty", "twentytwentyone", "twentytwentytwo", "twentytwentythree", "twentytwentyfour"]
                installed_default_themes = [theme for theme in themes if theme in default_themes]

                if len(installed_default_themes) > 1:
                    self.report["recommendations"].append(
                        f"Hapus tema default WordPress yang tidak digunakan: {', '.join(installed_default_themes[1:])}"
                    )

            except Exception as e:
                print(f"[-] Error saat memeriksa tema: {e}")

    def check_database_security(self):
        """Memeriksa keamanan database dari wp-config"""
        print("[+] Memeriksa keamanan database...")

        config_path = os.path.join(self.wp_path, "wp-config.php")

        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    content = f.read()

                    # Dapatkan informasi database
                    db_name_match = re.search(r"define\s*\(\s*['\"]DB_NAME['\"],\s*['\"](.*?)['\"]\s*\)", content)
                    db_user_match = re.search(r"define\s*\(\s*['\"]DB_USER['\"],\s*['\"](.*?)['\"]\s*\)", content)
                    db_password_match = re.search(r"define\s*\(\s*['\"]DB_PASSWORD['\"],\s*['\"](.*?)['\"]\s*\)", content)
                    db_host_match = re.search(r"define\s*\(\s*['\"]DB_HOST['\"],\s*['\"](.*?)['\"]\s*\)", content)

                    db_name = db_name_match.group(1) if db_name_match else "Unknown"
                    db_user = db_user_match.group(1) if db_user_match else "Unknown"
                    db_password = db_password_match.group(1) if db_password_match else "Unknown"
                    db_host = db_host_match.group(1) if db_host_match else "localhost"

                    # Evaluasi keamanan password
                    password_strength = "Lemah"
                    if len(db_password) >= 12 and re.search(r"[A-Z]", db_password) and re.search(r"[a-z]", db_password) and re.search(r"[0-9]", db_password) and re.search(r"[^A-Za-z0-9]", db_password):
                        password_strength = "Kuat"
                    elif len(db_password) >= 8 and re.search(r"[A-Za-z]", db_password) and re.search(r"[0-9]", db_password):
                        password_strength = "Sedang"

                    self.report["database_security"] = {
                        "db_name": db_name,
                        "db_user": db_user,
                        "db_password_length": len(db_password),
                        "db_password_strength": password_strength,
                        "db_host": db_host,
                        "using_remote_db": db_host != "localhost"
                    }

                    # Tambahkan rekomendasi
                    if password_strength == "Lemah":
                        self.report["recommendations"].append(
                            "Gunakan password database yang lebih kuat (minimal 12 karakter dengan kombinasi huruf besar, huruf kecil, angka, dan simbol)"
                        )

                    if db_user == "root":
                        self.report["recommendations"].append(
                            "Jangan gunakan user 'root' untuk koneksi database WordPress"
                        )

            except Exception as e:
                print(f"[-] Error saat memeriksa keamanan database: {e}")
                self.report["database_security"] = {"Error": str(e)}

    def generate_recommendations(self):
        """Menghasilkan rekomendasi keamanan tambahan"""
        print("[+] Menghasilkan rekomendasi keamanan tambahan...")

        # Rekomendasi umum
        general_recommendations = [
            "Aktifkan otentikasi dua faktor untuk semua pengguna (gunakan plugin seperti Two Factor Authentication)",
            "Aktifkan HTTPS dan arahkan semua traffic melalui koneksi terenkripsi",
            "Batasi jumlah percobaan login yang gagal (gunakan plugin seperti Limit Login Attempts)",
            "Pindahkan file wp-config.php ke direktori di atas root publik jika memungkinkan",
            "Nonaktifkan editor file di panel admin WordPress",
            "Mulai gunakan firewall aplikasi web (WAF) seperti Cloudflare atau Sucuri",
            "Perbarui WordPress, plugin, dan tema secara teratur ke versi terbaru"
        ]

        # Tambahkan rekomendasi umum jika belum ada
        for recommendation in general_recommendations:
            if recommendation not in self.report["recommendations"]:
               self.report["recommendations"].append(recommendation)

    def save_report(self):
        """Menyimpan laporan audit dalam format JSON"""
        with open(self.output_file, 'w') as f:
            json.dump(self.report, f, indent=4)


def main():
    print("=" * 70)
    print(" WordPress Security Audit Tool ")
    print("=" * 70)

    # Parse input parameter
    if len(sys.argv) > 1:
        # Jika berupa URL
        if sys.argv[1].startswith("http"):
            wp_url = sys.argv[1]
            wp_path = None

            # Pastikan URL diakhiri dengan /
            if not wp_url.endswith("/"):
                wp_url += "/"

            print(f"[+] Target URL: {wp_url}")
        else:
            # Jika berupa path lokal
            wp_url = None
            wp_path = sys.argv[1]
            print(f"[+] Target Path: {wp_path}")
    else:
        # Jika tidak ada parameter, minta input dari pengguna
        print("Pilih metode audit:")
        print("1. Audit situs WordPress online (URL)")
        print("2. Audit instalasi WordPress lokal (path)")

        choice = input("Pilihan Anda (1/2): ")

        if choice == "1":
            wp_url = input("Masukkan URL WordPress (contoh: https://example.com): ")

            # Pastikan URL diakhiri dengan /
            if not wp_url.endswith("/"):
                wp_url += "/"

            wp_path = None
        else:
            wp_path = input("Masukkan path instalasi WordPress lokal: ")
            wp_url = None

    # Jalankan audit
    audit = WordPressSecurityAudit(wp_url=wp_url, wp_path=wp_path)
    audit.run_audit()

    # Tampilkan temuan dan rekomendasi utama
    report_file = audit.output_file

    print("\n" + "=" * 70)
    print(" Temuan dan Rekomendasi Utama ")
    print("=" * 70)

    with open(report_file, 'r') as f:
        report = json.load(f)

        print(f"\n[+] Versi WordPress: {report['wordpress_version']}")

        # Tampilkan file sensitif yang terekspos
        if report['exposed_sensitive_files']:
            print("\n[!] File Sensitif Terekspos:")
            for file in report['exposed_sensitive_files']:
                print(f"  - {file['file']}")

        # Tampilkan direktori yang terbuka
        if report['open_directories']:
            print("\n[!] Direktori yang Terbuka:")
            for directory in report['open_directories']:
                print(f"  - {directory['directory']}")

        # Tampilkan rekomendasi
        print("\n[+] Rekomendasi Keamanan:")
        for i, recommendation in enumerate(report['recommendations'][:10], 1):  # Hanya tampilkan 10 rekomendasi teratas
            print(f"  {i}. {recommendation}")

        if len(report['recommendations']) > 10:
            print(f"  ... dan {len(report['recommendations']) - 10} rekomendasi lainnya.")

    print(f"\n[+] Laporan lengkap tersimpan di: {report_file}")


if __name__ == "__main__":
    main()
