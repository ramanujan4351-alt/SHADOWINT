#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║                    SHADOWINT - Advanced OSINT Framework              ║
║                        Ethical Security Tool v2.0                    ║
╚══════════════════════════════════════════════════════════════════════╝

Author: Security Researcher
License: MIT
Purpose: Open-source intelligence gathering for authorized security testing
"""

import argparse
import sys
import json
import os
import socket
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

class Colors:
    HEADER = Fore.CYAN
    SUCCESS = Fore.GREEN
    WARNING = Fore.YELLOW
    ERROR = Fore.RED
    INFO = Fore.BLUE
    DIM = Fore.LIGHTBLACK_EX
    BOLD = Style.BRIGHT

class ShadowInt:
    def __init__(self):
        self.results = {}
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = f"shadowint_results_{self.timestamp}"
        os.makedirs(self.output_dir, exist_ok=True)

    def banner(self):
        print(f"""{Fore.CYAN}
    ╔═══════════════════════════════════════════════════════════════╗
    ║  ███████╗██╗   ██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗  ║
    ║  ██╔════╝╚██╗ ██╔╝██╔════╝██╔═══██╗██╔══██╗██╔═══██╗██╔════╝  ║
    ║  █████╗   ╚████╔╝ █████╗  ██║   ██║██████╔╝██║   ██║███████╗  ║
    ║  ██╔══╝    ╚██╔╝  ██╔══╝  ██║   ██║██╔══██╗██║   ██║╚════██║  ║
    ║  ███████╗   ██║   ███████╗╚██████╔╝██║  ██║╚██████╔╝███████║  ║
    ║  ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝  ║
    ║              {Fore.WHITE}Advanced OSINT Framework v2.0{Fore.CYAN}                ║
    ╚═══════════════════════════════════════════════════════════════╝
        """)

    def save_results(self, module_name, data):
        self.results[module_name] = data
        filename = os.path.join(self.output_dir, f"{module_name}.json")
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        print(f"{Colors.DIM}[+] Results saved to {filename}")

    def print_header(self, text):
        print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*65}")
        print(f"{Colors.HEADER}{Colors.BOLD}  {text}")
        print(f"{Colors.HEADER}{Colors.BOLD}{'='*65}\n")

    def print_success(self, text):
        print(f"{Colors.SUCCESS}[✓] {text}")

    def print_error(self, text):
        print(f"{Colors.ERROR}[✗] {text}")

    def print_info(self, text):
        print(f"{Colors.INFO}[•] {text}")

    def print_warning(self, text):
        print(f"{Colors.WARNING}[!] {text}")

    def print_data(self, label, value, indent=2):
        print(f"{' '*indent}{Colors.DIM}{label}: {Fore.WHITE}{value}")

class DomainRecon:
    def __init__(self, si):
        self.si = si

    def run(self, target):
        self.si.print_header(f"DOMAIN RECONNAISSANCE: {target}")
        results = {'target': target, 'scan_time': str(datetime.now())}

        self._whois_lookup(target, results)
        self._dns_enumeration(target, results)
        self._port_scan(target, results)
        self._tech_fingerprint(target, results)
        self._subdomain_enum(target, results)

        self.si.save_results('domain_recon', results)
        return results

    def _whois_lookup(self, target, results):
        try:
            import whois
            self.si.print_info("Fetching WHOIS data...")
            w = whois.whois(target)
            results['whois'] = {
                'registrar': str(w.registrar) if w.registrar else 'N/A',
                'creation_date': str(w.creation_date) if w.creation_date else 'N/A',
                'expiration_date': str(w.expiration_date) if w.expiration_date else 'N/A',
                'updated_date': str(w.updated_date) if w.updated_date else 'N/A',
                'name_servers': list(w.name_servers) if w.name_servers else [],
                'emails': list(w.emails) if w.emails else [],
                'org': str(w.org) if w.org else 'N/A',
                'country': str(w.country) if hasattr(w, 'country') and w.country else 'N/A',
                'state': str(w.state) if hasattr(w, 'state') and w.state else 'N/A',
                'dnssec': str(w.dnssec) if hasattr(w, 'dnssec') else 'N/A'
            }
            self.si.print_success(f"WHOIS: {results['whois']['registrar']}")
            self.si.print_info(f"Created: {results['whois']['creation_date']}")
        except ImportError:
            self.si.print_error("Install whois: pip install python-whois")
        except Exception as e:
            self.si.print_error(f"WHOIS lookup failed: {e}")

    def _dns_enumeration(self, target, results):
        try:
            import dns.resolver
            self.si.print_info("Enumerating DNS records...")
            dns_records = {}
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'DKIM', 'DMARC', 'SPF', 'CAA']
            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(target, rtype, raise_on_no_answer=False)
                    records = [str(rdata).strip('"') for rdata in answers]
                    if records:
                        dns_records[rtype] = records
                        for rec in records:
                            self.si.print_data(rtype, rec)
                except:
                    pass
            results['dns'] = dns_records
        except ImportError:
            self.si.print_error("Install dnspython: pip install dnspython")
        except Exception as e:
            self.si.print_error(f"DNS enumeration failed: {e}")

    def _port_scan(self, target, results):
        try:
            import socket
            self.si.print_info("Scanning common ports...")
            ports = {
                21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
                80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
                445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
                1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
                5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
                27017: 'MongoDB', 11211: 'Memcached'
            }
            open_ports = []
            for port, service in ports.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    if sock.connect_ex((target, port)) == 0:
                        open_ports.append({'port': port, 'service': service})
                        self.si.print_success(f"Port {port}/tcp - {service} - OPEN")
                    sock.close()
                except:
                    pass
            results['open_ports'] = open_ports
            self.si.print_info(f"Scan complete: {len(open_ports)} open ports found")
        except Exception as e:
            self.si.print_error(f"Port scan failed: {e}")

    def _tech_fingerprint(self, target, results):
        try:
            import requests
            self.si.print_info("Fingerprinting web technologies...")
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            tech_info = {'web_server': 'Unknown', 'powered_by': [], 'tech_stack': []}
            
            try:
                r = requests.get(f"http://{target}", headers=headers, timeout=5, verify=False)
                resp_headers = dict(r.headers)
                
                if 'Server' in resp_headers:
                    tech_info['web_server'] = resp_headers['Server']
                    self.si.print_data("Server", resp_headers['Server'])
                if 'X-Powered-By' in resp_headers:
                    tech_info['powered_by'].append(resp_headers['X-Powered-By'])
                if 'X-AspNet-Version' in resp_headers:
                    tech_info['tech_stack'].append(f"ASP.NET {resp_headers['X-AspNet-Version']}")
                    
                tech_info['status_code'] = r.status_code
                tech_info['title'] = None
                try:
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(r.text, 'html.parser')
                    if soup.title:
                        tech_info['title'] = soup.title.string
                except:
                    pass
            except:
                pass
            results['tech_fingerprint'] = tech_info
        except ImportError:
            self.si.print_error("Install requests: pip install requests")
        except Exception as e:
            self.si.print_error(f"Tech fingerprint failed: {e}")

    def _subdomain_enum(self, target, results):
        try:
            import requests
            self.si.print_info("Enumerating subdomains...")
            common_subdomains = [
                'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test', ' staging',
                'api', 'shop', 'store', 'cdn', 'static', 'assets', 'img', 'images',
                'video', 'media', 'secure', 'login', 'portal', 'vpn', 'git', 'svn',
                'jenkins', 'ci', 'demo', 'docs', 'help', 'support', 'forum',
                'm', 'mobile', 'app', 'beta', 'alpha', 'db', 'database', 'mysql'
            ]
            found_subdomains = []
            for sub in common_subdomains:
                try:
                    hostname = f"{sub}.{target}"
                    ip = socket.gethostbyname(hostname)
                    found_subdomains.append({'subdomain': hostname, 'ip': ip})
                    self.si.print_success(f"Found: {hostname} -> {ip}")
                except:
                    pass
            results['subdomains'] = found_subdomains
        except Exception as e:
            self.si.print_error(f"Subdomain enum failed: {e}")

class EmailOSINT:
    def __init__(self, si):
        self.si = si

    def run(self, email):
        self.si.print_header(f"EMAIL OSINT: {email}")
        results = {'target': email, 'breaches': [], 'metadata': {}, 'social': []}

        self._breach_check(email, results)
        self._email_validation(email, results)
        self._email_reputation(email, results)

        self.si.save_results('email_osint', results)
        return results

    def _breach_check(self, email, results):
        try:
            import requests
            self.si.print_info("Checking breach databases (simulated)...")
            results['breaches'].append({
                'source': 'HaveIBeenPwned (API requires key)',
                'note': 'Get API key from haveibeenpwned.com for live checks',
                'alternative': 'Use hunter.io or similar for email discovery'
            })
            self.si.print_warning("Breach check requires API key for live results")
        except Exception as e:
            self.si.print_error(f"Breach check failed: {e}")

    def _email_validation(self, email, results):
        try:
            import socket
            import dns.resolver
            domain = email.split('@')[1]
            self.si.print_info(f"Validating {domain}...")
            
            mx_found = False
            try:
                answers = dns.resolver.resolve(domain, 'MX', raise_on_no_answer=False)
                mx_records = [str(rdata.exchange).rstrip('.') for rdata in answers]
                if mx_records:
                    results['metadata']['mail_servers'] = mx_records
                    results['metadata']['mx_valid'] = True
                    mx_found = True
                    self.si.print_success(f"MX Records: {mx_records}")
            except:
                results['metadata']['mx_valid'] = False
                
            if not mx_found:
                try:
                    socket.gethostbyname(domain)
                    results['metadata']['domain_exists'] = True
                except:
                    results['metadata']['domain_exists'] = False
                    self.si.print_error("Domain does not exist")
        except Exception as e:
            self.si.print_error(f"Email validation failed: {e}")

    def _email_reputation(self, email, results):
        results['metadata']['disposable'] = self._check_disposable(email)
        if results['metadata']['disposable']:
            self.si.print_warning("Disposable email detected!")
        else:
            self.si.print_success("Email appears to be legitimate")

    def _check_disposable(self, email):
        disposable_domains = ['tempmail.com', 'guerrillamail.com', 'mailinator.com', '10minutemail.com', 'throwaway.email']
        domain = email.split('@')[1].lower()
        return any(d in domain for d in disposable_domains)

class UsernameSearch:
    def __init__(self, si):
        self.si = si

    def run(self, username):
        self.si.print_header(f"USERNAME SEARCH: {username}")
        results = {'username': username, 'found': [], 'not_found': []}

        platforms = [
            ('GitHub', 'https://github.com/{}'),
            ('Twitter/X', 'https://twitter.com/{}'),
            ('Instagram', 'https://instagram.com/{}'),
            ('LinkedIn', 'https://linkedin.com/in/{}/'),
            ('Reddit', 'https://reddit.com/user/{}/'),
            ('YouTube', 'https://www.youtube.com/@{}'),
            ('TikTok', 'https://www.tiktok.com/@{}'),
            ('Pinterest', 'https://www.pinterest.com/{}/'),
            ('Tumblr', 'https://{}.tumblr.com/'),
            ('Medium', 'https://medium.com/@{}'),
            ('HackerNews', 'https://news.ycombinator.com/user?id={}'),
            ('Steam', 'https://steamcommunity.com/id/{}/'),
            ('Discord', 'https://discord.com/users/{}'),
            ('Telegram', 'https://t.me/{}'),
            ('Snapchat', 'https://www.snapchat.com/add/{}'),
            ('Twitch', 'https://www.twitch.tv/{}'),
            ('Spotify', 'https://open.spotify.com/user/{}'),
            ('SoundCloud', 'https://soundcloud.com/{}'),
            ('Vimeo', 'https://vimeo.com/{}'),
            ('Flickr', 'https://www.flickr.com/people/{}'),
            ('Dribbble', 'https://dribbble.com/{}'),
            ('Behance', 'https://www.behance.net/{}'),
            ('DeviantArt', 'https://www.deviantart.com/{}'),
            ('ProductHunt', 'https://www.producthunt.com/@{}'),
            ('Keybase', 'https://keybase.io/{}'),
            ('Mastodon', 'https://mastodon.social/@{}'),
            ('StackOverflow', 'https://stackoverflow.com/users/{}'),
            ('GitLab', 'https://gitlab.com/{}'),
            ('Bitbucket', 'https://bitbucket.org/{}/'),
            ('Replit', 'https://replit.com/@{}'),
        ]

        try:
            import requests
            for platform, url in platforms:
                try:
                    if 'github' in url or 'stackoverflow' in url:
                        r = requests.get(url.format(username), timeout=5)
                        if r.status_code == 200:
                            results['found'].append({'platform': platform, 'url': url.format(username)})
                            self.si.print_success(f"{platform}: FOUND")
                        else:
                            results['not_found'].append(platform)
                    else:
                        r = requests.head(url.format(username), timeout=5, allow_redirects=True)
                        if r.status_code == 200:
                            results['found'].append({'platform': platform, 'url': url.format(username)})
                            self.si.print_success(f"{platform}: FOUND")
                        else:
                            results['not_found'].append(platform)
                except:
                    results['not_found'].append(platform)
        except ImportError:
            self.si.print_error("Install requests: pip install requests")
        except Exception as e:
            self.si.print_error(f"Search failed: {e}")

        self.si.print_info(f"\nTotal: {len(results['found'])} found, {len(results['not_found'])} not found")
        self.si.save_results('username_search', results)
        return results

class ImageOSINT:
    def __init__(self, si):
        self.si = si

    def run(self, image_path):
        self.si.print_header(f"IMAGE FORENSICS: {image_path}")
        results = {'file': image_path, 'exif': {}, 'hashes': {}, 'metadata': {}}

        self._extract_exif(image_path, results)
        self._calculate_hashes(image_path, results)
        self._get_metadata(image_path, results)

        self.si.save_results('image_forensics', results)
        return results

    def _extract_exif(self, path, results):
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS
            self.si.print_info("Extracting EXIF metadata...")
            img = Image.open(path)
            exif_data = img._getexif()
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    results['exif'][str(tag)] = str(value)
                    self.si.print_data(str(tag), str(value)[:100])
            else:
                self.si.print_warning("No EXIF data found")
            results['metadata']['dimensions'] = f"{img.width}x{img.height}"
            results['metadata']['format'] = img.format
        except ImportError:
            self.si.print_error("Install Pillow: pip install Pillow")
        except Exception as e:
            self.si.print_error(f"EXIF extraction failed: {e}")

    def _calculate_hashes(self, path, results):
        import hashlib
        self.si.print_info("Calculating file hashes...")
        with open(path, 'rb') as f:
            data = f.read()
        results['hashes']['md5'] = hashlib.md5(data).hexdigest()
        results['hashes']['sha1'] = hashlib.sha1(data).hexdigest()
        results['hashes']['sha256'] = hashlib.sha256(data).hexdigest()
        results['hashes']['ssdeep'] = self._ssdeep_hash(data)
        self.si.print_data("MD5", results['hashes']['md5'])
        self.si.print_data("SHA1", results['hashes']['sha1'])
        self.si.print_data("SHA256", results['hashes']['sha256'][:64] + "...")

    def _ssdeep_hash(self, data):
        try:
            import ssdeep
            return ssdeep.hash(data)
        except:
            import hashlib
            return hashlib.md5(data).hexdigest()[:32] + " (ssdeep unavailable)"

    def _get_metadata(self, path, results):
        import os
        stats = os.stat(path)
        results['metadata']['size_bytes'] = stats.st_size
        results['metadata']['size_human'] = self._human_size(stats.st_size)
        results['metadata']['created'] = str(datetime.fromtimestamp(stats.st_ctime))
        results['metadata']['modified'] = str(datetime.fromtimestamp(stats.st_mtime))
        self.si.print_data("Size", results['metadata']['size_human'])
        self.si.print_data("Created", results['metadata']['created'])

    def _human_size(self, bytes):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes < 1024:
                return f"{bytes:.2f} {unit}"
            bytes /= 1024
        return f"{bytes:.2f} TB"

class PhoneOSINT:
    def __init__(self, si):
        self.si = si

    def run(self, phone):
        self.si.print_header(f"PHONE OSINT: {phone}")
        results = {'phone': phone, 'info': {}, 'valid': False}

        try:
            import phonenumbers
            from phonenumbers import carrier, timezone, geocoder
            self.si.print_info("Analyzing phone number...")
            parsed = phonenumbers.parse(phone, None)
            results['valid'] = phonenumbers.is_valid_number(parsed)
            
            info = {
                'country_code': phonenumbers.region_code_for_number(parsed),
                'country': self._get_country_name(phonenumbers.region_code_for_number(parsed)),
                'location': geocoder.description_for_number(parsed, 'en') or 'Unknown',
                'carrier': carrier.name_for_number(parsed, 'en') or 'Unknown',
                'timezones': [str(tz) for tz in timezone.time_zones_for_number(parsed)],
                'type': self._phone_type(parsed),
                'international': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                'e164': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
            }
            results['info'] = info
            
            self.si.print_data("Valid", str(results['valid']))
            self.si.print_data("Country", f"{info['country']} ({info['country_code']})")
            self.si.print_data("Location", info['location'])
            self.si.print_data("Carrier", info['carrier'])
            self.si.print_data("Timezones", ', '.join(info['timezones']))
            self.si.print_data("Type", info['type'])
        except ImportError:
            self.si.print_error("Install phonenumbers: pip install phonenumbers")
        except Exception as e:
            self.si.print_error(f"Phone analysis failed: {e}")

        self.si.save_results('phone_osint', results)
        return results

    def _phone_type(self, parsed):
        import phonenumbers
        types = {
            phonenumbers.MOBILE: 'Mobile',
            phonenumbers.FIXED_LINE: 'Fixed Line',
            phonenumbers.TOLL_FREE: 'Toll Free',
            phonenumbers.VOIP: 'VoIP',
            phonenumbers.PREMIUM_RATE: 'Premium Rate',
        }
        return types.get(phonenumbers.number_type(parsed), 'Unknown')

    def _get_country_name(self, code):
        countries = {'US': 'United States', 'GB': 'United Kingdom', 'IN': 'India', 
                      'DE': 'Germany', 'FR': 'France', 'AU': 'Australia', 'CA': 'Canada'}
        return countries.get(code, code)

class NetworkScan:
    def __init__(self, si):
        self.si = si

    def run(self, target):
        self.si.print_header(f"NETWORK SCAN: {target}")
        results = {'target': target, 'services': [], 'headers': {}, 'ssl': {}}

        self._service_enum(target, results)
        self._http_analysis(target, results)
        self._ssl_check(target, results)

        self.si.save_results('network_scan', results)
        return results

    def _service_enum(self, target, results):
        import socket
        self.si.print_info("Enumerating services...")
        ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
            1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
            27017: 'MongoDB', 11211: 'Memcached'
        }
        for port, service in ports.items():
            try:
                sock = socket.socket()
                sock.settimeout(1)
                if sock.connect_ex((target, port)) == 0:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    try:
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()[:100]
                    except:
                        banner = "Service detected"
                    results['services'].append({'port': port, 'service': service, 'banner': banner})
                    self.si.print_success(f"{port}/tcp {service}: {banner}")
                sock.close()
            except:
                pass

    def _http_analysis(self, target, results):
        try:
            import requests
            self.si.print_info("Analyzing HTTP headers...")
            headers = {'User-Agent': 'ShadowInt-Scanner/1.0'}
            try:
                r = requests.get(f"http://{target}", headers=headers, timeout=5, verify=False)
                results['headers'] = dict(r.headers)
                for k, v in r.headers.items():
                    self.si.print_data(k, v[:80])
            except:
                pass
        except ImportError:
            pass

    def _ssl_check(self, target, results):
        import socket
        self.si.print_info("Checking SSL/TLS...")
        try:
            context = socket.socket()
            context.settimeout(3)
            context.connect((target, 443))
            ssl_data = context.recv(1024).decode('utf-8', errors='ignore')[:100]
            results['ssl']['detected'] = True
            self.si.print_success("SSL/TLS available")
        except:
            results['ssl']['detected'] = False
            self.si.print_info("No SSL detected on port 443")

def main():
    si = ShadowInt()
    si.banner()
    
    parser = argparse.ArgumentParser(
        description='\nSHADOWINT - Advanced OSINT Framework for Ethical Security Testing',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--domain', help='Target domain for reconnaissance')
    parser.add_argument('--email', help='Email address for OSINT')
    parser.add_argument('--username', help='Username to search across platforms')
    parser.add_argument('--phone', help='Phone number for OSINT')
    parser.add_argument('--image', help='Image file for forensics')
    parser.add_argument('--network', help='Network target for scanning')
    parser.add_argument('--all', action='store_true', help='Run all modules')
    parser.add_argument('--target', help='Target for --all mode')
    parser.add_argument('--output', help='Output directory', default=None)

    args = parser.parse_args()

    if args.output:
        si.output_dir = args.output
        os.makedirs(si.output_dir, exist_ok=True)

    if len(sys.argv) == 1:
        parser.print_help()
        print(f"\n{Colors.HEADER}Examples:{Colors.DIM}")
        print("  python shadowint.py --domain example.com")
        print("  python shadowint.py --email target@email.com")
        print("  python shadowint.py --username johndoe")
        print("  python shadowint.py --all --target example.com")
        sys.exit(1)

    print(f"\n{Colors.WARNING}⚠ LEGAL NOTICE: Use only on systems you own or have written authorization to test ⚠\n")

    if args.all and args.target:
        dr = DomainRecon(si)
        dr.run(args.target)
        es = EmailOSINT(si)
        es.run(f"admin@{args.target}")
        ns = NetworkScan(si)
        ns.run(args.target)

    if args.domain:
        DomainRecon(si).run(args.domain)

    if args.email:
        EmailOSINT(si).run(args.email)

    if args.username:
        UsernameSearch(si).run(args.username)

    if args.phone:
        PhoneOSINT(si).run(args.phone)

    if args.image:
        ImageOSINT(si).run(args.image)

    if args.network:
        NetworkScan(si).run(args.network)

    print(f"\n{Colors.HEADER}{'='*65}")
    print(f"{Colors.SUCCESS}✓ Scan complete! Results: {si.output_dir}/")
    print(f"{Colors.HEADER}{'='*65}\n")

if __name__ == '__main__':
    main()
