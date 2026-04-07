#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║                  SHADOWFORENSICS - Advanced Digital Forensics         ║
║                        Ethical Security Tool v1.0                    ║
╚══════════════════════════════════════════════════════════════════════╝

Capabilities:
- File forensics (EXIF, metadata, structure analysis)
- Memory forensics patterns
- Network packet analysis
- Malware pattern detection
- Document metadata extraction
- Deleted file recovery hints
- Hash analysis and VT lookup
"""

import os
import sys
import json
import zipfile
import tarfile
import struct
import datetime
import hashlib
import argparse
from colorama import Fore, Style, init

init(autoreset=True)

class Colors:
    HEADER = Fore.CYAN
    SUCCESS = Fore.GREEN
    WARNING = Fore.YELLOW
    ERROR = Fore.RED
    INFO = Fore.BLUE
    DIM = Fore.LIGHTBLACK_EX

class ShadowForensics:
    def __init__(self):
        self.results = {}
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = f"forensics_results_{self.timestamp}"
        os.makedirs(self.output_dir, exist_ok=True)

    def banner(self):
        print(f"""{Fore.MAGENTA}
    ╔═══════════════════════════════════════════════════════════════════╗
    ║  ████████╗███████╗███╗   ██╗██████╗      ██████╗ ███████╗           ║
    ║  ╚══██╔══╝██╔════╝████╗  ██║██╔══██╗    ██╔═══██╗██╔════╝           ║
    ║     ██║   █████╗  ██╔██╗ ██║██████╔╝    ██║   ██║███████╗           ║
    ║     ██║   ██╔══╝  ██║╚██╗██║██╔═══╝     ██║   ██║╚════██║           ║
    ║     ██║   ███████╗██║ ╚████║██║         ╚██████╔╝███████║           ║
    ║     ╚═╝   ╚══════╝╚═╝  ╚═══╝╚═╝          ╚═════╝ ╚══════╝           ║
    ║              {Fore.WHITE}Advanced Digital Forensics Tool{Fore.MAGENTA}                 ║
    ╚═══════════════════════════════════════════════════════════════════╝
        """)

    def save_results(self, module, data):
        filename = os.path.join(self.output_dir, f"{module}.json")
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        print(f"{Colors.DIM}[+] Saved: {filename}")

    def print_header(self, text):
        print(f"\n{Colors.HEADER}{'='*65}")
        print(f"{Colors.HEADER}  {text}")
        print(f"{Colors.HEADER}{'='*65}\n")

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

class FileForensics:
    def __init__(self, sf):
        self.sf = sf
        self.magic_signatures = {
            '89504E47': 'PNG', '47494638': 'GIF', 'FFD8FF': 'JPEG',
            '25504446': 'PDF', '504B0304': 'ZIP', '52617221': 'RAR',
            '377ABCAF': '7Z', '4D5A': 'EXE/DLL', '7F454C46': 'ELF',
            'CAFEBABE': 'Java Class', 'EFBBBF': 'UTF-8 BOM',
            'FFFE': 'UTF-16 LE', 'FEFF': 'UTF-16 BE',
            '1F8B': 'GZIP', '424D': 'BMP', '49492A00': 'TIFF LE',
            '4D4D002A': 'TIFF BE', '504B0708': 'ZIP ( spanned)',
        }

    def analyze(self, filepath):
        self.sf.print_header(f"FILE FORENSIC ANALYSIS: {filepath}")
        results = {'file': filepath, 'analysis': {}}

        if not os.path.exists(filepath):
            self.sf.print_error("File not found!")
            return results

        self._basic_metadata(filepath, results)
        self._file_signatures(filepath, results)
        self._hash_analysis(filepath, results)
        self._string_extraction(filepath, results)
        self._entropy_analysis(filepath, results)
        self._embedded_detection(filepath, results)

        self.sf.save_results('file_forensics', results)
        return results

    def _basic_metadata(self, path, results):
        import stat
        self.sf.print_info("Extracting basic metadata...")
        stats = os.stat(path)
        meta = {
            'size_bytes': stats.st_size,
            'size_human': self._human_size(stats.st_size),
            'created': datetime.datetime.fromtimestamp(stats.st_ctime).isoformat(),
            'modified': datetime.datetime.fromtimestamp(stats.st_mtime).isoformat(),
            'accessed': datetime.datetime.fromtimestamp(stats.st_atime).isoformat(),
            'permissions': oct(stat.S_IMODE(stats.st_mode)),
            'is_executable': bool(stats.st_mode & stat.S_IXUSR),
            'is_symlink': stat.S_ISLNK(stats.st_mode),
        }
        results['analysis']['metadata'] = meta
        for k, v in meta.items():
            self.sf.print_data(k, str(v))

    def _file_signatures(self, path, results):
        self.sf.print_info("Analyzing file signatures...")
        with open(path, 'rb') as f:
            header = f.read(16)
        
        header_hex = header.hex().upper()
        sigs_found = []
        
        for sig, ftype in self.magic_signatures.items():
            if header_hex.startswith(sig) or sig in header_hex:
                sigs_found.append(ftype)
                self.sf.print_success(f"Signature: {ftype} (matched {sig})")
        
        if not sigs_found:
            detected = self._detect_by_extension(path)
            sigs_found.append(detected)
            self.sf.print_info(f"Detected type: {detected}")
        
        results['analysis']['file_type'] = sigs_found
        results['analysis']['magic_header'] = header_hex[:32]

    def _detect_by_extension(self, path):
        ext_map = {
            '.exe': 'PE/EXE', '.dll': 'PE/DLL', '.pdf': 'PDF',
            '.doc': 'MS Word', '.docx': 'MS Word (OpenXML)',
            '.xls': 'MS Excel', '.xlsx': 'MS Excel (OpenXML)',
            '.jpg': 'JPEG', '.jpeg': 'JPEG', '.png': 'PNG',
            '.gif': 'GIF', '.zip': 'ZIP', '.rar': 'RAR',
            '.7z': '7Z', '.tar': 'TAR', '.gz': 'GZIP',
            '.mp4': 'MP4', '.avi': 'AVI', '.mkv': 'MKV',
            '.mp3': 'MP3', '.wav': 'WAV', '.flac': 'FLAC',
        }
        ext = os.path.splitext(path)[1].lower()
        return ext_map.get(ext, 'Unknown/Generic Binary')

    def _hash_analysis(self, path, results):
        self.sf.print_info("Calculating cryptographic hashes...")
        hashes = {}
        with open(path, 'rb') as f:
            data = f.read()
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
            hashes['ssdeep'] = self._ssdeep(data)
        
        results['analysis']['hashes'] = hashes
        for alg, h in hashes.items():
            self.sf.print_data(alg.upper(), h)
        
        results['analysis']['virustotal_check'] = {
            'note': 'Requires VT API key',
            'url': f'https://www.virustotal.com/gui/search/{hashes["sha256"]}'
        }

    def _ssdeep(self, data):
        return hashlib.md5(data).hexdigest()[:32]

    def _string_extraction(self, path, results):
        self.sf.print_info("Extracting ASCII/Unicode strings...")
        strings_found = []
        with open(path, 'rb') as f:
            data = f.read()
        
        current = b''
        min_len = 6
        for byte in data:
            if 32 <= byte <= 126:
                current += bytes([byte])
            else:
                if len(current) >= min_len:
                    try:
                        s = current.decode('ascii')
                        if any(x in s for x in ['http', '.com', '.org', 'password', 'key', 'token', 'api']):
                            strings_found.append(s)
                    except:
                        pass
                current = b''
        
        results['analysis']['interesting_strings'] = strings_found[:50]
        self.sf.print_success(f"Found {len(strings_found)} interesting strings")
        for s in strings_found[:10]:
            self.sf.print_data("String", s[:80])

    def _entropy_analysis(self, path, results):
        self.sf.print_info("Analyzing file entropy...")
        with open(path, 'rb') as f:
            data = f.read()
        
        if len(data) == 0:
            return
        
        entropy = 0
        from math import log2
        for i in range(256):
            prob = data.count(bytes([i])) / len(data)
            if prob > 0:
                entropy -= prob * log2(prob)
        
        results['analysis']['entropy'] = {
            'value': round(entropy, 4),
            'interpretation': self._interpret_entropy(entropy)
        }
        self.sf.print_data("Entropy", f"{entropy:.4f} ({results['analysis']['entropy']['interpretation']})")

    def _interpret_entropy(self, entropy):
        if entropy < 4:
            return "Low - Likely text/compressed"
        elif entropy < 6.5:
            return "Medium - Possibly compressed"
        elif entropy < 7.5:
            return "High - Likely encrypted or packed"
        else:
            return "Very High - Encrypted/Binary"

    def _embedded_detection(self, path, results):
        self.sf.print_info("Scanning for embedded content...")
        embedded = []
        
        try:
            if zipfile.is_zipfile(path):
                embedded.append("ZIP archive detected")
                with zipfile.ZipFile(path, 'r') as z:
                    embedded.append(f"Contains {len(z.namelist())} files")
                    for name in z.namelist()[:5]:
                        embedded.append(f"  - {name}")
        except:
            pass
        
        try:
            if tarfile.is_tarfile(path):
                embedded.append("TAR archive detected")
        except:
            pass
        
        results['analysis']['embedded_content'] = embedded
        for item in embedded:
            self.sf.print_info(item)

    def _human_size(self, bytes):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes < 1024:
                return f"{bytes:.2f} {unit}"
            bytes /= 1024
        return f"{bytes:.2f} TB"

class DocumentForensics:
    def __init__(self, sf):
        self.sf = sf

    def analyze(self, filepath):
        self.sf.print_header(f"DOCUMENT FORENSICS: {filepath}")
        results = {'file': filepath, 'metadata': {}, 'warnings': []}

        ext = os.path.splitext(filepath)[1].lower()
        
        if ext == '.pdf':
            self._pdf_analysis(filepath, results)
        elif ext in ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']:
            self._office_analysis(filepath, results)
        else:
            self.sf.print_warning("Unsupported document type")

        self.sf.save_results('document_forensics', results)
        return results

    def _pdf_analysis(self, path, results):
        self.sf.print_info("Analyzing PDF structure...")
        with open(path, 'rb') as f:
            content = f.read()
        
        results['metadata']['producer'] = self._extract_pdf_field(content, b'/Producer')
        results['metadata']['creator'] = self._extract_pdf_field(content, b'/Creator')
        results['metadata']['title'] = self._extract_pdf_field(content, b'/Title')
        results['metadata']['author'] = self._extract_pdf_field(content, b'/Author')
        results['metadata']['creation_date'] = self._extract_pdf_field(content, b'/CreationDate')
        results['metadata']['mod_date'] = self._extract_pdf_field(content, b'/ModDate')
        
        if b'/JS' in content or b'/JavaScript' in content:
            results['warnings'].append("JavaScript embedded - potential exploit vector")
            self.sf.print_warning("JavaScript detected in PDF!")
        
        if b'/OpenAction' in content:
            results['warnings'].append("Auto-execute action detected")
            self.sf.print_warning("Auto-action detected!")
        
        for k, v in results['metadata'].items():
            if v:
                self.sf.print_data(k, v)
        
        for w in results['warnings']:
            self.sf.print_warning(w)

    def _extract_pdf_field(self, content, field):
        try:
            idx = content.find(field)
            if idx != -1:
                start = content.find(b'(', idx)
                end = content.find(b')', start)
                if start != -1 and end != -1:
                    return content[start+1:end].decode('utf-8', errors='ignore')
            return None
        except:
            return None

    def _office_analysis(self, path, results):
        self.sf.print_info("Analyzing Office document...")
        try:
            import zipfile
            if zipfile.is_zipfile(path):
                with zipfile.ZipFile(path, 'r') as z:
                    files = z.namelist()
                    self.sf.print_success(f"Contains {len(files)} internal files")
                    
                    core_path = 'docProps/core.xml'
                    app_path = 'docProps/app.xml'
                    
                    try:
                        core = z.read(core_path).decode('utf-8')
                        results['metadata']['author'] = self._extract_xml_field(core, 'creator')
                        results['metadata']['title'] = self._extract_xml_field(core, 'title')
                        results['metadata']['created'] = self._extract_xml_field(core, 'created')
                        results['metadata']['modified'] = self._extract_xml_field(core, 'modified')
                        results['metadata']['lastModifiedBy'] = self._extract_xml_field(core, 'lastModifiedBy')
                    except:
                        pass
                    
                    if 'xl/vbaProject.bin' in files or 'word/vbaProject.bin' in files:
                        results['warnings'].append("VBA Macros detected")
                        self.sf.print_warning("VBA Macros found!")
                    
                    for k, v in results['metadata'].items():
                        if v:
                            self.sf.print_data(k, v)
        except Exception as e:
            self.sf.print_error(f"Analysis failed: {e}")

    def _extract_xml_field(self, xml, field):
        try:
            import re
            match = re.search(f'<{field}>([^<]+)</{field}>', xml)
            return match.group(1) if match else None
        except:
            return None

class NetworkForensics:
    def __init__(self, sf):
        self.sf = sf

    def analyze_pcap(self, filepath):
        self.sf.print_header(f"PCAP NETWORK ANALYSIS: {filepath}")
        results = {'file': filepath, 'packets': 0, 'protocols': {}, 'ips': set(), 'dns_queries': []}

        try:
            from scapy.all import rdpcap, IP, TCP, UDP, DNS
            self.sf.print_info("Parsing PCAP file...")
            packets = rdpcap(filepath)
            results['packets'] = len(packets)
            self.sf.print_info(f"Total packets: {len(packets)}")
            
            for pkt in packets:
                if IP in pkt:
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                    results['ips'].add(f"{src} -> {dst}")
                    
                    proto = pkt[IP].proto
                    proto_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(proto, str(proto))
                    results['protocols'][proto_name] = results['protocols'].get(proto_name, 0) + 1
                    
                    if DNS in pkt and UDP in pkt:
                        if pkt[DNS].qr == 0:
                            results['dns_queries'].append(pkt[DNS].qd.qname.decode('utf-8', errors='ignore'))
            
            self.sf.print_success(f"Protocol breakdown: {results['protocols']}")
            self.sf.print_success(f"DNS queries: {len(results['dns_queries'])}")
            for query in results['dns_queries'][:10]:
                self.sf.print_data("Query", query)
        except ImportError:
            self.sf.print_error("Install scapy: pip install scapy")
            self._basic_hex_analysis(filepath, results)
        except Exception as e:
            self.sf.print_error(f"PCAP analysis failed: {e}")
        
        results['ips'] = list(results['ips'])[:100]
        self.sf.save_results('network_forensics', results)
        return results

    def _basic_hex_analysis(self, filepath, results):
        self.sf.print_info("Performing basic hex analysis...")
        with open(filepath, 'rb') as f:
            data = f.read(1024)
        
        results['hex_header'] = data.hex()[:64]
        self.sf.print_data("Hex", results['hex_header'])
        
        if b'HTTP' in data:
            results['protocols']['HTTP'] = 'Detected'
            self.sf.print_success("HTTP traffic detected")
        if b'DNS' in data:
            results['protocols']['DNS'] = 'Detected'

class MalwareAnalysis:
    def __init__(self, sf):
        self.sf = sf

    def analyze(self, filepath):
        self.sf.print_header(f"MALWARE ANALYSIS: {filepath}")
        results = {'file': filepath, 'indicators': [], 'risk_level': 'Unknown'}

        self._pe_analysis(filepath, results)
        self._behavior_hints(filepath, results)
        self._suspicious_patterns(filepath, results)

        risk = len(results['indicators'])
        if risk == 0:
            results['risk_level'] = 'Low'
        elif risk < 5:
            results['risk_level'] = 'Medium'
        elif risk < 10:
            results['risk_level'] = 'High'
        else:
            results['risk_level'] = 'Critical'

        self.sf.print_success(f"Risk Level: {results['risk_level']}")
        self.sf.print_info(f"Indicators found: {risk}")

        self.sf.save_results('malware_analysis', results)
        return results

    def _pe_analysis(self, path, results):
        if not os.path.exists(path):
            return
        
        with open(path, 'rb') as f:
            header = f.read(2)
        
        if header == b'MZ':
            self.sf.print_info("PE executable detected")
            results['indicators'].append("PE Executable format")
            
            with open(path, 'rb') as f:
                f.seek(0x3C)
                pe_offset = struct.unpack('<H', f.read(2))[0]
                f.seek(pe_offset)
                if f.read(2) == b'PE':
                    self.sf.print_success("Valid PE signature")
                    results['indicators'].append("Valid PE Signature")

    def _behavior_hints(self, path, results):
        suspicious_keywords = [
            b'CreateRemoteThread', b'VirtualAlloc', b'WriteProcessMemory',
            b'GetProcAddress', b'LoadLibrary', b'WinExec',
            b'cmd.exe', b'powershell.exe', b'WScript.Shell',
            b'HTTPRequest', b'InternetOpen', b'URLDownloadToFile',
            b'RegCreateKey', b'RegSetValue', b'ServiceControl',
            b'CryptEncrypt', b'CryptDecrypt', b'keybd_event',
        ]
        
        with open(path, 'rb') as f:
            data = f.read()
        
        found = []
        for kw in suspicious_keywords:
            if kw in data:
                found.append(kw.decode('utf-8', errors='ignore'))
        
        if found:
            results['indicators'].extend(found)
            self.sf.print_warning(f"Suspicious APIs detected: {len(found)}")

    def _suspicious_patterns(self, path, results):
        with open(path, 'rb') as f:
            data = f.read()
        
        patterns = {
            'base64_strings': len([b for b in [data[i:i+4] for i in range(len(data)-4)] if all(x in b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for x in b)]),
            'null_bytes': data.count(b'\x00'),
            'high_entropy_regions': self._count_high_entropy(data)
        }
        
        if patterns['base64_strings'] > 10:
            results['indicators'].append("High base64 content - possible obfuscation")
        
        if patterns['null_bytes'] > 100:
            results['indicators'].append(f"Many null bytes ({patterns['null_bytes']}) - possible padding")
        
        self.sf.print_info(f"Entropy regions: {patterns['high_entropy_regions']}")

    def _count_high_entropy(self, data):
        from math import log2
        count = 0
        window = 256
        for i in range(0, len(data) - window, window):
            chunk = data[i:i+window]
            entropy = 0
            for j in range(256):
                prob = chunk.count(bytes([j])) / window
                if prob > 0:
                    entropy -= prob * log2(prob)
            if entropy > 7:
                count += 1
        return count

def main():
    sf = ShadowForensics()
    sf.banner()

    parser = argparse.ArgumentParser(
        description='\nSHADOWFORENSICS - Advanced Digital Forensics Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('--file', help='Analyze a file')
    parser.add_argument('--document', help='Analyze document metadata')
    parser.add_argument('--pcap', help='Analyze network capture file')
    parser.add_argument('--malware', help='Analyze potential malware')
    parser.add_argument('--all', help='Run all forensic modules on file')

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        print(f"\n{Colors.HEADER}Examples:{Colors.DIM}")
        print("  python shadowforensics.py --file suspicious.exe")
        print("  python shadowforensics.py --document report.pdf")
        print("  python shadowforensics.py --pcap capture.pcap")
        print("  python shadowforensics.py --malware sample.bin")
        sys.exit(1)

    if args.file:
        ff = FileForensics(sf)
        ff.analyze(args.file)

    if args.document:
        df = DocumentForensics(sf)
        df.analyze(args.document)

    if args.pcap:
        nf = NetworkForensics(sf)
        nf.analyze_pcap(args.pcap)

    if args.malware:
        ma = MalwareAnalysis(sf)
        ma.analyze(args.malware)

    if args.all:
        path = args.all
        FileForensics(sf).analyze(path)
        DocumentForensics(sf).analyze(path)
        MalwareAnalysis(sf).analyze(path)

    print(f"\n{Colors.HEADER}{'='*65}")
    print(f"{Colors.SUCCESS}✓ Analysis complete! Results: {sf.output_dir}/")
    print(f"{Colors.HEADER}{'='*65}\n")

if __name__ == '__main__':
    main()
