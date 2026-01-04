# patterns.py - Detection patterns for DorkStrike PRO

import re
import math
import hashlib
import base58
import ecdsa
from Crypto.Hash import keccak
from typing import List, Dict, Any, Optional, Tuple

# ============================================
# DORK KEYWORDS - простые списки для поиска
# ============================================
DORK_KEYWORDS = {
    'extensions': [
        '.env', '.config.php', '.backup.sql', '.sql', '.db', '.zip', 
        '.tar.gz', '.bak', '.old', '.json', '.yml', '.yaml', '.ini', 
        '.conf', '.cnf', '.key', '.pem', '.crt', '.p12', '.pfx', 
        '.jks', '.keystore', '.dump', '.backup', '.log', '.txt', 
        '.csv', '.out', '.save', '.tmp', '.orig', '.swp', '.cfg', 
        '.config', '.properties'
    ],
    'keywords': [
        'config', 'backup', 'database', 'dump', 'secret', 'key', 
        'token', 'api', 'password', 'admin', 'login', 'dashboard', 
        'cpanel', 'wp-admin', 'pma', 'phpmyadmin', 'env', 'credentials'
    ],
    'paths': [
        'admin', 'backup', 'tmp', 'old', 'test', 'dev', 'staging', 
        'debug', 'config', 'logs', 'archive', 'dump', 'export', 
        'private', 'secret', 'keys', 'tokens'
    ]
}

# ============================================
# REGEX PATTERNS - только для поиска в тексте
# ============================================

def calculate_shannon_entropy(string: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not string:
        return 0.0

    entropy = 0.0
    length = len(string)
    char_counts = {}

    for char in string:
        char_counts[char] = char_counts.get(char, 0) + 1

    for count in char_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy

def is_valid_btc_address(address: str) -> bool:
    """Validate Bitcoin address with checksum."""
    try:
        decoded = base58.b58decode(address)
        if len(decoded) != 25:
            return False
        # Check version byte and checksum
        version = decoded[0]
        checksum = decoded[-4:]
        hash_data = decoded[:-4]
        calculated_checksum = hashlib.sha256(hashlib.sha256(hash_data).digest()).digest()[:4]
        return checksum == calculated_checksum and version in [0, 5]  # P2PKH or P2SH
    except:
        return False

def is_valid_eth_address(address: str) -> bool:
    """Validate Ethereum address with EIP-55 checksum."""
    if not re.match(r'^0x[a-fA-F0-9]{40}$', address):
        return False

    # EIP-55 checksum validation using keccak-256
    address_no_prefix = address[2:]
    address_lower = address_no_prefix.lower()

    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(address_lower.encode('utf-8'))
    hash_addr = keccak_hash.hexdigest()

    for i, char in enumerate(address_no_prefix):
        if int(hash_addr[i], 16) >= 8:
            if char.islower():
                return False
        else:
            if char.isupper():
                return False
    return True

def is_valid_xrp_address(address: str) -> bool:
    """Validate Ripple address with checksum."""
    if not re.match(r'^r[a-zA-Z0-9]{24,34}$', address):
        return False

    try:
        # Ripple uses base58 with different alphabet
        ripple_alphabet = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz'
        decoded = base58.b58decode(address, alphabet=ripple_alphabet)
        if len(decoded) != 25:
            return False
        # Check checksum
        checksum = decoded[-4:]
        hash_data = decoded[:-4]
        calculated_checksum = hashlib.sha256(hashlib.sha256(hash_data).digest()).digest()[:4]
        return checksum == calculated_checksum
    except:
        return False

def is_valid_ltc_address(address: str) -> bool:
    """Validate Litecoin address with checksum."""
    try:
        decoded = base58.b58decode(address)
        if len(decoded) != 25:
            return False
        version = decoded[0]
        checksum = decoded[-4:]
        hash_data = decoded[:-4]
        calculated_checksum = hashlib.sha256(hashlib.sha256(hash_data).digest()).digest()[:4]
        return checksum == calculated_checksum and version in [48, 50]  # LTC versions
    except:
        return False

def is_valid_doge_address(address: str) -> bool:
    """Validate Dogecoin address with checksum."""
    try:
        decoded = base58.b58decode(address)
        if len(decoded) != 25:
            return False
        version = decoded[0]
        checksum = decoded[-4:]
        hash_data = decoded[:-4]
        calculated_checksum = hashlib.sha256(hashlib.sha256(hash_data).digest()).digest()[:4]
        return checksum == calculated_checksum and version == 30  # DOGE version
    except:
        return False

def is_valid_bch_address(address: str) -> bool:
    """Validate Bitcoin Cash address."""
    # BCH uses the same format as BTC
    return is_valid_btc_address(address)

def is_valid_dash_address(address: str) -> bool:
    """Validate Dash address with checksum."""
    try:
        decoded = base58.b58decode(address)
        if len(decoded) != 25:
            return False
        version = decoded[0]
        checksum = decoded[-4:]
        hash_data = decoded[:-4]
        calculated_checksum = hashlib.sha256(hashlib.sha256(hash_data).digest()).digest()[:4]
        return checksum == calculated_checksum and version in [76, 16]  # DASH versions
    except:
        return False

def is_valid_zec_address(address: str) -> bool:
    """Validate Zcash address with checksum."""
    try:
        decoded = base58.b58decode(address)
        if len(decoded) != 25:
            return False
        version = decoded[0]
        checksum = decoded[-4:]
        hash_data = decoded[:-4]
        calculated_checksum = hashlib.sha256(hashlib.sha256(hash_data).digest()).digest()[:4]
        return checksum == calculated_checksum and version in [28, 184]  # ZEC t1/t3 versions
    except:
        return False

# ============================================
# OPTIONAL VALIDATION FUNCTIONS
# Эти функции сохранены для опциональной верификации,
# но больше не используются в основном потоке analyze_response
# ============================================

def validate_crypto_pattern_optional(pattern_name: str, match: str) -> Tuple[bool, str]:
    """
    OPTIONAL: Validate crypto wallet/address patterns with checksums.
    This function is kept for optional verification but not used in main flow.
    """
    is_valid = True
    if pattern_name == "BTC" and (match.startswith(('1', '3')) or match.startswith('bc1')):
        is_valid = is_valid_btc_address(match)
    elif pattern_name == "ETH" and match.startswith('0x'):
        is_valid = is_valid_eth_address(match)
    elif pattern_name == "XRP" and match.startswith('r'):
        is_valid = is_valid_xrp_address(match)
    elif pattern_name == "LTC" and match.startswith(('L', 'M')):
        is_valid = is_valid_ltc_address(match)
    elif pattern_name == "DOGE" and match.startswith('D'):
        is_valid = is_valid_doge_address(match)
    elif pattern_name == "BCH" and match.startswith(('1', '3')):
        is_valid = is_valid_bch_address(match)
    elif pattern_name == "DASH" and match.startswith('X'):
        is_valid = is_valid_dash_address(match)
    elif pattern_name == "ZEC" and match.startswith(('t1', 't3')):
        is_valid = is_valid_zec_address(match)
    elif len(match) > 10:
        entropy = calculate_shannon_entropy(match)
        if entropy > 4.0:
            return True, "Format valid"
        return False, "Low entropy"

    if is_valid:
        return True, "Format valid"
    return False, "Invalid checksum"

def validate_secret_pattern_optional(pattern_name: str, match: str) -> Tuple[bool, str]:
    """
    OPTIONAL: Validate secret patterns using entropy analysis.
    This function is kept for optional verification but not used in main flow.
    """
    if len(match) < 8:
        return False, "Too short"

    entropy = calculate_shannon_entropy(match)
    if pattern_name in ["API Key", "JWT", "AWS", "GCP", "Azure", "Bearer Token"]:
        if entropy > 4.5:
            return True, "Format valid"
        return False, "Low entropy"
    elif pattern_name in ["Password", "Generic Password"]:
        if entropy > 3.5:
            return True, "Format valid"
        return False, "Low entropy"
    elif pattern_name in ["Private Key", "SSH Key", "PGP Private Key"]:
        if entropy > 5.0:
            return True, "Format valid"
        return False, "Low entropy"

    if entropy > 3.0:
        return True, "Format valid"
    return False, "Low entropy"

# ============================================
# REGEX PATTERNS - основная структура для поиска в тексте
# ============================================
PATTERNS = {
    "CRYPTO": {
        "ETH": r"0x[a-fA-F0-9]{40}",
        "BTC": r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}",
        "LTC": r"[LM][a-km-zA-HJ-NP-Z1-9]{25,33}",
        "DOGE": r"D[a-km-zA-HJ-NP-Z1-9]{32,33}",
        "XRP": r"r[1-9A-HJ-NP-Za-km-z]{24,34}",
        "ADA": r"addr1[a-z0-9]{98}",
        "SOL": r"[1-9A-HJ-NP-Za-km-z]{44}",
        "DOT": r"1[a-zA-Z0-9]{47}",
        "BNB": r"bnb1[a-z0-9]{38}",
        "MATIC": r"0x[a-fA-F0-9]{40}",
        "AVAX": r"0x[a-fA-F0-9]{40}",
        "TRX": r"T[a-zA-Z0-9]{33}",
        "XMR": r"[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}",
        "ZEC": r"t1[a-km-zA-HJ-NP-Z0-9]{33}",
        "DASH": r"X[1-9A-HJ-NP-Za-km-z]{33}",
        "USDT": r"0x[a-fA-F0-9]{40}",
        "BCH": r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}",
        "ETC": r"0x[a-fA-F0-9]{40}",
        "XLM": r"G[A-Z0-9]{55}",
        "ALGO": r"[A-Z2-7]{58}",
        "VET": r"0x[a-fA-F0-9]{40}",
        "ICP": r"[a-z0-9]{64}",
        "FIL": r"f[0-9]{38,}",
        "HBAR": r"0\.0\.[0-9]{4,}",
        "NEAR": r"[a-z0-9_-]{2,64}\.near",
        "ATOM": r"cosmos1[a-z0-9]{38}",
        "LUNA": r"terra1[a-z0-9]{38}",
        "OSMO": r"osmo1[a-z0-9]{38}",
        "Private Key": r"[5KL][1-9A-HJ-NP-Za-km-z]{50,51}",
        "WIF": r"[5KL][1-9A-HJ-NP-Za-km-z]{50,51}",
        "Extended Private Key": r"xprv[1-9A-HJ-NP-Za-km-z]{107}",
        "Extended Public Key": r"xpub[1-9A-HJ-NP-Za-km-z]{107}",
        "BIP32 Root Key": r"xprv[1-9A-HJ-NP-Za-km-z]{107}",
        "BIP44 Account Key": r"xprv[1-9A-HJ-NP-Za-km-z]{107}",
        "Mnemonic": r"([a-z]{3,12}\s){11,23}[a-z]{3,12}",
        "Seed Phrase": r"([a-z]{3,12}\s){11,23}[a-z]{3,12}",
        "HD Seed": r"[a-f0-9]{128}",
        "BIP39 Passphrase": r"([a-z]{3,12}\s){11,23}[a-z]{3,12}\s[a-z]{3,12}",
        "Keystore File": r"\{.*\"address\".*\"crypto\".*\}",
        "Wallet.dat": r"wallet\.dat"
    },
    "SECRETS": {
        "API Key": r"[a-zA-Z0-9_\-]{32,}",
        "AWS": r"AKIA[0-9A-Z]{16}",
        "GCP": r"AIza[0-9A-Za-z\\-_]{35}",
        "Azure": r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
        "JWT": r"eyJ[a-zA-Z0-9]{10,}\\.[a-zA-Z0-9_\\-]{10,}\\.[a-zA-Z0-9_\\-]{10,}",
        "Bearer Token": r"Bearer\s+[a-zA-Z0-9_\\-\\.]{20,}",
        "OAuth Token": r"oauth[_-]?token[\s:=]['\"]?([a-z0-9]{32,})['\"]?",
        "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
        "GitHub Token": r"ghp_[a-zA-Z0-9]{36}",
        "Stripe Key": r"sk_(live|test)_[a-zA-Z0-9]{24}",
        "Password in URL": r"password=[^&\s]+",
        "Database URL": r"(mysql|postgres|mongodb)://[^@\s]+:[^@\s]+@",
        "SSH Key": r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
        "Discord Bot Token": r"([MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27})",
        "Twitter Bearer Token": r"AAAAAAAAAAAAAAAAAAAAA[a-zA-Z0-9]{18}",
        "Facebook Access Token": r"EAACEdEose0cBA[a-zA-Z0-9]{100,}",
        "Google OAuth Token": r"ya29\.[a-zA-Z0-9_-]{100,}",
        "Heroku API Key": r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
        "Mailgun API Key": r"key-[a-f0-9]{32}",
        "SendGrid API Key": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        "Twilio SID": r"SK[a-f0-9]{32}",
        "PayPal Client Secret": r"[A-Za-z0-9]{80,}",
        "Shopify Access Token": r"shpat_[a-f0-9]{32}",
        "DigitalOcean Token": r"dop_v1_[a-f0-9]{64}",
        "Linode Token": r"[a-f0-9]{64}",
        "Algolia API Key": r"[a-zA-Z0-9]{32}",
        "Sentry DSN": r"https://[a-f0-9]{8}@[a-z0-9-]+\.ingest\.sentry\.io/[0-9]+",
        "Generic Base64": r"base64,([a-zA-Z0-9+/=]{20,})",
        "Private RSA Key": r"-----BEGIN RSA PRIVATE KEY-----",
        "PGP Private Key": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "Generic Password": r"password[\s:=]['\"]?([^'\"\s]{8,})['\"]?"
    },
    "VULNERABILITIES": {
        "SQL Injection": r"(UNION|SELECT|INSERT|DELETE|UPDATE|DROP)\s",
        "SQL Error": r"(SQL syntax|MySQL server|PostgreSQL|ORA-[0-9]{5}|Microsoft SQL Server|SQLite|syntax error|mysql_fetch_array|mysql_num_rows)",
        "XSS": r"<script[^>]*>.*?</script>|<img[^>]*onerror[^>]*>|<svg[^>]*onload[^>]*>",
        "Config File": r"(config|configuration|settings)\.(php|json|yml|env|ini|xml|conf|cfg)",
        "Backup File": r"\.(bak|old|backup|swp|save|tmp|orig|zip|tar\.gz|rar)",
        "Git Folder": r"/\.git/",
        "SVN Folder": r"/\.svn/",
        "DS_Store": r"/\.DS_Store",
        "Log File": r"\.(log|txt|csv|out).*(pass|pwd|token|key|secret)",
        "PHP Info": r"phpinfo\(\)",
        "Directory Listing": r"Index of /",
        "Admin Panel": r"(admin|login|dashboard|cpanel|wp-admin|pma|phpmyadmin)",
        "WordPress": r"wp-content|wp-includes|wp-admin",
        "Joomla": r"administrator/components|joomla",
        "Drupal": r"sites/default/files|drupal",
        "Path Traversal": r"\.\./\.\./\.\./",
        "LFI/RFI": r"../../../etc/passwd|php://input|data://",
        "Command Injection": r";\s*(ls|cat|pwd|whoami|id)",
        "Open Redirect": r"redirect=|url=|return_url=",
        "CORS Misconfig": r"Access-Control-Allow-Origin: \*",
        "Exposed API": r"/api/v[0-9]+/|/graphql|/swagger",
        "Debug Info": r"debug_backtrace|var_dump|print_r",
        "Server Info": r"server-status|server-info|X-Powered-By|Server:",
        "Robots.txt": r"Disallow:|Allow:",
        "Sitemap.xml": r"<urlset|<sitemap",
        "Exposed DB": r"\.(db|sqlite|sql|mdb)",
        "Session Files": r"session\..*|sess_[a-f0-9]+",
        "Cache Files": r"cache/|\.cache",
        "Temp Files": r"tmp/|temp/",
        ".htaccess": r"RewriteRule|AuthUserFile",
        ".htpasswd": r":[a-zA-Z0-9]{13}:",
        "Web.config": r"<configuration|<system.web",
        "Error Logs": r"error_log|access_log|php_errors",
        "Version Disclosure": r"version|ver|build|release",
        "Default Creds": r"admin:admin|root:root|user:pass"
    }
}

class DorkPatterns:
    """Class to manage dork patterns and their associated dorks"""

    def __init__(self):
        self.patterns = PATTERNS
        self.initialize_pattern_categories()

    def initialize_pattern_categories(self):
        """Add allow_categories and deny_categories to patterns based on their type"""
        # Define category mappings for different pattern types
        category_mapping = {
            # Category A: CONFIG/DATA FILES - Most secrets belong here
            'A': {
                'names': [
                    'AWS', 'GCP', 'Azure', 'JWT', 'Bearer Token', 
                    'Private RSA Key', 'PGP Private Key', 'SSH Key',
                    'Config File', 'Log File', 'Exposed DB', 'Session Files', 
                    'Cache Files', 'Temp Files', '.htaccess', '.htpasswd', 'Web.config'
                ]
            },
            # Category B: SOURCE/BUILD ARTIFACTS  
            'B': {
                'names': [
                    'API Key', 'Database Connection', 'Private RSA Key',
                    'Generic Password', 'GitHub Token', 'Stripe Key', 'Slack Token'
                ]
            },
            # Category C: BACKUPS/DUMPS
            'C': {
                'names': [
                    'Backup File', 'Dump'
                ]
            },
            # Category D: WEB PAGES (usually vulnerabilities)
            'D': {
                'names': [
                    'SQL Injection', 'SQL Error', 'XSS', 'Git Folder', 'SVN Folder', 'DS_Store',
                    'PHP Info', 'Directory Listing', 'Admin Panel', 
                    'WordPress', 'Joomla', 'Drupal', 'Path Traversal', 
                    'LFI/RFI', 'Command Injection', 'Open Redirect', 
                    'CORS Misconfig', 'Exposed API', 'Debug Info', 
                    'Server Info', 'Robots.txt', 'Sitemap.xml', 
                    'Error Logs', 'Version Disclosure', 'Default Creds'
                ]
            }
        }
        
        # Universal patterns (applied to A/B/C, denied D/E)
        universal_patterns = {
            'names': [
                'ETH', 'BTC', 'LTC', 'DOGE', 'XRP', 'ADA', 'SOL', 'DOT', 'BNB',
                'MATIC', 'AVAX', 'TRX', 'XMR', 'ZEC', 'BCH', 'DASH',
                'Generic Base64', 'Cloudinary', 'Firebase', 'MailChimp API',
                'Twilio API', 'PayPal Token', 'Heroku Token', 'Jira Token',
                'BitBucket Token', 'CircleCI Token', 'TravisCI Token',
                'OpsGenie API', 'PagerDuty Token', 'DataDog API',
                'Shopify Access Token', 'DigitalOcean Token', 'Linode Token',
                'Algolia API Key', 'Sentry DSN'
            ],
            'allow': ['A', 'B', 'C'],
            'deny': ['D', 'E']
        }
        
        # Build name-to-category mapping
        name_to_categories = {}
        
        for category_key, category_data in category_mapping.items():
            for pattern_name in category_data['names']:
                name_to_categories[pattern_name] = [category_key]
        
        # Universal patterns can operate in multiple categories
        for pattern_name in universal_patterns['names']:
            name_to_categories[pattern_name] = universal_patterns['allow']
            
        # Update patterns with category information
        for category_name, category_patterns in self.patterns.items():
            for pattern_name, pattern_data in category_patterns.items():
                
                # Determine allowed categories for this pattern
                if pattern_name in name_to_categories:
                    allow_categories = name_to_categories[pattern_name]
                    # Deny categories not explicitly allowed
                    deny_categories = [cat for cat in ['D', 'E'] if cat not in allow_categories]
                else:
                    # Default: allow A/B/C, deny D/E (opt-in for web/doc patterns)
                    allow_categories = ['A', 'B', 'C']
                    deny_categories = ['D', 'E']
                
                # Update the pattern data structure
                if isinstance(pattern_data, str):
                    # Convert simple string to dict with enhanced metadata
                    self.patterns[category_name][pattern_name] = {
                        'regex': [pattern_data],
                        'dorks': self._get_dorks_for_pattern(pattern_name, category_name),
                        'allow_categories': allow_categories,
                        'deny_categories': deny_categories
                    }
                elif isinstance(pattern_data, dict):
                    # Ensure existing dict has the category fields
                    pattern_data['allow_categories'] = allow_categories
                    pattern_data['deny_categories'] = deny_categories
                    if 'regex' not in pattern_data:
                        pattern_data['regex'] = []
                    if 'dorks' not in pattern_data:
                        pattern_data['dorks'] = self._get_dorks_for_pattern(pattern_name, category_name)

    def get_patterns(self, category):
        """Get patterns for a specific category"""
        if category not in self.patterns:
            return {}

        patterns_dict = {}
        for pattern_name, pattern_data in self.patterns[category].items():
            if isinstance(pattern_data, str):
                # Convert simple regex string to dict format
                patterns_dict[pattern_name] = {
                    'regex': [pattern_data],
                    'dorks': self._get_dorks_for_pattern(pattern_name, category),
                    'allow_categories': ['A', 'B', 'C'],  # Default
                    'deny_categories': ['D', 'E']  # Default
                }
            else:
                patterns_dict[pattern_name] = pattern_data

        return patterns_dict

    def _get_dorks_for_pattern(self, pattern_name, category):
        """Get appropriate dorks for a pattern"""
        # Map patterns to dork templates
        dork_mapping = {
            # Crypto patterns
            "ETH": ['filetype:json "ethereum" "address"', 'inurl:config "0x[a-fA-F0-9]{40}"'],
            "BTC": ['filetype:txt "bitcoin" "address"', 'inurl:backup "1[a-km-zA-HJ-NP-Z1-9]{25,34}"'],
            "Private Key": ['filetype:key "private"', 'inurl:.key "BEGIN PRIVATE KEY"'],
            "Mnemonic": ['filetype:txt "mnemonic" "seed"', 'inurl:backup "word word word"'],

            # Secrets patterns
            "API Key": ['filetype:env "API_KEY"', 'filetype:json "api_key"', 'inurl:config "apikey"'],
            "AWS": ['filetype:env "AWS_ACCESS_KEY"', 'inurl:credentials "AKIA"'],
            "JWT": ['filetype:js "eyJ"', 'inurl:token "eyJ'],
            "Password": ['filetype:env "PASSWORD"', 'inurl:config "password"'],
            "SSH Key": ['filetype:pem "BEGIN SSH"', 'inurl:.ssh "ssh-rsa"'],

            # Vulnerability patterns
            "SQL Error": ['inurl:php?id=1\'', 'inurl:asp?id=1\''],
            "Config File": ['filetype:env', 'filetype:ini', 'filetype:conf'],
            "Backup File": ['filetype:bak', 'filetype:old', 'filetype:backup'],
            "Git Folder": ['inurl:.git', 'intitle:"index of" ".git"'],
            "PHP Info": ['inurl:phpinfo.php', 'intitle:"phpinfo"'],
            "Directory Listing": ['intitle:"index of /"', 'intitle:"directory listing"'],
            "Admin Panel": ['inurl:admin', 'inurl:login', 'intitle:"admin"'],
            "WordPress": ['inurl:wp-admin', 'inurl:wp-content'],
        }

        return dork_mapping.get(pattern_name, ['site:{target}'])

# Dork templates
DORK_TEMPLATES = [
    'site:{target} filetype:env DB_PASSWORD',
    'site:{target} "index of" .git',
    'inurl:"php?id=" "{target}"',
    'intitle:"index of" "{target}"',
    '"{target}" "API_KEY" filetype:json',
    'site:{target} ext:sql "dump"',
    '"{target}" "admin" "login" "password"'
]