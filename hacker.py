#!/usr/bin/env python3
"""
NexRecon: Advanced OSINT & Reconnaissance Toolkit
A comprehensive utility for IP tracking, phone lookup, network analysis, and security assessment.
"""

# IMPORT MODULE
import json
import re
import requests
import time
import os
import socket
import hashlib
import secrets
import string
import phonenumbers
from phonenumbers import carrier, geocoder, timezone
from sys import stderr
from functools import wraps
from typing import Callable, Any, Optional, List, Dict
from urllib.parse import urlparse
from datetime import datetime
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# Optional imports for async email checking (holehe-style)
try:
    import httpx
    import trio
    ASYNC_AVAILABLE = True
except ImportError:
    ASYNC_AVAILABLE = False

# Optional imports for image metadata extraction
try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# CONSTANTS
REQUEST_TIMEOUT = 10  # seconds
RETRY_ATTEMPTS = 3

# ANSI Color codes for terminal output
class Colors:
    BLACK = '\033[30m'
    RED = '\033[1;31m'
    GREEN = '\033[1;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[1;34m'
    MAGENTA = '\033[1;35m'
    CYAN = '\033[1;36m'
    WHITE = '\033[1;37m'
    RESET = '\033[0m'

# Shorthand aliases for colors
Bl = Colors.BLACK
Re = Colors.RED
Gr = Colors.GREEN
Ye = Colors.YELLOW
Blu = Colors.BLUE
Mage = Colors.MAGENTA
Cy = Colors.CYAN
Wh = Colors.WHITE


# UTILITIES

def validate_ip(ip: str) -> bool:
    """Validate if the given string is a valid IPv4 or IPv6 address."""
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
    
    if re.match(ipv4_pattern, ip):
        # Check each octet is 0-255
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    return bool(re.match(ipv6_pattern, ip))


def make_request(url: str, timeout: int = REQUEST_TIMEOUT) -> Optional[requests.Response]:
    """Make HTTP request with error handling and retry logic."""
    for attempt in range(RETRY_ATTEMPTS):
        try:
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
            return response
        except requests.exceptions.Timeout:
            print(f"{Ye}Request timed out. Retrying ({attempt + 1}/{RETRY_ATTEMPTS})...")
            time.sleep(1)
        except requests.exceptions.ConnectionError:
            print(f"{Re}Connection error. Please check your internet connection.")
            return None
        except requests.exceptions.HTTPError as e:
            print(f"{Re}HTTP Error: {e}")
            return None
        except requests.exceptions.RequestException as e:
            print(f"{Re}Request failed: {e}")
            return None
    print(f"{Re}Failed after {RETRY_ATTEMPTS} attempts.")
    return None


def loading_animation(message: str = "Loading", duration: float = 1.0):
    """Display a simple loading animation."""
    chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    end_time = time.time() + duration
    i = 0
    while time.time() < end_time:
        print(f"\r{Cy}{message} {chars[i % len(chars)]}{Wh}", end='', flush=True)
        time.sleep(0.1)
        i += 1
    print("\r" + " " * (len(message) + 3) + "\r", end='')


def print_banner_box(title: str, subtitle: str = ""):
    """Print a styled banner box."""
    width = 50
    print(f"\n {Cy}╔{'═' * width}╗{Wh}")
    print(f" {Cy}║{Wh}{title.center(width)}{Cy}║{Wh}")
    if subtitle:
        print(f" {Cy}║{Gr}{subtitle.center(width)}{Cy}║{Wh}")
    print(f" {Cy}╚{'═' * width}╝{Wh}")


def print_section(title: str):
    """Print a section header."""
    print(f"\n {Cy}┌─ {Wh}{title} {Cy}{'─' * (40 - len(title))}┐{Wh}")


def print_item(label: str, value: str, label_width: int = 18):
    """Print a formatted item."""
    print(f" {Wh}│ {label:{label_width}}: {Gr}{value}{Wh}")


def print_section_end():
    """Print section end."""
    print(f" {Cy}└{'─' * 45}┘{Wh}")


def print_success(message: str):
    """Print success message."""
    print(f" {Gr}✓ {message}{Wh}")


def print_error(message: str):
    """Print error message."""
    print(f" {Re}✗ {message}{Wh}")


def print_warning(message: str):
    """Print warning message."""
    print(f" {Ye}⚠ {message}{Wh}")


def print_info(message: str):
    """Print info message."""
    print(f" {Cy}ℹ {message}{Wh}")


def animated_print(text: str, delay: float = 0.02):
    """Print text with typing animation."""
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()


def progress_bar(current: int, total: int, width: int = 30, prefix: str = ""):
    """Display a progress bar."""
    percent = current / total
    filled = int(width * percent)
    bar = f"{Gr}{'█' * filled}{Wh}{'░' * (width - filled)}"
    print(f"\r {prefix}[{bar}] {Cy}{percent*100:.0f}%{Wh}", end='', flush=True)
    if current == total:
        print()


def get_terminal_width() -> int:
    """Get terminal width."""
    try:
        import shutil
        return shutil.get_terminal_size().columns
    except:
        return 80


def is_option(func: Callable) -> Callable:
    """Decorator for attaching run_banner to a function."""
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        run_banner()
        return func(*args, **kwargs)
    return wrapper


# FUNCTIONS FOR MENU
@is_option
def IP_Track():
    """Track IP address and display geolocation information."""
    ip = input(f"{Wh}\n Enter IP target : {Gr}").strip()
    
    # Validate IP address
    if not ip:
        print(f"{Re}Error: Please enter an IP address.")
        return
    
    if not validate_ip(ip) and not ip.replace('.', '').replace(':', '').isalnum():
        print(f"{Ye}Warning: IP format might be invalid. Proceeding anyway...")
    
    print()
    loading_animation("Fetching IP information", 1.5)
    print(f' {Wh}============= {Gr}SHOW INFORMATION IP ADDRESS {Wh}=============')
    
    # Try multiple APIs for better reliability and accuracy
    ip_data = None
    api_sources = [
        {"name": "ip-api.com", "url": f"http://ip-api.com/json/{ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,mobile,proxy,hosting,query"},
        {"name": "ipwho.is", "url": f"http://ipwho.is/{ip}"},
        {"name": "ipapi.co", "url": f"https://ipapi.co/{ip}/json/"},
    ]
    
    used_api = None
    for api in api_sources:
        response = make_request(api["url"])
        if response:
            try:
                data = response.json()
                # Check for errors in response
                if api["name"] == "ip-api.com" and data.get("status") == "fail":
                    print(f"{Ye}API {api['name']}: {data.get('message', 'Failed')}")
                    continue
                if api["name"] == "ipwho.is" and data.get("success") == False:
                    print(f"{Ye}API {api['name']}: {data.get('message', 'Failed')}")
                    continue
                if api["name"] == "ipapi.co" and data.get("error"):
                    print(f"{Ye}API {api['name']}: {data.get('reason', 'Failed')}")
                    continue
                ip_data = data
                used_api = api["name"]
                break
            except:
                continue
    
    if not ip_data:
        print(f"{Re}Failed to fetch IP information from all sources.")
        return
    
    try:
        print(f"{Cy}\n [Using: {used_api}]{Wh}")
        print(f"{Wh}\n IP target       :{Gr}", ip)
        
        # Normalize data from different APIs
        if used_api == "ip-api.com":
            print(f"{Wh} Status          :{Gr}", "Valid" if ip_data.get("status") == "success" else "Invalid")
            print(f"{Wh} Country         :{Gr}", ip_data.get("country", "N/A"))
            print(f"{Wh} Country Code    :{Gr}", ip_data.get("countryCode", "N/A"))
            print(f"{Wh} Region          :{Gr}", ip_data.get("regionName", "N/A"))
            print(f"{Wh} Region Code     :{Gr}", ip_data.get("region", "N/A"))
            print(f"{Wh} City            :{Gr}", ip_data.get("city", "N/A"))
            print(f"{Wh} District        :{Gr}", ip_data.get("district", "N/A") or "N/A")
            print(f"{Wh} ZIP/Postal      :{Gr}", ip_data.get("zip", "N/A"))
            print(f"{Wh} Continent       :{Gr}", ip_data.get("continent", "N/A"))
            print(f"{Wh} Continent Code  :{Gr}", ip_data.get("continentCode", "N/A"))
            print(f"{Wh} Latitude        :{Gr}", ip_data.get("lat", "N/A"))
            print(f"{Wh} Longitude       :{Gr}", ip_data.get("lon", "N/A"))
            lat, lon = ip_data.get('lat'), ip_data.get('lon')
            if lat and lon:
                print(f"{Wh} Maps            :{Gr}", f"https://www.google.com/maps/@{lat},{lon},15z")
            print(f"{Wh} Timezone        :{Gr}", ip_data.get("timezone", "N/A"))
            print(f"{Wh} UTC Offset      :{Gr}", ip_data.get("offset", "N/A"))
            print(f"{Wh} Currency        :{Gr}", ip_data.get("currency", "N/A"))
            print(f"{Wh} ISP             :{Gr}", ip_data.get("isp", "N/A"))
            print(f"{Wh} Organization    :{Gr}", ip_data.get("org", "N/A"))
            print(f"{Wh} AS Number       :{Gr}", ip_data.get("as", "N/A"))
            print(f"{Wh} AS Name         :{Gr}", ip_data.get("asname", "N/A"))
            print(f"{Wh} Mobile          :{Gr}", "Yes" if ip_data.get("mobile") else "No")
            print(f"{Wh} Proxy/VPN       :{Gr}", "Yes" if ip_data.get("proxy") else "No")
            print(f"{Wh} Hosting/DC      :{Gr}", "Yes" if ip_data.get("hosting") else "No")
            
        elif used_api == "ipwho.is":
            print(f"{Wh} Type IP         :{Gr}", ip_data.get("type", "N/A"))
            print(f"{Wh} Country         :{Gr}", ip_data.get("country", "N/A"))
            print(f"{Wh} Country Code    :{Gr}", ip_data.get("country_code", "N/A"))
            print(f"{Wh} City            :{Gr}", ip_data.get("city", "N/A"))
            print(f"{Wh} Continent       :{Gr}", ip_data.get("continent", "N/A"))
            print(f"{Wh} Continent Code  :{Gr}", ip_data.get("continent_code", "N/A"))
            print(f"{Wh} Region          :{Gr}", ip_data.get("region", "N/A"))
            print(f"{Wh} Region Code     :{Gr}", ip_data.get("region_code", "N/A"))
            print(f"{Wh} Latitude        :{Gr}", ip_data.get("latitude", "N/A"))
            print(f"{Wh} Longitude       :{Gr}", ip_data.get("longitude", "N/A"))
            lat, lon = ip_data.get('latitude'), ip_data.get('longitude')
            if lat and lon:
                print(f"{Wh} Maps            :{Gr}", f"https://www.google.com/maps/@{lat},{lon},15z")
            print(f"{Wh} EU              :{Gr}", ip_data.get("is_eu", "N/A"))
            print(f"{Wh} Postal          :{Gr}", ip_data.get("postal", "N/A"))
            print(f"{Wh} Calling Code    :{Gr}", ip_data.get("calling_code", "N/A"))
            print(f"{Wh} Capital         :{Gr}", ip_data.get("capital", "N/A"))
            print(f"{Wh} Borders         :{Gr}", ip_data.get("borders", "N/A"))
            flag = ip_data.get("flag", {})
            print(f"{Wh} Country Flag    :{Gr}", flag.get("emoji", "N/A") if flag else "N/A")
            connection = ip_data.get("connection", {})
            print(f"{Wh} ASN             :{Gr}", connection.get("asn", "N/A"))
            print(f"{Wh} ORG             :{Gr}", connection.get("org", "N/A"))
            print(f"{Wh} ISP             :{Gr}", connection.get("isp", "N/A"))
            print(f"{Wh} Domain          :{Gr}", connection.get("domain", "N/A"))
            tz = ip_data.get("timezone", {})
            print(f"{Wh} Timezone ID     :{Gr}", tz.get("id", "N/A"))
            print(f"{Wh} Timezone ABBR   :{Gr}", tz.get("abbr", "N/A"))
            print(f"{Wh} DST             :{Gr}", tz.get("is_dst", "N/A"))
            print(f"{Wh} UTC Offset      :{Gr}", tz.get("utc", "N/A"))
            print(f"{Wh} Current Time    :{Gr}", tz.get("current_time", "N/A"))
            
        elif used_api == "ipapi.co":
            print(f"{Wh} Country         :{Gr}", ip_data.get("country_name", "N/A"))
            print(f"{Wh} Country Code    :{Gr}", ip_data.get("country_code", "N/A"))
            print(f"{Wh} Region          :{Gr}", ip_data.get("region", "N/A"))
            print(f"{Wh} Region Code     :{Gr}", ip_data.get("region_code", "N/A"))
            print(f"{Wh} City            :{Gr}", ip_data.get("city", "N/A"))
            print(f"{Wh} Postal          :{Gr}", ip_data.get("postal", "N/A"))
            print(f"{Wh} Latitude        :{Gr}", ip_data.get("latitude", "N/A"))
            print(f"{Wh} Longitude       :{Gr}", ip_data.get("longitude", "N/A"))
            lat, lon = ip_data.get('latitude'), ip_data.get('longitude')
            if lat and lon:
                print(f"{Wh} Maps            :{Gr}", f"https://www.google.com/maps/@{lat},{lon},15z")
            print(f"{Wh} Timezone        :{Gr}", ip_data.get("timezone", "N/A"))
            print(f"{Wh} UTC Offset      :{Gr}", ip_data.get("utc_offset", "N/A"))
            print(f"{Wh} Currency        :{Gr}", ip_data.get("currency", "N/A"))
            print(f"{Wh} Currency Name   :{Gr}", ip_data.get("currency_name", "N/A"))
            print(f"{Wh} Languages       :{Gr}", ip_data.get("languages", "N/A"))
            print(f"{Wh} Country Area    :{Gr}", f"{ip_data.get('country_area', 'N/A')} km²")
            print(f"{Wh} Population      :{Gr}", f"{ip_data.get('country_population', 'N/A'):,}" if ip_data.get('country_population') else "N/A")
            print(f"{Wh} ASN             :{Gr}", ip_data.get("asn", "N/A"))
            print(f"{Wh} Organization    :{Gr}", ip_data.get("org", "N/A"))
        
    except json.JSONDecodeError:
        print(f"{Re}Error: Invalid response from server.")
    except Exception as e:
        print(f"{Re}Error processing data: {e}")


@is_option
def phoneGW():
    """Track phone number and display carrier/location information."""
    User_phone = input(
        f"\n {Wh}Enter phone number target {Gr}Ex [+6281xxxxxxxxx] {Wh}: {Gr}").strip()
    
    if not User_phone:
        print(f"{Re}Error: Please enter a phone number.")
        return
    
    default_region = "ID"  # DEFAULT COUNTRY: INDONESIA

    try:
        parsed_number = phonenumbers.parse(User_phone, default_region)
        
        # Validate the phone number
        if not phonenumbers.is_possible_number(parsed_number):
            print(f"{Ye}Warning: This doesn't appear to be a valid phone number format.")
        
        region_code = phonenumbers.region_code_for_number(parsed_number)
        jenis_provider = carrier.name_for_number(parsed_number, "en")
        location = geocoder.description_for_number(parsed_number, "id")
        is_valid_number = phonenumbers.is_valid_number(parsed_number)
        is_possible_number = phonenumbers.is_possible_number(parsed_number)
        formatted_number = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        formatted_number_for_mobile = phonenumbers.format_number_for_mobile_dialing(parsed_number, default_region,
                                                                                    with_formatting=True)
        number_type = phonenumbers.number_type(parsed_number)
        timezone1 = timezone.time_zones_for_number(parsed_number)
        timezoneF = ', '.join(timezone1) if timezone1 else "N/A"

        loading_animation("Analyzing phone number", 1.0)
        print(f"\n {Wh}========== {Gr}SHOW INFORMATION PHONE NUMBERS {Wh}==========")
        print(f"\n {Wh}Location             :{Gr} {location or 'Unknown'}")
        print(f" {Wh}Region Code          :{Gr} {region_code or 'Unknown'}")
        print(f" {Wh}Timezone             :{Gr} {timezoneF}")
        print(f" {Wh}Operator             :{Gr} {jenis_provider or 'Unknown'}")
        print(f" {Wh}Valid number         :{Gr} {is_valid_number}")
        print(f" {Wh}Possible number      :{Gr} {is_possible_number}")
        print(f" {Wh}International format :{Gr} {formatted_number}")
        print(f" {Wh}Mobile format        :{Gr} {formatted_number_for_mobile}")
        print(f" {Wh}Original number      :{Gr} {parsed_number.national_number}")
        print(
            f" {Wh}E.164 format         :{Gr} {phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)}")
        print(f" {Wh}Country code         :{Gr} {parsed_number.country_code}")
        print(f" {Wh}Local number         :{Gr} {parsed_number.national_number}")
        
        # Determine phone type
        type_map = {
            phonenumbers.PhoneNumberType.MOBILE: "Mobile number",
            phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed-line number",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed-line or mobile",
            phonenumbers.PhoneNumberType.TOLL_FREE: "Toll-free number",
            phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium rate number",
            phonenumbers.PhoneNumberType.VOIP: "VoIP number",
            phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal number",
            phonenumbers.PhoneNumberType.PAGER: "Pager",
            phonenumbers.PhoneNumberType.UAN: "UAN (Universal Access Number)",
            phonenumbers.PhoneNumberType.VOICEMAIL: "Voicemail",
        }
        phone_type_str = type_map.get(number_type, "Unknown type")
        print(f" {Wh}Type                 :{Gr} {phone_type_str}")
        
    except phonenumbers.phonenumberutil.NumberParseException as e:
        print(f"{Re}Error parsing phone number: {e}")
    except Exception as e:
        print(f"{Re}Error: {e}")


# ============== EMAIL FOOTPRINT CHECKER (HOLEHE-STYLE) ==============

def get_random_useragent():
    """Generate a random user agent string."""
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    ]
    return secrets.choice(user_agents)


def check_email_on_site(site_name: str, domain: str, email: str) -> dict:
    """Check if email is registered on a specific website."""
    result = {
        'name': site_name,
        'domain': domain,
        'exists': False,
        'rateLimit': False,
        'error': False,
        'emailrecovery': None,
        'phoneNumber': None,
        'others': None
    }
    
    headers = {
        'User-Agent': get_random_useragent(),
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Origin': f'https://{domain}',
        'Referer': f'https://{domain}/',
    }
    
    # Create a fresh session for each check to avoid cookie issues
    session = requests.Session()
    
    try:
        # ===== GRAVATAR =====
        if site_name == 'gravatar':
            email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
            url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
            response = session.get(url, headers=headers, timeout=8)
            result['exists'] = response.status_code == 200
            
        # ===== SPOTIFY =====
        elif site_name == 'spotify':
            # Updated Spotify endpoint
            spotify_headers = {
                'User-Agent': get_random_useragent(),
                'Accept': 'application/json',
                'Accept-Language': 'en-US,en;q=0.9',
                'Content-Type': 'application/x-www-form-urlencoded',
            }
            url = f"https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email={email}"
            response = session.get(url, headers=spotify_headers, timeout=10)
            if response.status_code == 200:
                try:
                    data = response.json()
                    status = data.get('status', 0)
                    # status 20 = email exists, status 1 = email available
                    result['exists'] = (status == 20)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                
        # ===== TWITTER/X =====
        elif site_name == 'twitter':
            # Twitter API is heavily restricted, mark as unable to check
            result['error'] = True
            result['others'] = {'Message': 'API restricted'}
                
        # ===== GITHUB =====
        elif site_name == 'github':
            # Method 1: Search by email in public profiles (most reliable)
            try:
                url = f"https://api.github.com/search/users?q={email}+in:email"
                github_headers = headers.copy()
                github_headers['Accept'] = 'application/vnd.github.v3+json'
                response = session.get(url, headers=github_headers, timeout=8)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('total_count', 0) > 0:
                        result['exists'] = True
                        users = data.get('items', [])
                        if users:
                            result['others'] = {'Username': users[0].get('login', '')}
                elif response.status_code == 403 or response.status_code == 429:
                    result['rateLimit'] = True
            except:
                result['error'] = True
            
            # Method 2: Search commits by author email
            if not result['exists'] and not result['rateLimit'] and not result['error']:
                try:
                    url = f"https://api.github.com/search/commits?q=author-email:{email}"
                    commit_headers = headers.copy()
                    commit_headers['Accept'] = 'application/vnd.github.cloak-preview+json'
                    response = session.get(url, headers=commit_headers, timeout=8)
                    if response.status_code == 200:
                        data = response.json()
                        if data.get('total_count', 0) > 0:
                            result['exists'] = True
                    elif response.status_code == 403 or response.status_code == 429:
                        result['rateLimit'] = True
                except:
                    pass
                
        # ===== PINTEREST =====
        elif site_name == 'pinterest':
            url = "https://www.pinterest.com/resource/EmailExistsResource/get/"
            params = {
                'source_url': '/login/',
                'data': json.dumps({'options': {'email': email}, 'context': {}})
            }
            response = session.get(url, params=params, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('resource_response', {}).get('data', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== DISCORD =====
        elif site_name == 'discord':
            # Discord has heavy bot protection, marking as error
            result['error'] = True
            result['others'] = {'Message': 'Bot protection active'}
                            
        # ===== ADOBE =====
        elif site_name == 'adobe':
            # Adobe has changed their API, mark as error
            result['error'] = True
            result['others'] = {'Message': 'API changed'}
                        
        # ===== IMGUR =====
        elif site_name == 'imgur':
            url = "https://imgur.com/signin/ajax_email_available"
            response = session.post(url, data={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    resp_data = response.json()
                    result['exists'] = not resp_data.get('data', {}).get('available', True)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== YAHOO =====
        elif site_name == 'yahoo':
            url = "https://login.yahoo.com/account/module/create?validateField=yid"
            response = session.post(url, data={'yid': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                result['exists'] = 'IDENTIFIER_EXISTS' in response.text or 'already taken' in response.text.lower()
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                
        # ===== SNAPCHAT ===== (API changed - can't reliably check)
        elif site_name == 'snapchat':
            # Snapchat's API has changed and no longer exposes email check
            result['error'] = True
            result['others'] = {'Message': 'API not available'}
                
        # ===== INSTAGRAM =====
        elif site_name == 'instagram':
            # Instagram has strong bot protection
            result['error'] = True
            result['others'] = {'Message': 'Bot protection active'}
                    
        # ===== WORDPRESS =====
        elif site_name == 'wordpress':
            url = "https://wordpress.com/wp-login.php?action=lostpassword"
            response = session.post(url, data={'user_login': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                if 'email has been sent' in response.text.lower() or 'check your email' in response.text.lower():
                    result['exists'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
                    
        # ===== EBAY =====
        elif site_name == 'ebay':
            # eBay doesn't easily reveal email existence
            result['error'] = True
            result['others'] = {'Message': 'Cannot check'}
            
        # ===== TUMBLR =====
        elif site_name == 'tumblr':
            url = "https://www.tumblr.com/api/v2/register/email_check"
            response = session.post(url, data={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = not data.get('response', {}).get('available', True)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== PATREON =====
        elif site_name == 'patreon':
            url = "https://www.patreon.com/api/auth/email-in-use"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('data', {}).get('email_in_use', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== DUOLINGO =====
        elif site_name == 'duolingo':
            url = f"https://www.duolingo.com/2017-06-30/users?email={email}"
            response = session.get(url, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    users = data.get('users', [])
                    result['exists'] = len(users) > 0
                    if users:
                        user = users[0]
                        result['others'] = {'Username': user.get('username', '')}
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== FIREFOX =====
        elif site_name == 'firefox':
            url = "https://api.accounts.firefox.com/v1/account/status"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('exists', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== LINKEDIN =====
        elif site_name == 'linkedin':
            # LinkedIn API is heavily restricted
            result['error'] = True
            result['others'] = {'Message': 'API restricted'}
                
        # ===== QUORA =====
        elif site_name == 'quora':
            url = "https://www.quora.com/webnode2/server_call_POST"
            json_data = {"args": [], "kwargs": {"email": email}}
            response = session.post(url, json=json_data, headers=headers, timeout=8)
            if response.status_code == 200 and 'true' in response.text.lower():
                result['exists'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                
        # ===== STRAVA =====
        elif site_name == 'strava':
            url = "https://www.strava.com/api/v3/oauth/email_validate"
            response = session.post(url, data={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = not data.get('available', True)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== AMAZON =====
        elif site_name == 'amazon':
            # Amazon has heavy bot protection
            result['error'] = True
            result['others'] = {'Message': 'Bot protection active'}
                    
        # ===== GOOGLE =====
        elif site_name == 'google':
            url = f"https://mail.google.com/mail/gxlu?email={email}"
            response = session.get(url, headers=headers, timeout=8)
            # Check if it's a valid Google account by cookie presence
            if 'COMPASS' in response.cookies.keys():
                result['exists'] = True
                
        # ===== ARCHIVEORG =====
        elif site_name == 'archiveorg':
            url = "https://archive.org/account/login"
            data = {'username': email, 'submit_by_js': 'true'}
            response = session.post(url, data=data, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    resp_data = response.json()
                    if resp_data.get('status') == 'need_password':
                        result['exists'] = True
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== ATLASSIAN =====
        elif site_name == 'atlassian':
            url = "https://id.atlassian.com/rest/check-username"
            json_data = {'username': email}
            atlassian_headers = headers.copy()
            atlassian_headers['Content-Type'] = 'application/json'
            response = session.post(url, json=json_data, headers=atlassian_headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('exists', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== BITLY =====
        elif site_name == 'bitly':
            url = "https://bitly.com/a/sign_up_check_email"
            response = session.post(url, data={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                if 'already' in response.text.lower() or 'exists' in response.text.lower():
                    result['exists'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== BODYBUILDING =====
        elif site_name == 'bodybuilding':
            url = "https://www.bodybuilding.com/api/user/email-exists"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('exists', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== BUYMEACOFFEE =====
        elif site_name == 'buymeacoffee':
            url = f"https://www.buymeacoffee.com/api/v1/auth/check-email?email={email}"
            response = session.get(url, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('exists', False) or data.get('registered', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== CODECADEMY =====
        elif site_name == 'codecademy':
            url = "https://www.codecademy.com/api/v1/accounts/email_exists"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('exists', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== DELIVEROO =====
        elif site_name == 'deliveroo':
            url = "https://api.deliveroo.com/orderapp/v1/check-email"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('registered', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== DOCKER =====
        elif site_name == 'docker':
            url = f"https://hub.docker.com/v2/users/{email.split('@')[0]}/"
            response = session.get(url, headers=headers, timeout=8)
            if response.status_code == 200:
                result['exists'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            elif response.status_code != 404:
                result['error'] = True
            
        # ===== ENVATO =====
        elif site_name == 'envato':
            url = "https://account.envato.com/api/v1/user/email-exists"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('exists', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== EVENTBRITE =====
        elif site_name == 'eventbrite':
            url = "https://www.eventbrite.com/api/v3/users/lookup/"
            params = {'email': email}
            response = session.get(url, params=params, headers=headers, timeout=8)
            if response.status_code == 200:
                result['exists'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            elif response.status_code != 404:
                result['error'] = True
            
        # ===== EVERNOTE =====
        elif site_name == 'evernote':
            url = "https://www.evernote.com/Registration.action"
            response = session.post(url, data={'email': email, 'analyticsLoginOrigin': 'login_action'}, headers=headers, timeout=8)
            if response.status_code == 200:
                if 'already' in response.text.lower() or 'exists' in response.text.lower():
                    result['exists'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== FLIPKART =====
        elif site_name == 'flipkart':
            url = "https://www.flipkart.com/api/5/user/email-exists"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('RESPONSE', {}).get('emailExists', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== FREELANCER =====
        elif site_name == 'freelancer':
            url = "https://www.freelancer.com/api/users/0.1/users/check"
            params = {'emails[]': email}
            response = session.get(url, params=params, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = len(data.get('result', {}).get('users', [])) > 0
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== HUBSPOT =====
        elif site_name == 'hubspot':
            url = "https://api.hubspot.com/login-api/v1/login/check-email"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('exists', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== ISSUU =====
        elif site_name == 'issuu':
            url = "https://api.issuu.com/v2/login"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 400:
                result['exists'] = True  # Email exists but wrong password
            elif response.status_code == 429:
                result['rateLimit'] = True
            elif response.status_code != 401:
                result['error'] = True
                
        # ===== LASTFM =====
        elif site_name == 'lastfm':
            url = "https://www.last.fm/join/partial/validate"
            response = session.post(url, data={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = not data.get('email', {}).get('valid', True)
                except:
                    if 'taken' in response.text.lower() or 'already' in response.text.lower():
                        result['exists'] = True
                    else:
                        result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                        
        # ===== LAZADA =====
        elif site_name == 'lazada':
            url = "https://member.lazada.co.id/user/api/email-exist"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('exist', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== MEWE =====
        elif site_name == 'mewe':
            url = "https://mewe.com/api/v2/auth/checkEmail"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('exists', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== MYSPACE =====
        elif site_name == 'myspace':
            url = "https://myspace.com/ajax/account/validateEmail"
            response = session.post(url, data={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                if 'taken' in response.text.lower() or 'exists' in response.text.lower():
                    result['exists'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== NIKE =====
        elif site_name == 'nike':
            url = "https://unite.nike.com/getUserByEmail"
            params = {'email': email}
            response = session.get(url, params=params, headers=headers, timeout=8)
            if response.status_code == 200:
                result['exists'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            elif response.status_code != 404:
                result['error'] = True
            
        # ===== PICSART =====
        elif site_name == 'picsart':
            url = "https://api.picsart.com/users/email/check"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('exists', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== PORNHUB =====
        elif site_name == 'pornhub':
            url = "https://www.pornhub.com/signup/check_email"
            response = session.post(url, data={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = not data.get('available', True)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== REPLIT =====
        elif site_name == 'replit':
            url = "https://replit.com/graphql"
            json_data = {
                'query': 'query { userByEmail(email: \"' + email + '\") { id username } }'
            }
            response = session.post(url, json=json_data, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('data', {}).get('userByEmail') is not None
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== SAMSUNG =====
        elif site_name == 'samsung':
            url = "https://account.samsung.com/accounts/v1/MBR/checkEmailID"
            json_data = {'emailID': email}
            response = session.post(url, json=json_data, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('resultCode') == '000'
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== SHOPIFY =====
        elif site_name == 'shopify':
            url = "https://accounts.shopify.com/lookup"
            response = session.post(url, data={'email': email}, headers=headers, timeout=8, allow_redirects=False)
            if response.status_code == 302:
                result['exists'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                
        # ===== SMULE =====
        elif site_name == 'smule':
            url = "https://www.smule.com/api/check_email"
            response = session.post(url, data={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = not data.get('available', True)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== SOUNDCLOUD =====
        elif site_name == 'soundcloud':
            url = "https://api-v2.soundcloud.com/signup/email-check"
            params = {'email': email}
            response = session.get(url, params=params, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('registered', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== SPOTIFY =====  (handled above)
        
        # ===== TOKOPEDIA =====
        elif site_name == 'tokopedia':
            url = "https://accounts.tokopedia.com/otp/c/ajax/email-check"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('data', {}).get('is_exist', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== TWITCH =====
        elif site_name == 'twitch':
            url = "https://passport.twitch.tv/usernames/check"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                if 'taken' in response.text.lower():
                    result['exists'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== VENMO =====
        elif site_name == 'venmo':
            url = "https://venmo.com/api/v5/users"
            params = {'query': email}
            response = session.get(url, params=params, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = len(data.get('data', [])) > 0
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== VIVINO =====
        elif site_name == 'vivino':
            url = "https://www.vivino.com/api/login"
            response = session.post(url, json={'email': email, 'password': 'test'}, headers=headers, timeout=8)
            if response.status_code == 401:
                result['exists'] = True  # Wrong password but email exists
            elif response.status_code == 429:
                result['rateLimit'] = True
                
        # ===== WATTPAD =====
        elif site_name == 'wattpad':
            url = "https://www.wattpad.com/api/v3/users/check_email"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('exists', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== XING =====
        elif site_name == 'xing':
            url = "https://login.xing.com/api/login/email"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                result['exists'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                
        # ===== ZOHO =====
        elif site_name == 'zoho':
            url = "https://accounts.zoho.com/accounts/validate/email"
            response = session.post(url, data={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                if 'already' in response.text.lower() or 'exists' in response.text.lower():
                    result['exists'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
        
        # ==================== CODING PLATFORMS ====================
        
        # ===== GITLAB =====
        elif site_name == 'gitlab':
            # Try password reset endpoint
            url = "https://gitlab.com/users/password"
            gitlab_headers = headers.copy()
            gitlab_headers['Content-Type'] = 'application/x-www-form-urlencoded'
            response = session.post(url, data={'user[email]': email}, headers=gitlab_headers, timeout=8, allow_redirects=False)
            if response.status_code == 302 or response.status_code == 200:
                # If redirect or success, account exists
                result['exists'] = True
            elif response.status_code == 422:
                # Check response for error about email not found
                if 'email not found' in response.text.lower():
                    result['exists'] = False
                else:
                    result['exists'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== BITBUCKET =====
        elif site_name == 'bitbucket':
            # Use password reset endpoint
            url = "https://bitbucket.org/account/password/reset/"
            response = session.post(url, data={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                # Check if it says email sent or no account
                if 'no account' not in response.text.lower() and 'not found' not in response.text.lower():
                    result['exists'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== STACKOVERFLOW =====
        elif site_name == 'stackoverflow':
            # Use account recovery check
            url = "https://stackoverflow.com/users/account-recovery"
            so_headers = headers.copy()
            so_headers['Content-Type'] = 'application/x-www-form-urlencoded'
            response = session.post(url, data={'email': email}, headers=so_headers, timeout=8)
            if response.status_code == 200:
                # If no error about email not found, account may exist
                if 'could not find' not in response.text.lower() and 'no user' not in response.text.lower():
                    if 'recovery' in response.text.lower() or 'sent' in response.text.lower():
                        result['exists'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== HACKERRANK =====
        elif site_name == 'hackerrank':
            # Use login check endpoint - if it says "invalid login or password", account exists
            url = "https://www.hackerrank.com/rest/auth/login"
            hr_headers = headers.copy()
            hr_headers['Content-Type'] = 'application/json'
            response = session.post(url, json={'login': email, 'password': 'wrongpassword123!', 'remember_me': False}, headers=hr_headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    # "Invalid login or password" means account EXISTS but wrong password
                    if data.get('status') == False:
                        errors = data.get('errors', [])
                        for err in errors:
                            if 'invalid' in err.lower() and 'password' in err.lower():
                                result['exists'] = True
                                break
                        # Also check internal status
                        if data.get('internal_status_code') == 'login_invalid':
                            result['exists'] = True
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== LEETCODE =====
        elif site_name == 'leetcode':
            # LeetCode uses Cloudflare protection - limited detection capability
            # Try to check if username derived from email exists
            try:
                username = email.split('@')[0]
                url = "https://leetcode.com/graphql/"
                query = {
                    "operationName": "getUserProfile",
                    "variables": {"username": username},
                    "query": "query getUserProfile($username: String!) { matchedUser(username: $username) { username profile { realName } } }"
                }
                lc_headers = headers.copy()
                lc_headers['Content-Type'] = 'application/json'
                response = session.post(url, json=query, headers=lc_headers, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('data', {}).get('matchedUser'):
                        result['exists'] = True
                        matched = data['data']['matchedUser']
                        result['others'] = {'Username': matched.get('username', '')}
                elif response.status_code == 429:
                    result['rateLimit'] = True
                else:
                    result['error'] = True
            except:
                result['error'] = True
                    
        # ===== CODECHEF =====
        elif site_name == 'codechef':
            url = "https://www.codechef.com/api/user/email-exists"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('exists', False) or data.get('result', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== CODEFORCES =====
        elif site_name == 'codeforces':
            url = "https://codeforces.com/register"
            response = session.post(url, data={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                if 'already registered' in response.text.lower() or 'already used' in response.text.lower():
                    result['exists'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== KAGGLE =====
        elif site_name == 'kaggle':
            url = "https://www.kaggle.com/api/v1/users/check-email"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('isRegistered', False) or data.get('exists', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== CODEWARS =====
        elif site_name == 'codewars':
            url = "https://www.codewars.com/api/v1/users/check_email"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('exists', False) or not data.get('available', True)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== EXERCISM =====
        elif site_name == 'exercism':
            url = "https://exercism.org/api/v2/validate_email"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = not data.get('valid', True) or data.get('taken', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== FREECODECAMP =====
        elif site_name == 'freecodecamp':
            url = "https://api.freecodecamp.org/api/users/exists"
            response = session.get(url, params={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('exists', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== GLITCH =====
        elif site_name == 'glitch':
            url = "https://api.glitch.com/v1/users/by/email"
            response = session.get(url, params={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                result['exists'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            elif response.status_code != 404:
                result['error'] = True
            
        # ===== HEROKU =====
        elif site_name == 'heroku':
            url = "https://id.heroku.com/account/accept/check"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('exists', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== VERCEL =====
        elif site_name == 'vercel':
            url = "https://vercel.com/api/registration/email"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200 or response.status_code == 400:
                if 'exists' in response.text.lower() or 'already' in response.text.lower():
                    result['exists'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== NETLIFY =====
        elif site_name == 'netlify':
            url = "https://api.netlify.com/api/v1/accounts/lookup"
            response = session.get(url, params={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                result['exists'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            elif response.status_code != 404:
                result['error'] = True
            
        # ===== CODESANDBOX =====
        elif site_name == 'codesandbox':
            url = "https://codesandbox.io/api/v1/users/check_email"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('exists', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== CODEPEN =====
        elif site_name == 'codepen':
            url = "https://codepen.io/signup/check/email"
            response = session.post(url, data={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = not data.get('available', True)
                except:
                    if 'taken' in response.text.lower():
                        result['exists'] = True
                    else:
                        result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                        
        # ===== NPM =====
        elif site_name == 'npm':
            # Try to check via npmjs signup
            url = "https://www.npmjs.com/signup/check-email"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = not data.get('available', True)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== PYPI =====
        elif site_name == 'pypi':
            url = "https://pypi.org/account/register/"
            response = session.post(url, data={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                if 'already' in response.text.lower() or 'exists' in response.text.lower():
                    result['exists'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== JETBRAINS =====
        elif site_name == 'jetbrains':
            url = "https://account.jetbrains.com/api/v1/accounts/check-email"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('registered', False) or data.get('exists', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== HACKEREARTH =====
        elif site_name == 'hackerearth':
            url = "https://www.hackerearth.com/api/v2/auth/email-exists/"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('exists', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== TOPCODER =====
        elif site_name == 'topcoder':
            url = "https://api.topcoder.com/v3/users/validateEmail"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = not data.get('valid', True)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== SOURCEFORGE =====
        elif site_name == 'sourceforge':
            url = "https://sourceforge.net/auth/signup"
            response = session.post(url, data={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                if 'already' in response.text.lower() or 'exists' in response.text.lower():
                    result['exists'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== LAUNCHPAD =====
        elif site_name == 'launchpad':
            url = "https://login.launchpad.net/+login"
            response = session.post(url, data={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                if 'already' in response.text.lower():
                    result['exists'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== GITBOOK =====
        elif site_name == 'gitbook':
            url = "https://api.gitbook.com/v1/auth/check-email"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('exists', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== DEV.TO =====
        elif site_name == 'devto':
            url = "https://dev.to/users/check_email"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = not data.get('available', True)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== HASHNODE =====
        elif site_name == 'hashnode':
            url = "https://hashnode.com/api/check-email"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('exists', False) or data.get('registered', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== MEDIUM =====
        elif site_name == 'medium':
            url = "https://medium.com/_/api/users/email-check"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    # Medium returns ])}while(1);</x> prefix
                    text = response.text.replace("])}while(1);</x>", "")
                    data = json.loads(text)
                    result['exists'] = data.get('payload', {}).get('value', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== DIGITALOCEAN =====
        elif site_name == 'digitalocean':
            url = "https://cloud.digitalocean.com/api/v1/accounts/exists"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('exists', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== RENDER =====
        elif site_name == 'render':
            url = "https://api.render.com/v1/check-email"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('exists', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== RAILWAY =====
        elif site_name == 'railway':
            url = "https://backboard.railway.app/graphql/v2"
            graphql_query = {
                'query': 'query { userByEmail(email: "' + email + '") { id } }'
            }
            response = session.post(url, json=graphql_query, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('data', {}).get('userByEmail') is not None
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== SUPABASE =====
        elif site_name == 'supabase':
            url = "https://app.supabase.com/api/auth/check-email"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('exists', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== FIREBASE =====
        elif site_name == 'firebase':
            url = "https://console.firebase.google.com/api/auth/check-email"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('registered', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== POSTMAN =====
        elif site_name == 'postman':
            url = "https://identity.getpostman.com/api/v1/users/exists"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('exists', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== FIGMA =====
        elif site_name == 'figma':
            url = "https://www.figma.com/api/user/email_exists"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('exists', False) or data.get('email_exists', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== NOTION =====
        elif site_name == 'notion':
            url = "https://www.notion.so/api/v3/getSpaces"
            notion_headers = headers.copy()
            notion_headers['Content-Type'] = 'application/json'
            response = session.post(url, json={'email': email}, headers=notion_headers, timeout=8)
            if response.status_code == 401:
                result['exists'] = True  # Account exists but wrong auth
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                
        # ===== TRELLO =====
        elif site_name == 'trello':
            url = f"https://trello.com/1/members/{email.split('@')[0]}"
            response = session.get(url, headers=headers, timeout=8)
            if response.status_code == 200:
                result['exists'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            elif response.status_code != 404:
                result['error'] = True
            
        # ===== DRIBBBLE =====
        elif site_name == 'dribbble':
            url = "https://dribbble.com/signup/check_email"
            response = session.post(url, data={'user[email]': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                if 'taken' in response.text.lower() or 'already' in response.text.lower():
                    result['exists'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== BEHANCE =====
        elif site_name == 'behance':
            url = "https://www.behance.net/v2/account/email"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = not data.get('available', True)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
        
        # ==================== ADDITIONAL PLATFORMS ====================
        
        # ===== SLACK =====
        elif site_name == 'slack':
            url = "https://slack.com/api/users.admin.checkEmail"
            response = session.post(url, data={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = not data.get('ok', True) or data.get('user_exists', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== ZOOM =====
        elif site_name == 'zoom':
            url = "https://zoom.us/signin"
            zoom_headers = headers.copy()
            zoom_headers['Content-Type'] = 'application/x-www-form-urlencoded'
            response = session.post(url, data={'email': email}, headers=zoom_headers, timeout=8)
            if response.status_code == 200:
                if 'password' in response.text.lower() or 'sign in' in response.text.lower():
                    result['exists'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== DROPBOX =====
        elif site_name == 'dropbox':
            url = "https://www.dropbox.com/login"
            response = session.post(url, data={'login_email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                if 'password' in response.text.lower() and 'incorrect' not in response.text.lower():
                    result['exists'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== REDDIT =====
        elif site_name == 'reddit':
            url = "https://www.reddit.com/api/check_email.json"
            response = session.post(url, data={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = not data.get('available', True)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== TIKTOK =====
        elif site_name == 'tiktok':
            url = "https://www.tiktok.com/api/user/check_email/"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('is_registered', False) or not data.get('available', True)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== AIRBNB =====
        elif site_name == 'airbnb':
            url = "https://www.airbnb.com/api/v2/auth/email_exists"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('email_exists', False) or data.get('exists', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== CANVA =====
        elif site_name == 'canva':
            url = "https://www.canva.com/_ajax/api/v2/auth/check_email"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('registered', False) or data.get('exists', False)
                except:
                    result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                    
        # ===== BOOKING =====
        elif site_name == 'booking':
            url = "https://account.booking.com/api/account/check_email"
            response = session.post(url, json={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['exists'] = data.get('exists', False) or data.get('registered', False)
                except:
                    if 'exists' in response.text.lower():
                        result['exists'] = True
                    else:
                        result['error'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
                        
        # ===== MAILCHIMP =====
        elif site_name == 'mailchimp':
            url = "https://login.mailchimp.com/signup/email"
            response = session.post(url, data={'email': email}, headers=headers, timeout=8)
            if response.status_code == 200:
                if 'already' in response.text.lower() or 'exists' in response.text.lower():
                    result['exists'] = True
            elif response.status_code == 429:
                result['rateLimit'] = True
            else:
                result['error'] = True
        
        # ===== DEFAULT - Mark as unchecked =====
        else:
            result['error'] = True
            result['others'] = {'Message': 'No check method available'}
            
    except requests.exceptions.Timeout:
        result['rateLimit'] = True
    except requests.exceptions.ConnectionError:
        result['error'] = True
    except requests.exceptions.RequestException as e:
        result['error'] = True
    except Exception as e:
        result['error'] = True
        
    return result


# List of websites to check (100 platforms)
EMAIL_CHECK_SITES = [
    # Social Media
    ('twitter', 'twitter.com'),
    ('instagram', 'instagram.com'),
    ('pinterest', 'pinterest.com'),
    ('tumblr', 'tumblr.com'),
    ('linkedin', 'linkedin.com'),
    ('mewe', 'mewe.com'),
    
    # Music & Entertainment
    ('spotify', 'spotify.com'),
    ('soundcloud', 'soundcloud.com'),
    ('lastfm', 'last.fm'),
    ('smule', 'smule.com'),
    ('twitch', 'twitch.tv'),
    ('wattpad', 'wattpad.com'),
    
    # ==================== CODING & DEVELOPMENT ====================
    # Version Control & Code Hosting
    ('github', 'github.com'),
    ('gitlab', 'gitlab.com'),
    ('bitbucket', 'bitbucket.org'),
    ('sourceforge', 'sourceforge.net'),
    ('launchpad', 'launchpad.net'),
    ('gitbook', 'gitbook.io'),
    
    # Competitive Programming & Learning
    ('hackerrank', 'hackerrank.com'),
    ('leetcode', 'leetcode.com'),
    ('codechef', 'codechef.com'),
    ('codeforces', 'codeforces.com'),
    ('topcoder', 'topcoder.com'),
    ('hackerearth', 'hackerearth.com'),
    ('codewars', 'codewars.com'),
    ('exercism', 'exercism.org'),
    ('freecodecamp', 'freecodecamp.org'),
    ('kaggle', 'kaggle.com'),
    ('codecademy', 'codecademy.com'),
    
    # Code Playground & IDE
    ('replit', 'replit.com'),
    ('codesandbox', 'codesandbox.io'),
    ('codepen', 'codepen.io'),
    ('glitch', 'glitch.com'),
    ('stackoverflow', 'stackoverflow.com'),
    
    # Cloud & Deployment
    ('heroku', 'heroku.com'),
    ('vercel', 'vercel.com'),
    ('netlify', 'netlify.com'),
    ('digitalocean', 'digitalocean.com'),
    ('render', 'render.com'),
    ('railway', 'railway.app'),
    ('supabase', 'supabase.com'),
    ('firebase', 'firebase.google.com'),
    
    # Package Registries
    ('npm', 'npmjs.com'),
    ('pypi', 'pypi.org'),
    ('docker', 'hub.docker.com'),
    
    # Developer Tools & Productivity
    ('jetbrains', 'jetbrains.com'),
    ('postman', 'postman.com'),
    ('figma', 'figma.com'),
    ('notion', 'notion.so'),
    ('trello', 'trello.com'),
    
    # Developer Blogging & Community
    ('devto', 'dev.to'),
    ('hashnode', 'hashnode.com'),
    ('medium', 'medium.com'),
    
    # Design & Creative (Dev-Related)
    ('dribbble', 'dribbble.com'),
    ('behance', 'behance.net'),
    
    # ==================== END CODING PLATFORMS ====================
    
    # Professional Platforms
    ('gravatar', 'gravatar.com'),
    ('discord', 'discord.com'),
    ('atlassian', 'atlassian.com'),
    ('freelancer', 'freelancer.com'),
    ('envato', 'envato.com'),
    ('hubspot', 'hubspot.com'),
    ('xing', 'xing.com'),
    ('bitly', 'bitly.com'),
    
    # Shopping & Services  
    ('amazon', 'amazon.com'),
    ('ebay', 'ebay.com'),
    ('flipkart', 'flipkart.com'),
    ('lazada', 'lazada.com'),
    ('tokopedia', 'tokopedia.com'),
    ('shopify', 'shopify.com'),
    ('deliveroo', 'deliveroo.com'),
    
    # Productivity & Tools
    ('adobe', 'adobe.com'),
    ('wordpress', 'wordpress.com'),
    ('firefox', 'firefox.com'),
    ('evernote', 'evernote.com'),
    ('zoho', 'zoho.com'),
    ('google', 'google.com'),
    
    # Community & Social
    ('quora', 'quora.com'),
    ('patreon', 'patreon.com'),
    ('buymeacoffee', 'buymeacoffee.com'),
    ('bodybuilding', 'bodybuilding.com'),
    ('picsart', 'picsart.com'),
    ('reddit', 'reddit.com'),
    ('tiktok', 'tiktok.com'),
    
    # Learning
    ('duolingo', 'duolingo.com'),
    
    # Tech & Gaming
    ('samsung', 'samsung.com'),
    ('strava', 'strava.com'),
    
    # Finance
    ('venmo', 'venmo.com'),
    ('vivino', 'vivino.com'),
    
    # Media
    ('imgur', 'imgur.com'),
    ('issuu', 'issuu.com'),
    ('eventbrite', 'eventbrite.com'),
    ('archiveorg', 'archive.org'),
    
    # Communication & Collaboration
    ('yahoo', 'yahoo.com'),
    ('slack', 'slack.com'),
    ('zoom', 'zoom.us'),
    ('dropbox', 'dropbox.com'),
    ('mailchimp', 'mailchimp.com'),
    
    # Travel & Booking
    ('airbnb', 'airbnb.com'),
    ('booking', 'booking.com'),
    
    # Design
    ('canva', 'canva.com'),
]


def run_email_checks_threaded(email: str, sites: list, max_workers: int = 15) -> list:
    """Run email checks using thread pool for parallel execution."""
    results = []
    total = len(sites)
    completed = 0
    lock = threading.Lock()
    
    def check_and_append(site_tuple):
        nonlocal completed
        site_name, domain = site_tuple
        result = check_email_on_site(site_name, domain, email)
        with lock:
            completed += 1
            print(f"\r {Cy}[{completed}/{total}] Checking {domain}...{' ' * 20}", end='', flush=True)
        return result
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(check_and_append, site) for site in sites]
        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                pass
                
    print(f"\r{' ' * 60}\r", end='')
    return sorted(results, key=lambda x: x['domain'])


@is_option
def email_footprint():
    """Search for email address footprint across multiple websites."""
    email = input(f"\n {Wh}Enter email address {Gr}(e.g., user@example.com){Wh}: {Gr}").strip()
    
    if not email:
        print(f"{Re}Error: Please enter an email address.")
        return
    
    # Basic email validation
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        print(f"{Re}Error: Invalid email format.")
        return
    
    print(f"\n {Wh}{'*' * (len(email) + 6)}")
    print(f" {Wh}   {Gr}{email}")
    print(f" {Wh}{'*' * (len(email) + 6)}")
    
    # Extract email components
    local_part, domain = email.split('@')
    email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
    
    print(f"\n {Wh}Local Part: {Gr}{local_part}")
    print(f" {Wh}Domain: {Gr}{domain}")
    print(f" {Wh}MD5 Hash: {Gr}{email_hash}")
    
    start_time = time.time()
    print(f"\n {Cy}Checking {len(EMAIL_CHECK_SITES)} websites...\n")
    
    # Run checks
    results = run_email_checks_threaded(email, EMAIL_CHECK_SITES, max_workers=10)
    
    elapsed_time = round(time.time() - start_time, 2)
    
    # Categorize results
    found = [r for r in results if r['exists'] == True]
    not_found = [r for r in results if r['exists'] == False and not r['error'] and not r['rateLimit']]
    rate_limited = [r for r in results if r['rateLimit']]
    errors = [r for r in results if r['error']]
    
    # Print results
    print(f"\n {Wh}========== {Gr}EMAIL FOOTPRINT RESULTS {Wh}==========")
    
    # Show FOUND sites
    print(f"\n {Gr}[+] EMAIL REGISTERED {Wh}({len(found)} sites):")
    if found:
        for r in found:
            extra = ""
            if r.get('emailrecovery'):
                extra += f" | Recovery: {r['emailrecovery']}"
            if r.get('phoneNumber'):
                extra += f" | Phone: {r['phoneNumber']}"
            if r.get('others'):
                for k, v in r['others'].items():
                    if v:
                        extra += f" | {k}: {v}"
            print(f" {Wh}[ {Gr}+ {Wh}] {r['domain']}{Gr}{extra}")
    else:
        print(f" {Ye}   No registered accounts found")
    
    # Show NOT FOUND sites
    print(f"\n {Mage}[-] NOT REGISTERED {Wh}({len(not_found)} sites):")
    if not_found:
        not_found_domains = [r['domain'] for r in not_found]
        # Print in columns
        for i in range(0, len(not_found_domains), 3):
            row = not_found_domains[i:i+3]
            print(f" {Wh}[ {Mage}- {Wh}] " + ", ".join(row))
    else:
        print(f" {Ye}   All sites either found, rate-limited, or errored")
    
    # Show RATE LIMITED sites
    if rate_limited:
        print(f"\n {Ye}[x] RATE LIMITED {Wh}({len(rate_limited)} sites):")
        rate_limited_domains = [r['domain'] for r in rate_limited]
        for i in range(0, len(rate_limited_domains), 3):
            row = rate_limited_domains[i:i+3]
            print(f" {Wh}[ {Ye}x {Wh}] " + ", ".join(row))
    
    # Show ERROR sites
    if errors:
        print(f"\n {Re}[!] CHECK FAILED {Wh}({len(errors)} sites):")
        error_domains = [r['domain'] for r in errors]
        for i in range(0, len(error_domains), 3):
            row = error_domains[i:i+3]
            print(f" {Wh}[ {Re}! {Wh}] " + ", ".join(row))
    
    # Check breach databases
    print(f"\n {Cy}[*] Checking breach databases...")
    try:
        hibp_url = f"https://haveibeenpwned.com/unifiedsearch/{email}"
        response = requests.get(hibp_url, timeout=10, headers={
            'User-Agent': get_random_useragent(),
            'Accept': 'application/json'
        })
        if response.status_code == 200:
            breach_data = response.json()
            if breach_data.get('Breaches'):
                breaches = breach_data['Breaches']
                print(f"\n {Re}[⚠ SECURITY ALERT] {Wh}Found in {len(breaches)} data breach(es):")
                for breach in breaches[:10]:
                    print(f" {Wh}[ {Re}! {Wh}] {breach.get('Name', 'Unknown')}")
                if len(breaches) > 10:
                    print(f" {Wh}   ... and {len(breaches) - 10} more")
            else:
                print(f" {Wh}[ {Gr}✓ {Wh}] No breaches found (good!)")
        elif response.status_code == 404:
            print(f" {Wh}[ {Gr}✓ {Wh}] No breaches found (good!)")
        else:
            print(f" {Wh}[ {Ye}? {Wh}] Could not check (status: {response.status_code})")
    except Exception as e:
        print(f" {Wh}[ {Ye}? {Wh}] Could not check breach database")
    
    # Summary
    print(f"\n {Wh}{'─' * 55}")
    print(f" {Wh}Summary: {Gr}{len(found)} found{Wh}, {Mage}{len(not_found)} not found{Wh}, {Ye}{len(rate_limited)} rate-limited{Wh}, {Re}{len(errors)} errors")
    print(f" {Wh}Checked {len(EMAIL_CHECK_SITES)} websites in {Gr}{elapsed_time}{Wh} seconds")
    print(f" {Wh}{'─' * 55}")


@is_option
def phone_footprint():
    """Search for phone number footprint across various services."""
    phone_input = input(
        f"\n {Wh}Enter phone number {Gr}Ex [+6281xxxxxxxxx] {Wh}: {Gr}").strip()
    
    if not phone_input:
        print(f"{Re}Error: Please enter a phone number.")
        return
    
    default_region = "ID"
    
    try:
        parsed_number = phonenumbers.parse(phone_input, default_region)
        
        if not phonenumbers.is_valid_number(parsed_number):
            print(f"{Ye}Warning: This may not be a valid phone number.")
        
        # Get phone info
        region_code = phonenumbers.region_code_for_number(parsed_number)
        phone_carrier = carrier.name_for_number(parsed_number, "en")
        location = geocoder.description_for_number(parsed_number, "en")
        phone_type = phonenumbers.number_type(parsed_number)
        e164_format = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)
        national_format = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.NATIONAL)
        
        results = {'found': [], 'messaging_apps': [], 'info': {}}
        
        print(f"\n {Wh}========== {Gr}PHONE NUMBER FOOTPRINT {Wh}==========")
        print(f"\n {Wh}Target Number: {Gr}{e164_format}")
        print(f" {Wh}National Format: {Gr}{national_format}")
        print(f" {Wh}Country/Region: {Gr}{location or region_code or 'Unknown'}")
        print(f" {Wh}Carrier: {Gr}{phone_carrier or 'Unknown'}")
        
        # Determine phone type
        type_map = {
            phonenumbers.PhoneNumberType.MOBILE: "Mobile",
            phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed-line",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed-line/Mobile",
            phonenumbers.PhoneNumberType.TOLL_FREE: "Toll-free",
            phonenumbers.PhoneNumberType.VOIP: "VoIP",
        }
        phone_type_str = type_map.get(phone_type, "Unknown")
        print(f" {Wh}Type: {Gr}{phone_type_str}")
        
        loading_animation("Searching for phone footprint", 1.5)
        
        # Services commonly associated with phone numbers
        messaging_services = [
            {"name": "WhatsApp", "url": f"https://wa.me/{e164_format.replace('+', '')}", "check": "whatsapp"},
            {"name": "Telegram", "url": f"https://t.me/+{e164_format.replace('+', '')}", "check": "telegram"},
            {"name": "Viber", "url": "https://www.viber.com/", "check": "viber"},
            {"name": "Signal", "url": "https://signal.org/", "check": "signal"},
            {"name": "WeChat", "url": "https://www.wechat.com/", "check": "wechat"},
            {"name": "LINE", "url": "https://line.me/", "check": "line"},
        ]
        
        social_services = [
            {"name": "Facebook", "url": "https://www.facebook.com/"},
            {"name": "Instagram", "url": "https://www.instagram.com/"},
            {"name": "Twitter/X", "url": "https://twitter.com/"},
            {"name": "LinkedIn", "url": "https://www.linkedin.com/"},
            {"name": "TikTok", "url": "https://www.tiktok.com/"},
            {"name": "Snapchat", "url": "https://www.snapchat.com/"},
        ]
        
        other_services = [
            {"name": "Google", "url": "https://accounts.google.com/"},
            {"name": "Apple", "url": "https://appleid.apple.com/"},
            {"name": "Microsoft", "url": "https://account.microsoft.com/"},
            {"name": "Amazon", "url": "https://www.amazon.com/"},
            {"name": "PayPal", "url": "https://www.paypal.com/"},
            {"name": "Uber", "url": "https://www.uber.com/"},
            {"name": "Grab", "url": "https://www.grab.com/"},
            {"name": "Gojek", "url": "https://www.gojek.com/"},
        ]
        
        # Check WhatsApp (can be partially verified)
        print(f"\n {Cy}[1] Checking messaging apps...")
        print(f" {Wh}[ {Gr}→ {Wh}] WhatsApp: {Gr}https://wa.me/{e164_format.replace('+', '')}")
        print(f" {Wh}     {Ye}(Click link to check if registered)")
        results['messaging_apps'].append({
            'name': 'WhatsApp',
            'url': f"https://wa.me/{e164_format.replace('+', '')}",
            'status': 'Check manually'
        })
        
        print(f" {Wh}[ {Gr}→ {Wh}] Telegram: {Gr}https://t.me/+{e164_format.replace('+', '')}")
        results['messaging_apps'].append({
            'name': 'Telegram',
            'url': f"https://t.me/+{e164_format.replace('+', '')}",
            'status': 'Check manually'
        })
        
        # Check Truecaller-like services (using available APIs)
        print(f"\n {Cy}[2] Checking caller ID services...")
        
        # NumVerify API (free tier)
        try:
            clean_number = e164_format.replace('+', '')
            numverify_url = f"http://apilayer.net/api/validate?access_key=YOUR_API_KEY&number={clean_number}"
            # Note: This would need a real API key to work
            print(f" {Wh}[ {Ye}? {Wh}] NumVerify: API key required for lookup")
        except:
            pass
        
        # Search for potential social media profiles
        print(f"\n {Cy}[3] Potential social media associations...")
        print(f" {Wh}The following services commonly use phone numbers for registration:")
        
        for service in social_services:
            print(f" {Wh}[ {Cy}? {Wh}] {service['name']}: {Ye}May be registered")
        
        print(f"\n {Cy}[4] Other services...")
        for service in other_services:
            print(f" {Wh}[ {Cy}? {Wh}] {service['name']}: {Ye}May be registered")
        
        # Generate search queries
        print(f"\n {Cy}[5] Search suggestions...")
        search_queries = [
            f'"{e164_format}"',
            f'"{national_format}"',
            f'"{phone_input}"',
        ]
        
        print(f" {Wh}Try these Google dorks to find more info:")
        for query in search_queries:
            encoded_query = query.replace('"', '%22').replace(' ', '+')
            print(f" {Wh}[ {Gr}→ {Wh}] https://www.google.com/search?q={encoded_query}")
        
        # Summary
        print(f"\n {Wh}{'─' * 50}")
        print(f"\n {Gr}[SUMMARY] {Wh}Phone Number Analysis:")
        print(f" {Wh}• Number: {Gr}{e164_format}")
        print(f" {Wh}• Location: {Gr}{location or 'Unknown'}")
        print(f" {Wh}• Carrier: {Gr}{phone_carrier or 'Unknown'}")
        print(f" {Wh}• Type: {Gr}{phone_type_str}")
        
        print(f"\n {Wh}[MESSAGING APPS]")
        for app in results['messaging_apps']:
            print(f" {Wh}• {app['name']}: {Gr}{app['url']}")
        
        print(f"\n {Wh}{'─' * 50}")
        print(f" {Ye}Note: Most services require manual verification.")
        print(f" {Ye}Phone number lookups are limited without paid APIs.")
        print(f" {Ye}For detailed caller ID info, consider Truecaller or similar services.")
        
    except phonenumbers.phonenumberutil.NumberParseException as e:
        print(f"{Re}Error parsing phone number: {e}")
    except Exception as e:
        print(f"{Re}Error: {e}")


@is_option
def TrackLu():
    """Search for username across multiple social media platforms."""
    try:
        username = input(f"\n {Wh}Enter Username : {Gr}").strip()
        
        if not username:
            print(f"{Re}Error: Please enter a username.")
            return
        
        # Validate username (basic alphanumeric check)
        if not re.match(r'^[\w.]+$', username):
            print(f"{Ye}Warning: Username contains special characters that may not work on all platforms.")
        
        results = {'found': [], 'not_found': []}
        
        # Removed duplicate Snapchat entry from original list
        social_media = [
            {"url": "https://www.facebook.com/{}", "name": "Facebook"},
            {"url": "https://www.twitter.com/{}", "name": "Twitter/X"},
            {"url": "https://www.instagram.com/{}", "name": "Instagram"},
            {"url": "https://www.linkedin.com/in/{}", "name": "LinkedIn"},
            {"url": "https://www.github.com/{}", "name": "GitHub"},
            {"url": "https://www.pinterest.com/{}", "name": "Pinterest"},
            {"url": "https://www.tumblr.com/{}", "name": "Tumblr"},
            {"url": "https://www.youtube.com/@{}", "name": "Youtube"},
            {"url": "https://soundcloud.com/{}", "name": "SoundCloud"},
            {"url": "https://www.snapchat.com/add/{}", "name": "Snapchat"},
            {"url": "https://www.tiktok.com/@{}", "name": "TikTok"},
            {"url": "https://www.behance.net/{}", "name": "Behance"},
            {"url": "https://www.medium.com/@{}", "name": "Medium"},
            {"url": "https://www.quora.com/profile/{}", "name": "Quora"},
            {"url": "https://www.flickr.com/people/{}", "name": "Flickr"},
            {"url": "https://www.twitch.tv/{}", "name": "Twitch"},
            {"url": "https://www.dribbble.com/{}", "name": "Dribbble"},
            {"url": "https://www.reddit.com/user/{}", "name": "Reddit"},
            {"url": "https://www.telegram.me/{}", "name": "Telegram"},
            {"url": "https://weheartit.com/{}", "name": "We Heart It"},
            {"url": "https://open.spotify.com/user/{}", "name": "Spotify"},
            {"url": "https://mastodon.social/@{}", "name": "Mastodon"},

            {"url": "https://www.deviantart.com/{}", "name": "DeviantArt"},
            {"url": "https://www.goodreads.com/{}", "name": "Goodreads"},
            {"url": "https://www.vimeo.com/{}", "name": "Vimeo"},
            {"url": "https://www.badoo.com/{}", "name": "Badoo"},
            {"url": "https://www.myspace.com/{}", "name": "MySpace"},
            {"url": "https://www.classmates.com/people/{}", "name": "Classmates"},
            {"url": "https://www.yelp.com/user_details?userid={}", "name": "Yelp"},
            {"url": "https://www.last.fm/user/{}", "name": "Last.fm"},
            {"url": "https://www.mixcloud.com/{}", "name": "Mixcloud"},
            {"url": "https://www.taringa.net/{}", "name": "Taringa"},
            {"url": "https://www.xing.com/profile/{}", "name": "Xing"},
            {"url": "https://www.tripadvisor.com/members/{}", "name": "TripAdvisor"},
            {"url": "https://www.bandcamp.com/{}", "name": "Bandcamp"},
            {"url": "https://www.codementor.io/{}", "name": "Codementor"},
            {"url": "https://www.producthunt.com/@{}", "name": "Product Hunt"},
            {"url": "https://www.behance.net/{}", "name": "Behance"},
            {"url": "https://www.patreon.com/{}", "name": "Patreon"},
            {"url": "https://www.ello.co/{}", "name": "Ello"},
            {"url": "https://www.soundcloud.com/{}", "name": "SoundCloud"},
            {"url": "https://www.whatsapp.com/{}", "name": "WhatsApp"},
            {"url": "https://www.signal.org/{}", "name": "Signal"},


        ]
        
        total = len(social_media)
        print(f"\n {Wh}Searching across {Gr}{total}{Wh} platforms...\n")
        
        for i, site in enumerate(social_media, 1):
            url = site['url'].format(username)
            print(f"\r {Cy}[{i}/{total}] Checking {site['name']}...{' ' * 20}", end='', flush=True)
            
            try:
                response = requests.get(url, timeout=5, allow_redirects=True, 
                                        headers={'User-Agent': 'Mozilla/5.0'})
                if response.status_code == 200:
                    results['found'].append({'name': site['name'], 'url': url})
                else:
                    results['not_found'].append(site['name'])
            except requests.exceptions.RequestException:
                results['not_found'].append(site['name'])
        
        print(f"\r{' ' * 60}\r", end='')  # Clear the progress line
        
        print(f"\n {Wh}========== {Gr}SHOW INFORMATION USERNAME {Wh}==========")
        print(f"\n {Wh}Username: {Gr}{username}")
        print(f"\n {Gr}[FOUND] {Wh}Potential matches ({len(results['found'])}):")
        
        if results['found']:
            for item in results['found']:
                print(f" {Wh}[ {Gr}✓ {Wh}] {item['name']}: {Gr}{item['url']}")
        else:
            print(f" {Ye}No profiles found.")
        
        print(f"\n {Ye}[NOT FOUND] {Wh}({len(results['not_found'])}):")
        for name in results['not_found']:
            print(f" {Wh}[ {Re}✗ {Wh}] {name}")
            
    except KeyboardInterrupt:
        print(f"\n{Ye}Search cancelled.")
    except Exception as e:
        print(f"{Re}Error : {e}")


@is_option
def showIP():
    """Display the current machine's public IP address."""
    loading_animation("Fetching your IP address", 1.0)
    
    response = make_request('https://api.ipify.org/')
    if not response:
        # Try fallback API
        response = make_request('https://icanhazip.com/')
    
    if response:
        Show_IP = response.text.strip()
        print(f"\n {Wh}========== {Gr}SHOW INFORMATION YOUR IP {Wh}==========")
        print(f"\n {Wh}[{Gr} + {Wh}] Your IP Address : {Gr}{Show_IP}")
        print(f"\n {Wh}==============================================")
    else:
        print(f"{Re}Failed to fetch your IP address. Please check your connection.")


@is_option
def whois_lookup():
    """Perform WHOIS lookup for a domain."""
    domain = input(f"\n {Wh}Enter domain name {Gr}(e.g., example.com){Wh}: {Gr}").strip()
    
    if not domain:
        print(f"{Re}Error: Please enter a domain name.")
        return
    
    # Clean the domain
    domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
    
    loading_animation("Fetching WHOIS data", 1.5)
    print(f"\n {Wh}========== {Gr}WHOIS INFORMATION {Wh}==========")
    
    # Try multiple WHOIS APIs
    whois_data = None
    used_api = None
    
    # API 1: RDAP via Verisign (for .com, .net)
    tld = domain.split('.')[-1].lower()
    rdap_servers = {
        'com': 'https://rdap.verisign.com/com/v1/domain/',
        'net': 'https://rdap.verisign.com/net/v1/domain/',
        'org': 'https://rdap.publicinterestregistry.org/rdap/domain/',
        'io': 'https://rdap.nic.io/domain/',
        'co': 'https://rdap.nic.co/domain/',
    }
    
    # Try RDAP first
    rdap_url = rdap_servers.get(tld, f'https://rdap.org/domain/')
    response = make_request(f"{rdap_url}{domain}")
    
    if response and response.status_code == 200:
        try:
            whois_data = response.json()
            used_api = "RDAP"
        except:
            pass
    
    # Fallback: Try whoisjson.com API
    if not whois_data:
        response = make_request(f"https://whoisjson.com/api/v1/whois?domain={domain}")
        if response and response.status_code == 200:
            try:
                whois_data = response.json()
                used_api = "whoisjson"
            except:
                pass
    
    # Fallback: Use ip-api for basic info + DNS
    if not whois_data:
        print(f"{Ye}Note: Full WHOIS data unavailable. Showing available information...{Wh}")
        print(f"\n {Wh}Domain           :{Gr} {domain}")
        
        # Get DNS info as fallback
        try:
            ip = socket.gethostbyname(domain)
            print(f" {Wh}Resolves to      :{Gr} {ip}")
            
            # Get IP info
            ip_response = make_request(f"http://ip-api.com/json/{ip}")
            if ip_response:
                ip_data = ip_response.json()
                if ip_data.get('status') == 'success':
                    print(f" {Wh}Hosted in        :{Gr} {ip_data.get('country', 'N/A')}, {ip_data.get('city', 'N/A')}")
                    print(f" {Wh}ISP              :{Gr} {ip_data.get('isp', 'N/A')}")
                    print(f" {Wh}Organization     :{Gr} {ip_data.get('org', 'N/A')}")
                    print(f" {Wh}AS               :{Gr} {ip_data.get('as', 'N/A')}")
        except socket.gaierror:
            print(f" {Re}Could not resolve domain.")
        
        # Get nameservers via DNS
        ns_response = make_request(f"https://dns.google/resolve?name={domain}&type=NS")
        if ns_response:
            try:
                ns_data = ns_response.json()
                answers = ns_data.get('Answer', [])
                if answers:
                    print(f" {Wh}Nameservers      :{Gr}")
                    for ns in answers[:5]:
                        print(f"   {Gr}• {ns.get('data', 'N/A')}")
            except:
                pass
        return
    
    # Parse RDAP response
    if used_api == "RDAP":
        try:
            print(f"\n {Wh}Domain           :{Gr} {domain}")
            print(f" {Wh}Handle           :{Gr} {whois_data.get('handle', 'N/A')}")
            
            # Status
            status = whois_data.get('status', [])
            print(f" {Wh}Status           :{Gr} {', '.join(status) if status else 'N/A'}")
            
            # Events (creation, expiration, etc.)
            events = whois_data.get('events', [])
            for event in events:
                action = event.get('eventAction', '').replace('registration', 'Created').replace('expiration', 'Expires').replace('last changed', 'Updated').replace('last update of RDAP database', 'RDAP Updated').title()
                date = event.get('eventDate', 'N/A')[:10] if event.get('eventDate') else 'N/A'
                if action and date != 'N/A':
                    print(f" {Wh}{action:17}:{Gr} {date}")
            
            # Nameservers
            nameservers = whois_data.get('nameservers', [])
            if nameservers:
                print(f" {Wh}Nameservers      :{Gr}")
                for ns in nameservers[:5]:
                    ns_name = ns.get('ldhName', '') if isinstance(ns, dict) else str(ns)
                    if ns_name:
                        print(f"   {Gr}• {ns_name}")
            
            # Entities (registrar, registrant info)
            entities = whois_data.get('entities', [])
            for entity in entities:
                roles = entity.get('roles', [])
                if 'registrar' in roles:
                    # Try to get registrar name
                    vcard = entity.get('vcardArray', [None, []])
                    if vcard and len(vcard) > 1:
                        for item in vcard[1]:
                            if isinstance(item, list) and item[0] == 'fn':
                                print(f" {Wh}Registrar        :{Gr} {item[3]}")
                                break
                    # Also try handle
                    if entity.get('handle'):
                        print(f" {Wh}Registrar ID     :{Gr} {entity.get('handle')}")
                        
        except Exception as e:
            print(f"{Re}Error parsing WHOIS data: {e}")
    
    # Parse whoisjson response
    elif used_api == "whoisjson":
        try:
            print(f"\n {Wh}Domain           :{Gr} {domain}")
            print(f" {Wh}Registrar        :{Gr} {whois_data.get('registrar', 'N/A')}")
            print(f" {Wh}Created          :{Gr} {whois_data.get('created', 'N/A')[:10] if whois_data.get('created') else 'N/A'}")
            print(f" {Wh}Expires          :{Gr} {whois_data.get('expires', 'N/A')[:10] if whois_data.get('expires') else 'N/A'}")
            print(f" {Wh}Updated          :{Gr} {whois_data.get('changed', 'N/A')[:10] if whois_data.get('changed') else 'N/A'}")
            
            ns = whois_data.get('nameservers', [])
            if ns:
                print(f" {Wh}Nameservers      :{Gr}")
                for n in ns[:5]:
                    print(f"   {Gr}• {n}")
        except Exception as e:
            print(f"{Re}Error parsing WHOIS data: {e}")


@is_option
def dns_lookup():
    """Perform DNS lookup for a domain."""
    domain = input(f"\n {Wh}Enter domain name {Gr}(e.g., example.com){Wh}: {Gr}").strip()
    
    if not domain:
        print(f"{Re}Error: Please enter a domain name.")
        return
    
    # Clean the domain
    domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
    
    loading_animation("Performing DNS lookup", 1.0)
    print(f"\n {Wh}========== {Gr}DNS RECORDS FOR {domain} {Wh}==========")
    
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    
    for record_type in record_types:
        response = make_request(f"https://dns.google/resolve?name={domain}&type={record_type}")
        if response:
            try:
                data = response.json()
                answers = data.get('Answer', [])
                if answers:
                    print(f"\n {Cy}[{record_type}]{Wh}")
                    for answer in answers:
                        print(f"   {Gr}• {answer.get('data', 'N/A')}")
            except:
                pass
    
    # Also get IP address using socket
    try:
        ip = socket.gethostbyname(domain)
        print(f"\n {Cy}[Resolved IP]{Wh}")
        print(f"   {Gr}• {ip}")
    except socket.gaierror:
        print(f"\n {Re}Could not resolve domain to IP address.")
    
    print(f"\n {Wh}==============================================")


@is_option
def website_headers():
    """Analyze website HTTP headers and security configuration."""
    url = input(f"\n {Wh}Enter URL {Gr}(e.g., https://example.com){Wh}: {Gr}").strip()
    
    if not url:
        print(f"{Re}Error: Please enter a URL.")
        return
    
    # Add https if no protocol specified
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    loading_animation("Analyzing headers", 1.5)
    print(f"\n {Wh}========== {Gr}WEBSITE HEADER ANALYSIS {Wh}==========")
    
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True,
                                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        
        print(f"\n {Wh}URL              :{Gr} {url}")
        print(f" {Wh}Final URL        :{Gr} {response.url}")
        print(f" {Wh}Status Code      :{Gr} {response.status_code}")
        print(f" {Wh}Response Time    :{Gr} {response.elapsed.total_seconds():.2f}s")
        
        headers = response.headers
        
        print(f"\n {Cy}[Server Info]{Wh}")
        print(f"   {Wh}Server          :{Gr} {headers.get('Server', 'Not disclosed')}")
        print(f"   {Wh}Powered By      :{Gr} {headers.get('X-Powered-By', 'Not disclosed')}")
        print(f"   {Wh}Content-Type    :{Gr} {headers.get('Content-Type', 'N/A')}")
        
        print(f"\n {Cy}[Security Headers]{Wh}")
        security_headers = {
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'X-Frame-Options': 'X-Frame-Options',
            'X-Content-Type-Options': 'X-Content-Type-Options',
            'X-XSS-Protection': 'XSS Protection',
            'Referrer-Policy': 'Referrer-Policy',
            'Permissions-Policy': 'Permissions-Policy',
        }
        
        for header, name in security_headers.items():
            value = headers.get(header)
            if value:
                print(f"   {Wh}{name:24}:{Gr} ✓ Present")
            else:
                print(f"   {Wh}{name:24}:{Re} ✗ Missing")
        
        print(f"\n {Cy}[Cookies]{Wh}")
        cookies = response.cookies
        if cookies:
            for cookie in cookies:
                secure = "🔒" if cookie.secure else "⚠️"
                httponly = "HTTP-Only" if cookie.has_nonstandard_attr('HttpOnly') else "Accessible"
                print(f"   {Gr}• {cookie.name} {secure} ({httponly})")
        else:
            print(f"   {Ye}No cookies set")
            
    except requests.exceptions.SSLError:
        print(f"{Re}SSL Certificate Error - The site may have an invalid certificate.")
    except requests.exceptions.ConnectionError:
        print(f"{Re}Connection Error - Could not connect to the website.")
    except Exception as e:
        print(f"{Re}Error: {e}")


@is_option
def password_generator():
    """Generate secure random passwords."""
    print(f"\n {Wh}========== {Gr}PASSWORD GENERATOR {Wh}==========")
    
    try:
        length_input = input(f"\n {Wh}Password length {Gr}(8-128, default: 16){Wh}: {Gr}").strip()
        length = int(length_input) if length_input else 16
        
        if length < 8:
            print(f"{Ye}Warning: Password length increased to minimum of 8 characters.")
            length = 8
        elif length > 128:
            print(f"{Ye}Warning: Password length reduced to maximum of 128 characters.")
            length = 128
        
        count_input = input(f" {Wh}How many passwords {Gr}(1-10, default: 5){Wh}: {Gr}").strip()
        count = int(count_input) if count_input else 5
        count = min(max(count, 1), 10)
        
        print(f"\n {Wh}Include options:")
        use_upper = input(f" {Wh}  Uppercase (A-Z)? {Gr}[Y/n]{Wh}: {Gr}").strip().lower() != 'n'
        use_lower = input(f" {Wh}  Lowercase (a-z)? {Gr}[Y/n]{Wh}: {Gr}").strip().lower() != 'n'
        use_digits = input(f" {Wh}  Numbers (0-9)? {Gr}[Y/n]{Wh}: {Gr}").strip().lower() != 'n'
        use_special = input(f" {Wh}  Special chars? {Gr}[Y/n]{Wh}: {Gr}").strip().lower() != 'n'
        
        # Build character set
        chars = ''
        if use_upper:
            chars += string.ascii_uppercase
        if use_lower:
            chars += string.ascii_lowercase
        if use_digits:
            chars += string.digits
        if use_special:
            chars += '!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        if not chars:
            print(f"{Re}Error: At least one character type must be selected.")
            return
        
        print(f"\n {Cy}Generated Passwords:{Wh}")
        print(f" {Wh}" + "─" * 50)
        
        for i in range(count):
            password = ''.join(secrets.choice(chars) for _ in range(length))
            # Calculate entropy
            entropy = len(password) * (len(chars).bit_length())
            strength = "Weak" if entropy < 50 else "Medium" if entropy < 80 else "Strong" if entropy < 100 else "Very Strong"
            color = Re if strength == "Weak" else Ye if strength == "Medium" else Gr
            print(f" {Wh}[{i+1}] {Gr}{password}")
            print(f"     {Wh}Strength: {color}{strength}{Wh} (~{entropy} bits)")
        
        print(f"\n {Wh}" + "─" * 50)
        print(f" {Cy}Tip: Use a password manager to store these securely!{Wh}")
        
    except ValueError:
        print(f"{Re}Error: Please enter valid numbers.")


@is_option
def hash_generator():
    """Generate various hash values for input text or check hash type."""
    print(f"\n {Wh}========== {Gr}HASH GENERATOR {Wh}==========")
    print(f"\n {Wh}[1] Generate hash from text")
    print(f" {Wh}[2] Identify hash type")
    
    choice = input(f"\n {Wh}Select option: {Gr}").strip()
    
    if choice == '1':
        text = input(f"\n {Wh}Enter text to hash: {Gr}").strip()
        if not text:
            print(f"{Re}Error: Please enter some text.")
            return
        
        text_bytes = text.encode('utf-8')
        
        print(f"\n {Cy}Hash Results:{Wh}")
        print(f" {Wh}" + "─" * 70)
        print(f" {Wh}MD5       : {Gr}{hashlib.md5(text_bytes).hexdigest()}")
        print(f" {Wh}SHA-1     : {Gr}{hashlib.sha1(text_bytes).hexdigest()}")
        print(f" {Wh}SHA-256   : {Gr}{hashlib.sha256(text_bytes).hexdigest()}")
        print(f" {Wh}SHA-384   : {Gr}{hashlib.sha384(text_bytes).hexdigest()}")
        print(f" {Wh}SHA-512   : {Gr}{hashlib.sha512(text_bytes).hexdigest()}")
        print(f" {Wh}" + "─" * 70)
        
    elif choice == '2':
        hash_input = input(f"\n {Wh}Enter hash to identify: {Gr}").strip()
        if not hash_input:
            print(f"{Re}Error: Please enter a hash.")
            return
        
        # Common hash patterns
        hash_patterns = [
            (32, 'MD5'),
            (40, 'SHA-1'),
            (56, 'SHA-224'),
            (64, 'SHA-256 / SHA3-256'),
            (96, 'SHA-384 / SHA3-384'),
            (128, 'SHA-512 / SHA3-512'),
        ]
        
        length = len(hash_input)
        is_hex = all(c in '0123456789abcdefABCDEF' for c in hash_input)
        
        print(f"\n {Cy}Hash Analysis:{Wh}")
        print(f" {Wh}Length      : {Gr}{length} characters")
        print(f" {Wh}Hex Valid   : {Gr}{'Yes' if is_hex else 'No'}")
        
        if is_hex:
            possible_types = [name for len_val, name in hash_patterns if len_val == length]
            if possible_types:
                print(f" {Wh}Possible    : {Gr}{', '.join(possible_types)}")
            else:
                print(f" {Ye}Unknown hash type for length {length}")
        else:
            # Check for bcrypt, base64, etc.
            if hash_input.startswith('$2'):
                print(f" {Wh}Possible    : {Gr}bcrypt")
            elif hash_input.startswith('$6$'):
                print(f" {Wh}Possible    : {Gr}SHA-512 Crypt")
            elif hash_input.startswith('$5$'):
                print(f" {Wh}Possible    : {Gr}SHA-256 Crypt")
            else:
                print(f" {Ye}Could not identify hash type")
    else:
        print(f"{Re}Invalid option.")


@is_option
def network_scanner():
    """Scan local network to discover connected devices."""
    import subprocess
    import struct
    
    print(f"\n {Wh}========== {Gr}LOCAL NETWORK SCANNER {Wh}==========")
    
    def get_local_ip():
        """Get the local IP address of this machine."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return None
    
    def get_network_range(ip):
        """Get the network range (assuming /24 subnet)."""
        parts = ip.split('.')
        return f"{parts[0]}.{parts[1]}.{parts[2]}"
    
    def get_mac_address(ip):
        """Get MAC address from ARP table."""
        try:
            # Try to get MAC from ARP table
            result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=2)
            output = result.stdout
            # Parse MAC address from output
            for line in output.split('\n'):
                if ip in line:
                    parts = line.split()
                    for part in parts:
                        if ':' in part and len(part) == 17:
                            return part.upper()
                        # Handle format like aa:bb:cc:dd:ee:ff
                        if re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', part):
                            return part.upper()
        except:
            pass
        return "Unknown"
    
    def get_hostname(ip):
        """Try to resolve hostname for an IP using multiple methods."""
        hostname = None
        
        # Method 1: Standard reverse DNS lookup
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            if hostname and hostname != ip:
                return hostname
        except:
            pass
        
        # Method 2: Try NetBIOS name lookup (for Windows devices)
        try:
            result = subprocess.run(
                ['nmblookup', '-A', ip],
                capture_output=True, text=True, timeout=3
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if '<00>' in line and 'GROUP' not in line:
                        # Extract NetBIOS name
                        name = line.split()[0]
                        if name and not name.startswith('Looking'):
                            return name
        except:
            pass
        
        # Method 3: Try mDNS/Avahi lookup (for Linux/Mac devices)
        try:
            result = subprocess.run(
                ['avahi-resolve', '-a', ip],
                capture_output=True, text=True, timeout=3
            )
            if result.returncode == 0 and result.stdout.strip():
                parts = result.stdout.strip().split()
                if len(parts) >= 2:
                    hostname = parts[1].rstrip('.')
                    if hostname:
                        return hostname
        except:
            pass
        
        # Method 4: Try getent hosts
        try:
            result = subprocess.run(
                ['getent', 'hosts', ip],
                capture_output=True, text=True, timeout=2
            )
            if result.returncode == 0 and result.stdout.strip():
                parts = result.stdout.strip().split()
                if len(parts) >= 2:
                    return parts[1]
        except:
            pass
        
        # Method 5: Check /etc/hosts file
        try:
            with open('/etc/hosts', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split()
                        if len(parts) >= 2 and parts[0] == ip:
                            return parts[1]
        except:
            pass
        
        # Method 6: Parse arp -a output for hostname
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if ip in line:
                        # Format: hostname (ip) at mac ...
                        # or: ? (ip) at mac ...
                        match = re.match(r'^(\S+)\s+\(' + re.escape(ip) + r'\)', line)
                        if match:
                            name = match.group(1)
                            if name and name != '?':
                                return name
        except:
            pass
        
        # Method 7: Try 'host' command for reverse DNS
        try:
            result = subprocess.run(['host', ip], capture_output=True, text=True, timeout=3)
            if result.returncode == 0 and 'domain name pointer' in result.stdout:
                # Format: X.X.X.X.in-addr.arpa domain name pointer hostname.
                parts = result.stdout.strip().split('domain name pointer')
                if len(parts) >= 2:
                    hostname = parts[1].strip().rstrip('.')
                    if hostname:
                        return hostname
        except:
            pass
        
        # Method 8: Try nmap for hostname detection (more thorough)
        try:
            result = subprocess.run(
                ['nmap', '-sn', '-R', ip],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Nmap scan report for' in line:
                        # Format: Nmap scan report for hostname (ip)
                        # or: Nmap scan report for ip
                        match = re.search(r'Nmap scan report for (.+?) \(' + re.escape(ip) + r'\)', line)
                        if match:
                            return match.group(1)
                        # Check if it found a hostname via PTR
                        match = re.search(r'Nmap scan report for (\S+)', line)
                        if match and match.group(1) != ip:
                            return match.group(1)
        except:
            pass
        
        return "Unknown"
    
    def get_hostname_from_arp():
        """Get all hostnames from arp -a output at once."""
        hostnames = {}
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    # Format: hostname (ip) at mac ...
                    match = re.match(r'^(\S+)\s+\(([0-9.]+)\)', line)
                    if match:
                        name, ip = match.groups()
                        if name and name != '?':
                            hostnames[ip] = name
        except:
            pass
        return hostnames
    
    def get_vendor_from_mac(mac):
        """Get vendor name from MAC address (first 3 octets)."""
        # Common MAC vendor prefixes
        vendors = {
            '00:50:56': 'VMware',
            '00:0C:29': 'VMware',
            '00:1C:42': 'Parallels',
            '08:00:27': 'VirtualBox',
            '52:54:00': 'QEMU/KVM',
            'B8:27:EB': 'Raspberry Pi',
            'DC:A6:32': 'Raspberry Pi',
            'E4:5F:01': 'Raspberry Pi',
            '00:1A:11': 'Google',
            '94:EB:2C': 'Google',
            '3C:5A:B4': 'Google',
            'F4:F5:D8': 'Google',
            '00:17:88': 'Philips Hue',
            '00:1E:C2': 'Apple',
            '00:03:93': 'Apple',
            '00:0A:95': 'Apple',
            '00:1D:4F': 'Apple',
            'A4:83:E7': 'Apple',
            'AC:BC:32': 'Apple',
            '3C:06:30': 'Apple',
            '78:31:C1': 'Apple',
            'F0:18:98': 'Apple',
            '00:26:BB': 'Apple',
            '40:6C:8F': 'Apple',
            'D0:E1:40': 'Apple',
            '00:26:B0': 'Apple',
            '00:23:12': 'Apple',
            '18:AF:8F': 'Apple',
            '00:24:36': 'Apple',
            'A8:20:66': 'Apple',
            '00:1F:F3': 'Apple',
            '00:21:E9': 'Apple',
            'B8:C7:5D': 'Apple',
            '00:25:00': 'Apple',
            '58:B0:35': 'Apple',
            '60:C5:47': 'Apple',
            '88:66:A5': 'Apple',
            '28:CF:DA': 'Apple',
            '00:50:F2': 'Microsoft',
            '00:03:FF': 'Microsoft',
            '00:0D:3A': 'Microsoft',
            '00:12:5A': 'Microsoft',
            '00:15:5D': 'Microsoft',
            '00:17:FA': 'Microsoft',
            '00:1D:D8': 'Microsoft',
            '28:18:78': 'Microsoft',
            '00:22:48': 'Microsoft',
            '00:25:AE': 'Microsoft',
            '60:45:BD': 'Microsoft',
            '7C:1E:52': 'Microsoft',
            'B4:0E:DE': 'Samsung',
            '00:26:37': 'Samsung',
            '5C:0A:5B': 'Samsung',
            '84:11:9E': 'Samsung',
            '94:35:0A': 'Samsung',
            'AC:5F:3E': 'Samsung',
            'C4:73:1E': 'Samsung',
            'F0:25:B7': 'Samsung',
            '00:E0:4C': 'Realtek',
            '00:60:52': 'Realtek',
            '52:54:00': 'Realtek',
            '00:1B:21': 'Intel',
            '00:1C:C0': 'Intel',
            '00:1D:E0': 'Intel',
            '00:1E:64': 'Intel',
            '00:1E:67': 'Intel',
            '00:1F:3B': 'Intel',
            '00:1F:3C': 'Intel',
            '00:21:5C': 'Intel',
            '00:21:6A': 'Intel',
            '00:22:FA': 'Intel',
            '00:24:D6': 'Intel',
            '00:24:D7': 'Intel',
            '00:26:C6': 'Intel',
            '00:26:C7': 'Intel',
            '3C:97:0E': 'Intel',
            '4C:79:6E': 'Intel',
            '84:3A:4B': 'Intel',
            'A4:4C:C8': 'Intel',
            'E8:B1:FC': 'Intel',
            'F8:16:54': 'Intel',
            '00:0E:C6': 'ASUS',
            '00:11:2F': 'ASUS',
            '00:15:F2': 'ASUS',
            '00:17:31': 'ASUS',
            '00:1A:92': 'ASUS',
            '00:1D:60': 'ASUS',
            '00:1E:8C': 'ASUS',
            '00:22:15': 'ASUS',
            '00:23:54': 'ASUS',
            '00:24:8C': 'ASUS',
            '00:26:18': 'ASUS',
            '14:DA:E9': 'ASUS',
            '1C:B7:2C': 'ASUS',
            '2C:56:DC': 'ASUS',
            '30:85:A9': 'ASUS',
            '54:04:A6': 'ASUS',
            '60:45:CB': 'ASUS',
            'AC:22:0B': 'ASUS',
            'BC:EE:7B': 'ASUS',
            'D8:50:E6': 'ASUS',
            'F4:6D:04': 'ASUS',
            '00:09:0F': 'Fortinet',
            '00:1B:77': 'Intel',
            'B0:BE:76': 'TP-Link',
            '50:C7:BF': 'TP-Link',
            '60:E3:27': 'TP-Link',
            '94:D9:B3': 'TP-Link',
            'C0:25:E9': 'TP-Link',
            'E8:DE:27': 'TP-Link',
            'F8:1A:67': 'TP-Link',
            '14:CC:20': 'TP-Link',
            '30:B5:C2': 'TP-Link',
            '54:C8:0F': 'TP-Link',
            '64:66:B3': 'TP-Link',
            '00:18:E7': 'D-Link',
            '00:1B:11': 'D-Link',
            '00:1C:F0': 'D-Link',
            '00:1E:58': 'D-Link',
            '00:21:91': 'D-Link',
            '00:22:B0': 'D-Link',
            '00:24:01': 'D-Link',
            '00:26:5A': 'D-Link',
            '1C:7E:E5': 'D-Link',
            '28:10:7B': 'D-Link',
            '34:08:04': 'D-Link',
            '1C:AF:F7': 'D-Link',
            '78:54:2E': 'D-Link',
            '9C:D6:43': 'D-Link',
            'AC:F1:DF': 'D-Link',
            'C8:BE:19': 'D-Link',
            'F0:7D:68': 'D-Link',
            '00:14:BF': 'Linksys',
            '00:18:39': 'Linksys',
            '00:1A:70': 'Linksys',
            '00:1C:10': 'Linksys',
            '00:1D:7E': 'Linksys',
            '00:1E:E5': 'Linksys',
            '00:21:29': 'Linksys',
            '00:22:6B': 'Linksys',
            '00:23:69': 'Linksys',
            '00:25:9C': 'Linksys',
            '58:6D:8F': 'Linksys',
            '68:7F:74': 'Linksys',
            'C0:C1:C0': 'Linksys',
            '20:AA:4B': 'Linksys',
            'E8:9F:80': 'Linksys',
            '00:1D:0F': 'TP-Link',
            '00:27:19': 'TP-Link',
            '10:FE:ED': 'TP-Link',
            '18:A6:F7': 'TP-Link',
            '20:DC:E6': 'TP-Link',
            '24:69:68': 'TP-Link',
            '00:01:E6': 'Hewlett-Packard',
            '00:02:A5': 'Hewlett-Packard',
            '00:04:EA': 'Hewlett-Packard',
            '00:08:02': 'Hewlett-Packard',
            '00:0B:CD': 'Hewlett-Packard',
            '00:0D:9D': 'Hewlett-Packard',
            '00:0E:7F': 'Hewlett-Packard',
            '00:0F:20': 'Hewlett-Packard',
            '00:0F:61': 'Hewlett-Packard',
            '00:10:83': 'Hewlett-Packard',
            '00:11:0A': 'Hewlett-Packard',
            '00:11:85': 'Hewlett-Packard',
            '00:12:79': 'Hewlett-Packard',
            '00:13:21': 'Hewlett-Packard',
            '00:14:38': 'Hewlett-Packard',
            '00:14:C2': 'Hewlett-Packard',
            '00:15:60': 'Hewlett-Packard',
            '00:16:35': 'Hewlett-Packard',
            '00:17:08': 'Hewlett-Packard',
            '00:17:A4': 'Hewlett-Packard',
            '00:18:71': 'Hewlett-Packard',
            '00:18:FE': 'Hewlett-Packard',
            '00:19:BB': 'Hewlett-Packard',
            '00:1A:4B': 'Hewlett-Packard',
            '00:1B:78': 'Hewlett-Packard',
            '00:1C:2E': 'Hewlett-Packard',
            '00:1E:0B': 'Hewlett-Packard',
            '00:1F:29': 'Hewlett-Packard',
            '00:21:5A': 'Hewlett-Packard',
            '00:22:64': 'Hewlett-Packard',
            '00:23:7D': 'Hewlett-Packard',
            '00:24:81': 'Hewlett-Packard',
            '00:25:B3': 'Hewlett-Packard',
            '00:26:55': 'Hewlett-Packard',
            '00:30:6E': 'Hewlett-Packard',
            '00:60:B0': 'Hewlett-Packard',
            '00:80:A0': 'Hewlett-Packard',
            '08:00:09': 'Hewlett-Packard',
        }
        
        if mac == "Unknown":
            return "Unknown"
        
        mac_prefix = mac[:8].upper()
        
        # Check for locally administered MAC (randomized/private MAC)
        # Second character: 2, 6, A, E indicate locally administered
        if len(mac) >= 2:
            second_char = mac[1].upper()
            if second_char in ['2', '6', 'A', 'E']:
                return "Private MAC"
        
        return vendors.get(mac_prefix, "Unknown Vendor")
    
    def is_private_mac(mac):
        """Check if MAC address is locally administered (randomized)."""
        if mac == "Unknown" or len(mac) < 2:
            return False
        second_char = mac[1].upper()
        return second_char in ['2', '6', 'A', 'E']
    
    def ping_host(ip, timeout=1):
        """Check if a host is alive using ping."""
        try:
            # Use ping command based on OS
            if os.name == 'nt':
                cmd = ['ping', '-n', '1', '-w', str(timeout * 1000), ip]
            else:
                cmd = ['ping', '-c', '1', '-W', str(timeout), ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 1)
            return result.returncode == 0
        except:
            return False
    
    def scan_host_socket(ip, timeout=0.5):
        """Try to connect to common ports to detect if host is alive."""
        common_ports = [80, 443, 22, 445, 139, 21, 23, 8080, 3389]
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return True
            except:
                pass
        return False
    
    # Get local IP
    local_ip = get_local_ip()
    if not local_ip:
        print(f"{Re}Error: Could not determine local IP address.")
        return
    
    network_range = get_network_range(local_ip)
    
    print(f"\n {Wh}Your IP: {Gr}{local_ip}")
    print(f" {Wh}Network: {Gr}{network_range}.0/24")
    print(f"\n {Cy}Scanning network for connected devices...{Wh}")
    print(f" {Wh}This may take a minute...\n")
    
    # Helper function to get hosts from ARP cache
    def get_arp_cache_hosts():
        """Get all hosts currently in the ARP cache."""
        hosts = set()
        try:
            # Try arp -a first
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    # Match IP addresses in parentheses: (192.168.1.x)
                    match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', line)
                    if match:
                        ip = match.group(1)
                        if ip.startswith(network_range + '.'):
                            # Check if it has a valid MAC (not incomplete)
                            if 'incomplete' not in line.lower() and '<incomplete>' not in line.lower():
                                hosts.add(ip)
        except:
            pass
        
        try:
            # Also try arp -n format
            result = subprocess.run(['arp', '-n'], capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    parts = line.split()
                    if len(parts) >= 3:
                        ip = parts[0]
                        if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip) and ip.startswith(network_range + '.'):
                            # Check if it has a valid MAC (not incomplete)
                            if 'incomplete' not in line.lower():
                                hosts.add(ip)
        except:
            pass
        
        try:
            # Try reading /proc/net/arp on Linux
            if os.path.exists('/proc/net/arp'):
                with open('/proc/net/arp', 'r') as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 4 and parts[0] != 'IP':
                            ip = parts[0]
                            flags = parts[2]
                            if ip.startswith(network_range + '.') and flags != '0x0':
                                hosts.add(ip)
        except:
            pass
        
        return hosts
    
    # Helper function to use arping (more reliable than ping for some devices)
    def arping_host(ip, timeout=1):
        """Use arping to check if host is alive (bypasses firewall better)."""
        try:
            # arping sends ARP requests directly - works even if ICMP is blocked
            result = subprocess.run(
                ['arping', '-c', '1', '-w', str(timeout), ip],
                capture_output=True, text=True, timeout=timeout + 2
            )
            return result.returncode == 0 or 'reply from' in result.stdout.lower()
        except:
            return False
    
    # Helper function to use nmap for host discovery (if available)
    def nmap_discover():
        """Use nmap for ARP discovery (most reliable method)."""
        hosts = set()
        try:
            # nmap -sn uses ARP ping on local network which is very reliable
            result = subprocess.run(
                ['nmap', '-sn', '-PR', f'{network_range}.0/24'],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    match = re.search(r'Nmap scan report for.*?(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        hosts.add(match.group(1))
        except:
            pass
        return hosts
    
    # First, try to populate ARP table using multiple methods
    print(f" {Cy}Phase 1: Populating ARP cache...{Wh}")
    
    try:
        # Send ping to broadcast address to populate ARP table
        broadcast_ip = f"{network_range}.255"
        if os.name != 'nt':
            subprocess.run(['ping', '-c', '2', '-b', broadcast_ip], capture_output=True, timeout=3)
    except:
        pass
    
    # Try sending ARP requests using arping to broadcast (if available)
    try:
        subprocess.run(['arping', '-c', '1', '-b', '-f', f'{network_range}.255'], capture_output=True, timeout=3)
    except:
        pass
    
    # Try using ip neigh to get neighbors
    try:
        result = subprocess.run(['ip', 'neigh', 'show'], capture_output=True, text=True, timeout=3)
    except:
        pass
    
    discovered_hosts = set()
    
    # Phase 1: Get hosts already in ARP cache (these are definitely alive)
    arp_hosts = get_arp_cache_hosts()
    discovered_hosts.update(arp_hosts)
    if arp_hosts:
        print(f" {Gr}Found {len(arp_hosts)} device(s) in ARP cache{Wh}")
    
    # Phase 2: Try nmap if available (most reliable)
    print(f" {Cy}Phase 2: Scanning network...{Wh}")
    nmap_hosts = nmap_discover()
    if nmap_hosts:
        new_hosts = nmap_hosts - discovered_hosts
        discovered_hosts.update(nmap_hosts)
        if new_hosts:
            print(f" {Gr}nmap discovered {len(new_hosts)} additional device(s){Wh}")
    
    # Scan the network range
    def scan_ip(i):
        ip = f"{network_range}.{i}"
        # Skip if already discovered
        if ip in discovered_hosts:
            return None
        # Try multiple methods
        if ping_host(ip, timeout=1):
            return ip
        if arping_host(ip, timeout=1):
            return ip
        if scan_host_socket(ip, timeout=0.3):
            return ip
        return None
    
    # Use threading for faster scanning (for IPs not yet discovered)
    print(f"\n {Cy}Phase 3: Ping/Port scanning remaining IPs...{Wh}\n")
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_ip, i): i for i in range(1, 255)}
        completed = 0
        for future in as_completed(futures):
            completed += 1
            progress_bar(completed, 254, prefix="Scanning: ")
            result = future.result()
            if result:
                discovered_hosts.add(result)
    
    print()  # New line after progress bar
    
    # Check ARP cache one more time after all the scanning
    final_arp_hosts = get_arp_cache_hosts()
    new_from_arp = final_arp_hosts - discovered_hosts
    if new_from_arp:
        print(f" {Gr}Found {len(new_from_arp)} additional device(s) in ARP cache after scan{Wh}")
        discovered_hosts.update(final_arp_hosts)
    
    # Convert to sorted list
    discovered_hosts = sorted(list(discovered_hosts), key=lambda x: [int(p) for p in x.split('.')])
    
    if not discovered_hosts:
        print(f"\n {Ye}No devices found on the network.")
        print(f" {Wh}Try running with sudo/admin privileges for better results.")
        print(f" {Wh}Installing 'nmap' and 'arping' can improve detection.")
        return
    
    # Pre-fetch hostnames from ARP table
    arp_hostnames = get_hostname_from_arp()
    
    # Display results
    print(f"\n {Gr}Found {len(discovered_hosts)} device(s) on the network:{Wh}\n")
    print(f" {Cy}{'─' * 95}{Wh}")
    print(f" {Wh}│ {'No.':<4} │ {'IP Address':<16} │ {'MAC Address':<18} │ {'Hostname':<20} │ {'Vendor/Type':<18} │{Wh}")
    print(f" {Cy}{'─' * 95}{Wh}")
    
    private_mac_devices = []
    
    for idx, ip in enumerate(discovered_hosts, 1):
        mac = get_mac_address(ip)
        
        # Try ARP hostname first, then full lookup
        hostname = arp_hostnames.get(ip) or get_hostname(ip)
        vendor = get_vendor_from_mac(mac)
        
        # Track private MAC devices
        if is_private_mac(mac):
            private_mac_devices.append(ip)
            if hostname == "Unknown":
                hostname = "Phone/Tablet?"
        
        # Truncate long values
        if len(hostname) > 20:
            hostname = hostname[:17] + "..."
        if len(vendor) > 18:
            vendor = vendor[:15] + "..."
        
        # Highlight local machine
        if ip == local_ip:
            print(f" {Gr}│ {idx:<4} │ {ip:<16} │ {mac:<18} │ {hostname:<20} │ {vendor:<18} │ ← You{Wh}")
        elif is_private_mac(mac):
            print(f" {Wh}│ {idx:<4} │ {Gr}{ip:<16}{Wh} │ {Ye}{mac:<18}{Wh} │ {Ye}{hostname:<20}{Wh} │ {Ye}{vendor:<18}{Wh} │{Wh}")
        else:
            print(f" {Wh}│ {idx:<4} │ {Gr}{ip:<16}{Wh} │ {Cy}{mac:<18}{Wh} │ {Cy}{hostname:<20}{Wh} │ {Mage}{vendor:<18}{Wh} │{Wh}")
    
    print(f" {Cy}{'─' * 95}{Wh}")
    
    # Summary
    print(f"\n {Wh}Summary:")
    print(f" {Wh}├─ Total devices: {Gr}{len(discovered_hosts)}{Wh}")
    print(f" {Wh}├─ Network: {Gr}{network_range}.0/24{Wh}")
    print(f" {Wh}├─ Your device: {Gr}{local_ip}{Wh}")
    if private_mac_devices:
        print(f" {Wh}└─ Private MAC devices: {Ye}{len(private_mac_devices)}{Wh} (likely phones/tablets with MAC randomization)")
    else:
        print(f" {Wh}└─ Private MAC devices: {Gr}0{Wh}")
    
    # Legend
    print(f"\n {Wh}Legend:")
    print(f" {Wh}├─ {Ye}Yellow{Wh} = Device using private/randomized MAC (common on phones)")
    print(f" {Wh}└─ {Cy}Cyan{Wh} = Device with identifiable MAC address")
    
    # Quick service scan for all hosts
    quick_scan = input(f"\n {Wh}Scan running services on all hosts? {Gr}(Y/n){Wh}: ").strip().lower()
    if quick_scan != 'n':
        print(f"\n {Cy}Scanning for running services on each host...{Wh}\n")
        
        port_mapping = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS',
            445: 'SMB', 515: 'LPD', 548: 'AFP', 554: 'RTSP', 631: 'IPP',
            993: 'IMAPS', 995: 'POP3S', 1883: 'MQTT', 1925: 'Philips TV',
            2049: 'NFS', 3074: 'Xbox', 3306: 'MySQL', 3389: 'RDP',
            3478: 'PlayStation', 5000: 'Synology', 5432: 'PostgreSQL',
            5683: 'CoAP', 6379: 'Redis', 8008: 'Chromecast', 8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt', 8554: 'RTSP-Alt', 8883: 'MQTT-SSL',
            9080: 'WebSocket', 9100: 'RAW Print', 27017: 'MongoDB', 5900: 'VNC'
        }
        
        for idx, ip in enumerate(discovered_hosts, 1):
            hostname = arp_hostnames.get(ip) or get_hostname(ip)
            
            # Truncate hostname
            display_hostname = hostname if len(hostname) <= 20 else hostname[:17] + "..."
            
            print(f" {Wh}[{idx}/{len(discovered_hosts)}] {Gr}{ip:<16}{Wh} ({display_hostname}){Wh}", end='', flush=True)
            
            open_ports = scan_host_services(ip, port_mapping, timeout=0.3)
            
            if open_ports:
                services = ', '.join([f"{port}/{service}" for port, service in sorted(open_ports)[:5]])
                if len(open_ports) > 5:
                    print(f" → {Gr}{services}{Wh}, +{len(open_ports)-5} more")
                else:
                    print(f" → {Gr}{services}{Wh}")
            else:
                print(f" → {Ye}No services detected{Wh}")
    
    # Store results for advanced features
    scan_results = []
    for ip in discovered_hosts:
        mac = get_mac_address(ip)
        hostname = arp_hostnames.get(ip) or get_hostname(ip)
        vendor = get_vendor_from_mac(mac)
        scan_results.append({
            'ip': ip,
            'mac': mac,
            'hostname': hostname,
            'vendor': vendor,
            'is_local': ip == local_ip,
            'private_mac': is_private_mac(mac)
        })
    
    # Advanced options menu
    while True:
        print(f"\n {Cy}━━━ Advanced Options ━━━{Wh}")
        print(f" {Wh}[1] 🔍 Deep scan (detect device types & services)")
        print(f" {Wh}[2] 📡 Monitor mode (watch for new devices)")
        print(f" {Wh}[3] 💾 Export results (JSON/HTML) - {Gr}{len(scan_results)} devices{Wh}")
        print(f" {Wh}[4] 🌐 Online MAC lookup")
        print(f" {Wh}[5] ⚡ Wake-on-LAN (wake a device)")
        print(f" {Wh}[6] 🔄 Rescan network")
        print(f" {Wh}[0] ← Back to main menu")
        
        choice = input(f"\n {Wh}Select option: {Gr}").strip()
        
        if choice == '0' or choice == '':
            break
        elif choice == '1':
            deep_scan_devices(scan_results, local_ip)
        elif choice == '2':
            updated_results = monitor_network(network_range, local_ip, scan_results, ping_host, scan_host_socket, get_mac_address, get_hostname, get_vendor_from_mac, is_private_mac, arp_hostnames)
            if updated_results:
                # Update scan_results with new devices from monitoring
                existing_ips = {d['ip'] for d in scan_results}
                for device in updated_results:
                    if device['ip'] not in existing_ips:
                        scan_results.append(device)
                    else:
                        # Update existing device info
                        for i, d in enumerate(scan_results):
                            if d['ip'] == device['ip']:
                                scan_results[i].update(device)
                                break
                # Remove devices that left
                updated_ips = {d['ip'] for d in updated_results}
                scan_results[:] = [d for d in scan_results if d['ip'] in updated_ips or d.get('is_local')]
                print(f" {Gr}✓ Results updated with {len(scan_results)} devices{Wh}")
        elif choice == '3':
            export_scan_results(scan_results, network_range)
        elif choice == '4':
            online_mac_lookup(scan_results)
        elif choice == '5':
            wake_on_lan_menu(scan_results)
        elif choice == '6':
            return network_scanner()
        else:
            print(f" {Re}Invalid option.{Wh}")


def scan_host_services(ip, port_list=None, timeout=0.3):
    """Scan a single host for open ports and identify services."""
    if port_list is None:
        # Default comprehensive port list
        port_list = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS',
            445: 'SMB', 515: 'LPD', 548: 'AFP', 554: 'RTSP', 631: 'IPP',
            993: 'IMAPS', 995: 'POP3S', 1883: 'MQTT', 1925: 'Philips TV',
            2049: 'NFS', 3074: 'Xbox', 3306: 'MySQL', 3389: 'RDP',
            3478: 'PlayStation', 5000: 'Synology', 5432: 'PostgreSQL',
            5683: 'CoAP', 6379: 'Redis', 8008: 'Chromecast', 8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt', 8554: 'RTSP-Alt', 8883: 'MQTT-SSL',
            9080: 'WebSocket', 9100: 'RAW Print', 27017: 'MongoDB', 5900: 'VNC'
        }
    
    open_ports = []
    for port, service in port_list.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                open_ports.append((port, service))
        except:
            pass
    
    return open_ports


def deep_scan_devices(scan_results, local_ip):
    """Perform deep scan to detect device types and running services."""
    print(f"\n {Cy}━━━ Deep Scan - Device Type Detection ━━━{Wh}")
    print(f" {Wh}Scanning ports to identify device types...\n")
    
    # Port signatures for device type detection
    device_signatures = {
        'Router/Gateway': [80, 443, 53, 8080, 8443],
        'Printer': [9100, 515, 631, 80],
        'NAS/File Server': [445, 139, 548, 2049, 5000],
        'Smart TV': [8008, 8443, 9080, 1925],
        'Game Console': [3074, 3478, 3479, 3480],
        'IP Camera': [554, 8554, 80, 8080],
        'Web Server': [80, 443, 8080, 8443],
        'SSH Server': [22],
        'FTP Server': [21],
        'Database': [3306, 5432, 27017, 6379],
        'Mail Server': [25, 587, 993, 995],
        'IoT Device': [1883, 8883, 5683],  # MQTT, CoAP
    }
    
    service_names = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS',
        445: 'SMB', 515: 'LPD', 548: 'AFP', 554: 'RTSP', 631: 'IPP',
        993: 'IMAPS', 995: 'POP3S', 1883: 'MQTT', 1925: 'Philips TV',
        2049: 'NFS', 3074: 'Xbox', 3306: 'MySQL', 3389: 'RDP',
        3478: 'PlayStation', 5000: 'Synology', 5432: 'PostgreSQL',
        5683: 'CoAP', 6379: 'Redis', 8008: 'Chromecast', 8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt', 8554: 'RTSP-Alt', 8883: 'MQTT-SSL',
        9080: 'WebSocket', 9100: 'RAW Print', 27017: 'MongoDB',
    }
    
    ports_to_scan = list(set([p for ports in device_signatures.values() for p in ports]))
    ports_to_scan.extend([3389, 5900, 23])  # RDP, VNC, Telnet
    ports_to_scan = sorted(list(set(ports_to_scan)))
    
    for device in scan_results:
        if device['is_local']:
            continue
            
        ip = device['ip']
        print(f" {Cy}Scanning {ip}...{Wh}", end='', flush=True)
        
        open_ports = []
        for port in ports_to_scan:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    open_ports.append(port)
            except:
                pass
        
        # Determine device type
        device_type = "Unknown Device"
        type_scores = {}
        
        for dtype, signature_ports in device_signatures.items():
            score = sum(1 for p in signature_ports if p in open_ports)
            if score > 0:
                type_scores[dtype] = score
        
        if type_scores:
            device_type = max(type_scores, key=type_scores.get)
        elif not open_ports:
            if device['private_mac']:
                device_type = "📱 Mobile Device"
            else:
                device_type = "Stealth/Firewall"
        
        # Display results
        print(f"\r {Wh}┌─ {Gr}{ip}{Wh} ({device['hostname']})")
        print(f" {Wh}│  Type: {Cy}{device_type}{Wh}")
        print(f" {Wh}│  MAC: {device['mac']} ({device['vendor']})")
        
        if open_ports:
            services = [f"{p}/{service_names.get(p, '?')}" for p in open_ports[:8]]
            print(f" {Wh}│  Open: {Gr}{', '.join(services)}{Wh}")
            if len(open_ports) > 8:
                print(f" {Wh}│        +{len(open_ports)-8} more ports")
        else:
            print(f" {Wh}│  Open: {Ye}No common ports detected{Wh}")
        
        # Security warnings
        warnings = []
        if 23 in open_ports:
            warnings.append("⚠️ Telnet (insecure)")
        if 21 in open_ports:
            warnings.append("⚠️ FTP (insecure)")
        if 3389 in open_ports:
            warnings.append("⚠️ RDP exposed")
        if 5900 in open_ports:
            warnings.append("⚠️ VNC exposed")
        
        if warnings:
            print(f" {Wh}│  {Re}{' | '.join(warnings)}{Wh}")
        
        print(f" {Wh}└{'─' * 50}")
        device['device_type'] = device_type
        device['open_ports'] = open_ports


def monitor_network(network_range, local_ip, initial_devices, ping_host, scan_host_socket, get_mac_address, get_hostname, get_vendor_from_mac, is_private_mac, arp_hostnames):
    """Monitor network for new devices joining or leaving."""
    import signal
    import subprocess
    
    print(f"\n {Cy}━━━ Network Monitor Mode ━━━{Wh}")
    print(f" {Wh}Watching for devices joining/leaving the network...")
    print(f" {Ye}Press Ctrl+C to stop monitoring{Wh}\n")
    
    known_devices = {d['ip']: d for d in initial_devices}
    scan_count = 0
    stop_monitoring = False
    
    def signal_handler(sig, frame):
        nonlocal stop_monitoring
        stop_monitoring = True
    
    # Set up signal handler
    old_handler = signal.signal(signal.SIGINT, signal_handler)
    
    def is_host_alive(ip):
        """Check if host is alive using multiple fast methods."""
        if stop_monitoring:
            return False
        
        # Method 1: Quick TCP connect to common ports
        quick_ports = [80, 443, 22, 7, 135, 445, 62078, 5353, 1900]
        for port in quick_ports:
            if stop_monitoring:
                return False
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return True
            except:
                pass
        
        # Method 2: Try UDP port (for devices that don't respond to TCP)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.1)
            sock.sendto(b'', (ip, 5353))  # mDNS
            sock.close()
        except:
            pass
        
        # Method 3: Check if in ARP table (device responded to something)
        try:
            result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=1)
            if result.returncode == 0 and 'no entry' not in result.stdout.lower():
                for line in result.stdout.split('\n'):
                    if ip in line and '(incomplete)' not in line:
                        return True
        except:
            pass
        
        return False
    
    def active_network_scan():
        """Actively scan all IPs in network range using threads."""
        alive_hosts = set()
        
        # First, send pings/packets to populate ARP table
        try:
            # Ping broadcast
            subprocess.run(
                ['ping', '-c', '1', '-b', '-W', '1', f'{network_range}.255'],
                capture_output=True, timeout=2
            )
        except:
            pass
        
        # Use nmap if available (most reliable)
        try:
            result = subprocess.run(
                ['nmap', '-sn', '-n', '--host-timeout', '500ms', f'{network_range}.0/24'],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Nmap scan report for' in line:
                        ip = line.split()[-1]
                        if ip.startswith(network_range):
                            alive_hosts.add(ip)
                if alive_hosts:
                    return alive_hosts
        except:
            pass
        
        # Fallback: Threaded scan
        def check_ip(ip):
            if is_host_alive(ip):
                return ip
            return None
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            ips_to_scan = [f"{network_range}.{i}" for i in range(1, 255)]
            futures = {executor.submit(check_ip, ip): ip for ip in ips_to_scan}
            
            for future in as_completed(futures, timeout=15):
                if stop_monitoring:
                    break
                try:
                    result = future.result(timeout=1)
                    if result:
                        alive_hosts.add(result)
                except:
                    pass
        
        # Also check ARP table for any devices we might have missed
        try:
            result = subprocess.run(['arp', '-n'], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    parts = line.split()
                    if len(parts) >= 4 and parts[0].startswith(network_range):
                        if '(incomplete)' not in line:
                            alive_hosts.add(parts[0])
        except:
            pass
        
        try:
            result = subprocess.run(['ip', 'neigh'], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    parts = line.split()
                    if parts and parts[0].startswith(network_range):
                        if 'REACHABLE' in line or 'STALE' in line or 'DELAY' in line:
                            alive_hosts.add(parts[0])
        except:
            pass
        
        return alive_hosts
    
    print(f" {Wh}Initial devices: {Gr}{len(known_devices)}{Wh}")
    print(f" {Wh}Performing active scans...\n")
    
    try:
        while not stop_monitoring:
            scan_count += 1
            current_time = datetime.now().strftime("%H:%M:%S")
            print(f"\r {Cy}[{current_time}] Scan #{scan_count} | Known: {len(known_devices)} | Scanning...{Wh}          ", end='', flush=True)
            
            if stop_monitoring:
                break
            
            # Active scan for all devices
            current_ips = active_network_scan()
            
            if stop_monitoring:
                break
            
            known_ips = set(known_devices.keys())
            
            # Check for new devices
            new_ips = current_ips - known_ips
            for ip in new_ips:
                if stop_monitoring:
                    break
                mac = get_mac_address(ip)
                hostname = get_hostname(ip)
                vendor = get_vendor_from_mac(mac)
                
                print(f"\n\n {Gr}{'='*50}")
                print(f" {Gr}[+] NEW DEVICE JOINED THE NETWORK!{Wh}")
                print(f" {Gr}{'='*50}{Wh}")
                print(f"     📍 IP Address : {Gr}{ip}{Wh}")
                print(f"     🔗 MAC Address: {Cy}{mac}{Wh}")
                print(f"     🏷️  Hostname   : {Ye}{hostname}{Wh}")
                print(f"     🏭 Vendor     : {Mage}{vendor}{Wh}")
                if is_private_mac(mac):
                    print(f"     📱 {Ye}(Private MAC - likely phone/tablet){Wh}")
                print(f" {Gr}{'='*50}{Wh}\n")
                
                known_devices[ip] = {
                    'ip': ip,
                    'mac': mac,
                    'hostname': hostname,
                    'vendor': vendor,
                    'private_mac': is_private_mac(mac)
                }
            
            # Check for devices that left
            gone_ips = known_ips - current_ips - {local_ip}
            for ip in list(gone_ips):
                if stop_monitoring:
                    break
                print(f"\n\n {Re}{'='*50}")
                print(f" {Re}[-] DEVICE LEFT THE NETWORK{Wh}")
                print(f" {Re}{'='*50}{Wh}")
                print(f"     📍 IP Address : {Re}{ip}{Wh}")
                old_device = known_devices.get(ip, {})
                if old_device:
                    print(f"     🔗 MAC Address: {old_device.get('mac', 'Unknown')}")
                    print(f"     🏷️  Hostname   : {old_device.get('hostname', 'Unknown')}")
                print(f" {Re}{'='*50}{Wh}\n")
                del known_devices[ip]
            
            print(f"\r {Cy}[{current_time}] Scan #{scan_count} | Known: {len(known_devices)} | Next scan in 5s...{Wh}    ", end='', flush=True)
            
            # Interruptible sleep
            for _ in range(10):
                if stop_monitoring:
                    break
                time.sleep(0.5)
            
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"\n {Re}Error: {e}{Wh}")
    finally:
        signal.signal(signal.SIGINT, old_handler)
    
    print(f"\n\n {Ye}━━━ Monitoring Stopped ━━━{Wh}")
    print(f" {Wh}Final device count: {Gr}{len(known_devices)}{Wh}")
    
    # Return updated device list
    return list(known_devices.values())


def export_scan_results(scan_results, network_range):
    """Export scan results to JSON or HTML file."""
    print(f"\n {Cy}━━━ Export Results ━━━{Wh}")
    print(f" {Wh}[1] Export as JSON")
    print(f" {Wh}[2] Export as HTML report")
    print(f" {Wh}[0] Cancel")
    
    choice = input(f"\n {Wh}Select format: {Gr}").strip()
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if choice == '1':
        filename = f"network_scan_{timestamp}.json"
        export_data = {
            'scan_time': datetime.now().isoformat(),
            'network': f"{network_range}.0/24",
            'devices': scan_results
        }
        try:
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            print(f" {Gr}✓ Exported to {filename}{Wh}")
        except Exception as e:
            print(f" {Re}Error: {e}{Wh}")
            
    elif choice == '2':
        filename = f"network_scan_{timestamp}.html"
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Network Scan Report - {datetime.now().strftime("%Y-%m-%d %H:%M")}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #1a1a2e; color: #eee; }}
        h1 {{ color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }}
        h2 {{ color: #00ff88; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; background: #16213e; }}
        th, td {{ border: 1px solid #0f3460; padding: 12px; text-align: left; }}
        th {{ background: #0f3460; color: #00d4ff; }}
        tr:hover {{ background: #1a1a4e; }}
        .local {{ background: #1e4d2b !important; }}
        .private-mac {{ color: #ffd700; }}
        .summary {{ background: #0f3460; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .footer {{ margin-top: 30px; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <h1>🌐 Network Scan Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Network:</strong> {network_range}.0/24</p>
        <p><strong>Scan Time:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        <p><strong>Devices Found:</strong> {len(scan_results)}</p>
        <p><strong>Private MAC Devices:</strong> {sum(1 for d in scan_results if d.get('private_mac'))}</p>
    </div>
    
    <h2>📋 Discovered Devices</h2>
    <table>
        <tr>
            <th>#</th>
            <th>IP Address</th>
            <th>MAC Address</th>
            <th>Hostname</th>
            <th>Vendor</th>
            <th>Notes</th>
        </tr>
"""
        for idx, device in enumerate(scan_results, 1):
            row_class = 'local' if device.get('is_local') else ''
            mac_class = 'private-mac' if device.get('private_mac') else ''
            notes = []
            if device.get('is_local'):
                notes.append('This device')
            if device.get('private_mac'):
                notes.append('Private MAC')
            if device.get('device_type'):
                notes.append(device['device_type'])
            
            html_content += f"""        <tr class="{row_class}">
            <td>{idx}</td>
            <td>{device['ip']}</td>
            <td class="{mac_class}">{device['mac']}</td>
            <td>{device['hostname']}</td>
            <td>{device['vendor']}</td>
            <td>{', '.join(notes)}</td>
        </tr>
"""
        
        html_content += """    </table>
    <div class="footer">
        <p>Generated by NexRecon Network Scanner</p>
    </div>
</body>
</html>"""
        
        try:
            with open(filename, 'w') as f:
                f.write(html_content)
            print(f" {Gr}✓ Exported to {filename}{Wh}")
            print(f" {Cy}Open in browser to view the report{Wh}")
        except Exception as e:
            print(f" {Re}Error: {e}{Wh}")
    else:
        print(f" {Ye}Export cancelled.{Wh}")


def online_mac_lookup(scan_results):
    """Lookup MAC vendor information online."""
    print(f"\n {Cy}━━━ Online MAC Vendor Lookup ━━━{Wh}")
    print(f" {Wh}Querying online database for unknown vendors...\n")
    
    for device in scan_results:
        mac = device['mac']
        if mac == "Unknown":
            continue
        if device['vendor'] not in ['Unknown Vendor', 'Private MAC', 'Unknown']:
            continue
        if device.get('private_mac'):
            print(f" {Ye}Skipping {device['ip']} (Private/Randomized MAC){Wh}")
            continue
            
        print(f" {Wh}Looking up {mac}...", end='', flush=True)
        
        try:
            # Using macvendors.com API
            response = requests.get(
                f"https://api.macvendors.com/{mac}",
                timeout=5,
                headers={'User-Agent': 'NexRecon/1.0'}
            )
            if response.status_code == 200:
                vendor = response.text.strip()
                device['vendor'] = vendor
                print(f" {Gr}{vendor}{Wh}")
            elif response.status_code == 404:
                print(f" {Ye}Not found in database{Wh}")
            else:
                print(f" {Re}API error{Wh}")
            time.sleep(1)  # Rate limiting
        except Exception as e:
            print(f" {Re}Error: {e}{Wh}")
    
    print(f"\n {Gr}✓ Lookup complete{Wh}")


def wake_on_lan_menu(scan_results):
    """Send Wake-on-LAN magic packet to wake a device."""
    print(f"\n {Cy}━━━ Wake-on-LAN ━━━{Wh}")
    print(f" {Wh}Send magic packet to wake a sleeping device.\n")
    
    # List devices with known MAC
    valid_devices = [(i, d) for i, d in enumerate(scan_results, 1) 
                     if d['mac'] != 'Unknown' and not d.get('is_local')]
    
    if not valid_devices:
        print(f" {Ye}No devices with known MAC addresses found.{Wh}")
        return
    
    print(f" {Wh}Available devices:")
    for idx, device in valid_devices:
        print(f"   [{idx}] {device['ip']} - {device['mac']} ({device['hostname']})")
    
    print(f"\n   [M] Enter MAC manually")
    print(f"   [0] Cancel")
    
    choice = input(f"\n {Wh}Select device or enter MAC: {Gr}").strip()
    
    if choice == '0':
        return
    
    mac_to_wake = None
    
    if choice.upper() == 'M':
        mac_to_wake = input(f" {Wh}Enter MAC address: {Gr}").strip()
    else:
        try:
            idx = int(choice)
            for i, d in valid_devices:
                if i == idx:
                    mac_to_wake = d['mac']
                    break
        except:
            print(f" {Re}Invalid selection.{Wh}")
            return
    
    if not mac_to_wake:
        print(f" {Re}No MAC address specified.{Wh}")
        return
    
    # Clean MAC address
    mac_clean = mac_to_wake.replace(':', '').replace('-', '').replace('.', '').upper()
    
    if len(mac_clean) != 12:
        print(f" {Re}Invalid MAC address format.{Wh}")
        return
    
    try:
        # Build magic packet
        mac_bytes = bytes.fromhex(mac_clean)
        magic_packet = b'\xff' * 6 + mac_bytes * 16
        
        # Send to broadcast
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(magic_packet, ('255.255.255.255', 9))
        sock.close()
        
        print(f"\n {Gr}✓ Magic packet sent to {mac_to_wake}{Wh}")
        print(f" {Wh}If the device supports WoL and is connected via Ethernet,")
        print(f" {Wh}it should wake up within a few seconds.{Wh}")
        
    except Exception as e:
        print(f" {Re}Error sending packet: {e}{Wh}")


@is_option
def port_scanner():
    """Scan common ports on a target host."""
    target = input(f"\n {Wh}Enter target IP or domain: {Gr}").strip()
    
    if not target:
        print(f"{Re}Error: Please enter a target.")
        return
    
    print(f"\n {Wh}========== {Gr}PORT SCANNER {Wh}==========")
    
    # Common ports to scan
    common_ports = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        993: 'IMAPS',
        995: 'POP3S',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        6379: 'Redis',
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt',
        27017: 'MongoDB',
    }
    
    print(f"\n {Wh}Target: {Gr}{target}")
    print(f" {Wh}Scanning {Gr}{len(common_ports)}{Wh} common ports...\n")
    
    open_ports = []
    closed_ports = []
    
    try:
        # Resolve hostname to IP
        try:
            ip = socket.gethostbyname(target)
            if ip != target:
                print(f" {Wh}Resolved IP: {Gr}{ip}\n")
        except socket.gaierror:
            print(f"{Re}Error: Could not resolve hostname.")
            return
        
        for port, service in common_ports.items():
            print(f"\r {Cy}Scanning port {port} ({service})...{' ' * 20}", end='', flush=True)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append((port, service))
            else:
                closed_ports.append((port, service))
            
            sock.close()
        
        print(f"\r{' ' * 60}\r", end='')  # Clear line
        
        print(f" {Cy}[OPEN PORTS]{Wh}")
        if open_ports:
            for port, service in open_ports:
                print(f"   {Gr}✓ {port:5} - {service}")
        else:
            print(f"   {Ye}No open ports found")
        
        print(f"\n {Wh}Scan complete. {Gr}{len(open_ports)}{Wh} open, {Re}{len(closed_ports)}{Wh} closed/filtered")
        
    except KeyboardInterrupt:
        print(f"\n{Ye}Scan cancelled.")
    except Exception as e:
        print(f"{Re}Error: {e}")


@is_option
def subnet_calculator():
    """Calculate subnet information from IP and CIDR notation."""
    ip_cidr = input(f"\n {Wh}Enter IP/CIDR {Gr}(e.g., 192.168.1.0/24){Wh}: {Gr}").strip()
    
    if not ip_cidr:
        print(f"{Re}Error: Please enter an IP address with CIDR notation.")
        return
    
    try:
        if '/' in ip_cidr:
            ip, cidr = ip_cidr.split('/')
            cidr = int(cidr)
        else:
            ip = ip_cidr
            cidr = 24  # Default to /24
            print(f"{Ye}No CIDR specified, using /24")
        
        # Validate IP
        parts = ip.split('.')
        if len(parts) != 4 or not all(0 <= int(p) <= 255 for p in parts):
            print(f"{Re}Error: Invalid IP address format.")
            return
        
        if not 0 <= cidr <= 32:
            print(f"{Re}Error: CIDR must be between 0 and 32.")
            return
        
        # Calculate subnet info
        ip_int = sum(int(octet) << (24 - 8 * i) for i, octet in enumerate(parts))
        mask_int = (0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF
        network_int = ip_int & mask_int
        broadcast_int = network_int | (~mask_int & 0xFFFFFFFF)
        
        def int_to_ip(n):
            return '.'.join(str((n >> (24 - 8 * i)) & 0xFF) for i in range(4))
        
        network = int_to_ip(network_int)
        broadcast = int_to_ip(broadcast_int)
        subnet_mask = int_to_ip(mask_int)
        wildcard = int_to_ip(~mask_int & 0xFFFFFFFF)
        first_host = int_to_ip(network_int + 1) if cidr < 31 else network
        last_host = int_to_ip(broadcast_int - 1) if cidr < 31 else broadcast
        total_hosts = (2 ** (32 - cidr)) - 2 if cidr < 31 else 2 ** (32 - cidr)
        
        print(f"\n {Wh}========== {Gr}SUBNET CALCULATOR {Wh}==========")
        print(f"\n {Wh}IP Address      : {Gr}{ip}")
        print(f" {Wh}CIDR Notation   : {Gr}/{cidr}")
        print(f" {Wh}Subnet Mask     : {Gr}{subnet_mask}")
        print(f" {Wh}Wildcard Mask   : {Gr}{wildcard}")
        print(f" {Wh}Network Address : {Gr}{network}")
        print(f" {Wh}Broadcast       : {Gr}{broadcast}")
        print(f" {Wh}First Host      : {Gr}{first_host}")
        print(f" {Wh}Last Host       : {Gr}{last_host}")
        print(f" {Wh}Total Hosts     : {Gr}{total_hosts:,}")
        print(f" {Wh}IP Class        : {Gr}{get_ip_class(ip)}")
        print(f" {Wh}IP Type         : {Gr}{'Private' if is_private_ip(ip) else 'Public'}")
        
    except ValueError as e:
        print(f"{Re}Error: Invalid input format. {e}")


def get_ip_class(ip: str) -> str:
    """Determine the class of an IP address."""
    first_octet = int(ip.split('.')[0])
    if first_octet < 128:
        return 'Class A (1-126)'
    elif first_octet < 192:
        return 'Class B (128-191)'
    elif first_octet < 224:
        return 'Class C (192-223)'
    elif first_octet < 240:
        return 'Class D - Multicast (224-239)'
    else:
        return 'Class E - Reserved (240-255)'


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is private."""
    parts = [int(p) for p in ip.split('.')]
    if parts[0] == 10:
        return True
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True
    if parts[0] == 192 and parts[1] == 168:
        return True
    if parts[0] == 127:
        return True
    return False


@is_option
def image_metadata_extractor():
    """Extract metadata and EXIF data from images."""
    if not PIL_AVAILABLE:
        print(f"{Re}Error: Pillow library is not installed.")
        print(f"{Ye}Install it with: pip install Pillow")
        return
    
    print(f"\n {Wh}========== {Gr}IMAGE METADATA EXTRACTOR {Wh}==========")
    print(f"\n {Wh}[1] Analyze local image file")
    print(f" {Wh}[2] Analyze image from URL")
    
    choice = input(f"\n {Wh}Select option: {Gr}").strip()
    
    image = None
    source_info = ""
    
    if choice == '1':
        file_path = input(f"\n {Wh}Enter image path: {Gr}").strip()
        
        # Remove quotes if present
        file_path = file_path.strip('"').strip("'")
        
        # Expand ~ to home directory
        file_path = os.path.expanduser(file_path)
        
        if not file_path:
            print(f"{Re}Error: Please enter a file path.")
            return
        
        if not os.path.exists(file_path):
            print(f"{Re}Error: File not found: {file_path}")
            return
        
        try:
            image = Image.open(file_path)
            source_info = file_path
        except Exception as e:
            print(f"{Re}Error opening image: {e}")
            return
            
    elif choice == '2':
        url = input(f"\n {Wh}Enter image URL: {Gr}").strip()
        
        if not url:
            print(f"{Re}Error: Please enter a URL.")
            return
        
        loading_animation("Downloading image", 1.5)
        
        try:
            response = requests.get(url, timeout=15, stream=True,
                                   headers={'User-Agent': 'Mozilla/5.0'})
            response.raise_for_status()
            
            from io import BytesIO
            image = Image.open(BytesIO(response.content))
            source_info = url
        except Exception as e:
            print(f"{Re}Error downloading image: {e}")
            return
    else:
        print(f"{Re}Invalid option.")
        return
    
    loading_animation("Extracting metadata", 1.0)
    
    print(f"\n {Wh}" + "═" * 60)
    print(f" {Cy}IMAGE METADATA ANALYSIS{Wh}")
    print(f" {Wh}" + "═" * 60)
    
    # Basic image information
    print(f"\n {Cy}[Basic Information]{Wh}")
    print(f"   {Wh}Source          : {Gr}{source_info[:50]}{'...' if len(source_info) > 50 else ''}")
    print(f"   {Wh}Format          : {Gr}{image.format or 'Unknown'}")
    print(f"   {Wh}Mode            : {Gr}{image.mode} ({get_mode_description(image.mode)})")
    print(f"   {Wh}Size            : {Gr}{image.width} x {image.height} pixels")
    print(f"   {Wh}Megapixels      : {Gr}{(image.width * image.height) / 1_000_000:.2f} MP")
    
    # File size if local
    if choice == '1' and os.path.exists(file_path):
        file_size = os.path.getsize(file_path)
        print(f"   {Wh}File Size       : {Gr}{format_file_size(file_size)}")
    
    # Color information
    if image.mode in ['RGB', 'RGBA']:
        print(f"   {Wh}Bit Depth       : {Gr}{'32-bit' if image.mode == 'RGBA' else '24-bit'}")
    
    # Animation info for GIFs
    if hasattr(image, 'n_frames') and image.n_frames > 1:
        print(f"   {Wh}Frames          : {Gr}{image.n_frames} (Animated)")
    
    # Extract EXIF data
    exif_data = {}
    gps_data = {}
    
    try:
        exif_raw = image._getexif()
        if exif_raw:
            for tag_id, value in exif_raw.items():
                tag = TAGS.get(tag_id, tag_id)
                
                # Handle GPS data separately
                if tag == 'GPSInfo':
                    for gps_tag_id, gps_value in value.items():
                        gps_tag = GPSTAGS.get(gps_tag_id, gps_tag_id)
                        gps_data[gps_tag] = gps_value
                else:
                    # Clean up binary data
                    if isinstance(value, bytes):
                        try:
                            value = value.decode('utf-8', errors='ignore')[:100]
                        except:
                            value = '<binary data>'
                    exif_data[tag] = value
    except AttributeError:
        pass
    except Exception as e:
        print(f"\n {Ye}Warning: Could not fully parse EXIF data: {e}")
    
    if exif_data:
        # Camera Information
        camera_tags = ['Make', 'Model', 'LensModel', 'LensMake', 'BodySerialNumber']
        camera_info = {k: v for k, v in exif_data.items() if k in camera_tags}
        if camera_info:
            print(f"\n {Cy}[Camera Information]{Wh}")
            for tag, value in camera_info.items():
                print(f"   {Wh}{tag:16}: {Gr}{value}")
        
        # Date/Time Information
        date_tags = ['DateTime', 'DateTimeOriginal', 'DateTimeDigitized']
        date_info = {k: v for k, v in exif_data.items() if k in date_tags}
        if date_info:
            print(f"\n {Cy}[Date/Time Information]{Wh}")
            for tag, value in date_info.items():
                print(f"   {Wh}{tag:16}: {Gr}{value}")
        
        # Exposure Settings
        exposure_tags = ['ExposureTime', 'FNumber', 'ISOSpeedRatings', 'ExposureProgram',
                        'ExposureBiasValue', 'MeteringMode', 'Flash', 'FocalLength',
                        'FocalLengthIn35mmFilm', 'WhiteBalance', 'DigitalZoomRatio']
        exposure_info = {k: v for k, v in exif_data.items() if k in exposure_tags}
        if exposure_info:
            print(f"\n {Cy}[Exposure Settings]{Wh}")
            for tag, value in exposure_info.items():
                # Format special values
                if tag == 'ExposureTime' and hasattr(value, 'numerator'):
                    value = f"1/{int(value.denominator/value.numerator)}s" if value.numerator else value
                elif tag == 'FNumber' and hasattr(value, 'numerator'):
                    value = f"f/{value.numerator/value.denominator:.1f}"
                elif tag == 'FocalLength' and hasattr(value, 'numerator'):
                    value = f"{value.numerator/value.denominator:.1f}mm"
                print(f"   {Wh}{tag:16}: {Gr}{value}")
        
        # Software Information
        software_tags = ['Software', 'ProcessingSoftware', 'HostComputer']
        software_info = {k: v for k, v in exif_data.items() if k in software_tags}
        if software_info:
            print(f"\n {Cy}[Software Information]{Wh}")
            for tag, value in software_info.items():
                print(f"   {Wh}{tag:16}: {Gr}{value}")
    
    # GPS Information
    if gps_data:
        print(f"\n {Cy}[GPS Location]{Wh} {Re}⚠ Privacy Sensitive{Wh}")
        
        lat = convert_gps_to_decimal(gps_data.get('GPSLatitude'), gps_data.get('GPSLatitudeRef'))
        lon = convert_gps_to_decimal(gps_data.get('GPSLongitude'), gps_data.get('GPSLongitudeRef'))
        
        if lat and lon:
            print(f"   {Wh}Latitude        : {Gr}{lat:.6f}")
            print(f"   {Wh}Longitude       : {Gr}{lon:.6f}")
            print(f"   {Wh}Google Maps     : {Gr}https://www.google.com/maps/@{lat},{lon},17z")
        
        if 'GPSAltitude' in gps_data:
            alt = gps_data['GPSAltitude']
            if hasattr(alt, 'numerator'):
                alt = alt.numerator / alt.denominator
            print(f"   {Wh}Altitude        : {Gr}{alt:.1f}m")
        
        if 'GPSTimeStamp' in gps_data:
            print(f"   {Wh}GPS Time        : {Gr}{gps_data['GPSTimeStamp']}")
        if 'GPSDateStamp' in gps_data:
            print(f"   {Wh}GPS Date        : {Gr}{gps_data['GPSDateStamp']}")
    
    # No metadata found
    if not exif_data and not gps_data:
        print(f"\n {Ye}No EXIF metadata found in this image.")
        print(f" {Wh}This could mean:")
        print(f"   • The image was stripped of metadata")
        print(f"   • The image format doesn't support EXIF (PNG, BMP)")
        print(f"   • The image was created without metadata")
    
    # Summary and warnings
    print(f"\n {Wh}" + "═" * 60)
    
    if gps_data:
        print(f"\n {Re}⚠ PRIVACY WARNING:{Wh}")
        print(f" {Wh}This image contains GPS coordinates! If you share this image,")
        print(f" {Wh}others may be able to determine where it was taken.")
    
    image.close()


def convert_gps_to_decimal(coords, ref):
    """Convert GPS coordinates from degrees/minutes/seconds to decimal."""
    if not coords or not ref:
        return None
    
    try:
        degrees = coords[0]
        minutes = coords[1]
        seconds = coords[2]
        
        # Handle IFDRational objects
        if hasattr(degrees, 'numerator'):
            degrees = degrees.numerator / degrees.denominator
        if hasattr(minutes, 'numerator'):
            minutes = minutes.numerator / minutes.denominator
        if hasattr(seconds, 'numerator'):
            seconds = seconds.numerator / seconds.denominator
        
        decimal = float(degrees) + float(minutes)/60 + float(seconds)/3600
        
        if ref in ['S', 'W']:
            decimal = -decimal
        
        return decimal
    except:
        return None


def get_mode_description(mode: str) -> str:
    """Get human-readable description of image mode."""
    modes = {
        '1': 'Black and White',
        'L': 'Grayscale',
        'P': 'Palette',
        'RGB': 'True Color',
        'RGBA': 'True Color + Alpha',
        'CMYK': 'Print Colors',
        'YCbCr': 'Video Format',
        'LAB': 'Lab Color Space',
        'HSV': 'Hue/Saturation/Value',
        'I': '32-bit Integer',
        'F': '32-bit Float',
    }
    return modes.get(mode, 'Unknown')


def format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} TB"


# OPTIONS MENU CONFIGURATION - Organized by category
MENU_CATEGORIES = [
    {
        'name': '🌐 Network & IP Tools',
        'color': Cy,
        'options': [
            {'num': 1, 'text': 'IP Tracker', 'func': IP_Track, 'desc': 'Track IP geolocation'},
            {'num': 2, 'text': 'Show Your IP', 'func': showIP, 'desc': 'Display your public IP'},
            {'num': 8, 'text': 'Port Scanner', 'func': port_scanner, 'desc': 'Scan open ports'},
            {'num': 9, 'text': 'Subnet Calculator', 'func': subnet_calculator, 'desc': 'Calculate network ranges'},
            {'num': 15, 'text': 'Network Scanner', 'func': network_scanner, 'desc': 'Scan local network devices'},
        ]
    },
    {
        'name': '🔍 OSINT & Lookup',
        'color': Gr,
        'options': [
            {'num': 3, 'text': 'Phone Tracker', 'func': phoneGW, 'desc': 'Phone number lookup'},
            {'num': 4, 'text': 'Username Search', 'func': TrackLu, 'desc': 'Find social profiles'},
            {'num': 5, 'text': 'WHOIS Lookup', 'func': whois_lookup, 'desc': 'Domain registration info'},
            {'num': 6, 'text': 'DNS Lookup', 'func': dns_lookup, 'desc': 'Query DNS records'},
            {'num': 13, 'text': 'Email Footprint', 'func': email_footprint, 'desc': 'Find email associations'},
            {'num': 14, 'text': 'Phone Footprint', 'func': phone_footprint, 'desc': 'Find phone associations'},
        ]
    },
    {
        'name': '🛡️ Security & Analysis',
        'color': Ye,
        'options': [
            {'num': 7, 'text': 'Header Analysis', 'func': website_headers, 'desc': 'Check security headers'},
            {'num': 12, 'text': 'Image EXIF', 'func': image_metadata_extractor, 'desc': 'Extract image metadata'},
        ]
    },
    {
        'name': '🔧 Utilities',
        'color': Mage,
        'options': [
            {'num': 10, 'text': 'Password Gen', 'func': password_generator, 'desc': 'Generate secure passwords'},
            {'num': 11, 'text': 'Hash Tools', 'func': hash_generator, 'desc': 'Generate/identify hashes'},
        ]
    },
]

# Flatten options for lookup
options = []
for category in MENU_CATEGORIES:
    options.extend(category['options'])
options.append({'num': 0, 'text': 'Exit', 'func': exit, 'desc': 'Exit the application'})


def clear():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def call_option(opt: int) -> None:
    """Execute the function associated with the given option number."""
    if not is_in_options(opt):
        raise ValueError(f'{Re}Option {opt} not found. Please select a valid option.')
    for option in options:
        if option['num'] == opt:
            if 'func' in option:
                option['func']()
            else:
                print(f'{Ye}No function assigned to this option.')
            break


def execute_option(opt: int) -> None:
    """Execute option with error handling and continuation prompt."""
    try:
        call_option(opt)
        print(f"\n  {Wh}{'─' * 50}")
        input(f'  {Gr}✓ Operation complete.{Wh} Press Enter to continue...')
        main()
    except ValueError as e:
        print(e)
        time.sleep(2)
        main()
    except KeyboardInterrupt:
        print(f'\n  {Ye}⚠ Operation cancelled.{Wh} Returning to menu...')
        time.sleep(1)
        main()


def option_text() -> str:
    """Generate formatted menu options text with categories."""
    lines = []
    for category in MENU_CATEGORIES:
        lines.append(f"\n  {category['color']}─── {category['name']} ───{Wh}")
        for opt in category['options']:
            num_str = f"{opt['num']:2d}"
            lines.append(f"   {Wh}[{Cy}{num_str}{Wh}] {Gr}{opt['text']:<16}{Wh}│ {Bl}{opt.get('desc', '')}{Wh}")
    lines.append(f"\n   {Wh}[{Re} 0{Wh}] {Re}Exit{Wh}")
    return '\n'.join(lines)


def is_in_options(num: int) -> bool:
    """Check if the given number is a valid menu option."""
    return any(opt['num'] == num for opt in options)


def show_quick_help():
    """Display quick help tips."""
    tips = [
        "Tip: Use Ctrl+C to cancel any operation",
        "Tip: IP addresses can be IPv4 or IPv6",
        "Tip: Phone numbers should include country code",
        "Tip: Some websites block automated requests",
        "Tip: Port scanning may be slow on filtered ports",
    ]
    import random
    print(f"\n  {Cy}💡 {random.choice(tips)}{Wh}")


def option():
    """Display the main menu banner and options."""
    clear()
    
    # Animated banner
    banner = f"""{Cy}
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                                                                   ║
    ║  {Ye}  ███╗   ██╗███████╗██╗  ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗  {Cy}║
    ║  {Ye}  ████╗  ██║██╔════╝╚██╗██╔╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║  {Cy}║
    ║  {Ye}  ██╔██╗ ██║█████╗   ╚███╔╝ ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║  {Cy}║
    ║  {Ye}  ██║╚██╗██║██╔══╝   ██╔██╗ ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║  {Cy}║
    ║  {Ye}  ██║ ╚████║███████╗██╔╝ ██╗██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║  {Cy}║
    ║  {Ye}  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝  {Cy}║
    ║                                                                   ║
    ╠═══════════════════════════════════════════════════════════════════╣
    ║  {Wh}👤 Author: Kumar Devashish    {Ye}📌 Version: 3.0              {Cy}║
    ║  {Wh}🔧 Tools: 12                  {Ye}🌐 Advanced OSINT Toolkit    {Cy}║
    ╚═══════════════════════════════════════════════════════════════════╝{Wh}
    """
    print(banner)
    
    # Menu options
    print(option_text())
    
    # Quick help
    show_quick_help()
    
    # Status bar
    print(f"\n  {Wh}{'─' * 60}")


def run_banner():
    """Display the animated banner before each operation."""
    clear()
    banner = f"""
    {Cy}╔════════════════════════════════════════════════════════╗
    ║                                                        ║
    ║  {Ye}  ███╗   ██╗███████╗██╗  ██╗{Wh}██████╗ ███████╗ ██████╗{Cy}  ║
    ║  {Ye}  ████╗  ██║██╔════╝╚██╗██╔╝{Wh}██╔══██╗██╔════╝██╔════╝{Cy}  ║
    ║  {Ye}  ██╔██╗ ██║█████╗   ╚███╔╝ {Wh}██████╔╝█████╗  ██║     {Cy}  ║
    ║  {Ye}  ██║╚██╗██║██╔══╝   ██╔██╗ {Wh}██╔══██╗██╔══╝  ██║     {Cy}  ║
    ║  {Ye}  ██║ ╚████║███████╗██╔╝ ██╗{Wh}██║  ██║███████╗╚██████╗{Cy}  ║
    ║  {Ye}  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝{Wh}╚═╝  ╚═╝╚══════╝ ╚═════╝{Cy}  ║
    ║                                                        ║
    ║  {Wh}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Cy}  ║
    ║         {Ye}🔍 NexRecon - Reconnaissance Tool{Cy}            ║
    ║              {Ye}Code by Kumar Devashish{Cy}                  ║
    ╚════════════════════════════════════════════════════════╝{Wh}
    """
    print(banner)
    time.sleep(0.3)


def main():
    """Main entry point for the application."""
    clear()
    option()
    try:
        user_input = input(f"\n  {Wh}┌─ {Gr}Enter option number{Wh} ─────────────────────────────┐\n  │ {Cy}>>> {Wh}").strip()
        
        if not user_input:
            print(f'  {Ye}⚠ Please select an option.{Wh}')
            time.sleep(1.5)
            main()
            return
        
        # Handle quick commands
        if user_input.lower() in ['q', 'quit', 'exit']:
            print(f'\n  {Ye}👋 Goodbye! Thanks for using NexRecon!{Wh}')
            time.sleep(1)
            exit(0)
        
        if user_input.lower() in ['h', 'help', '?']:
            show_help()
            input(f'\n  {Wh}Press Enter to continue...{Wh}')
            main()
            return
            
        opt = int(user_input)
        execute_option(opt)
    except ValueError:
        print(f'\n  {Re}✗ Invalid input. Please enter a number (0-12).{Wh}')
        time.sleep(2)
        main()
    except KeyboardInterrupt:
        print(f'\n\n  {Cy}👋 Goodbye!{Wh}')
        time.sleep(1)
        exit(0)


def show_help():
    """Display detailed help information."""
    clear()
    help_text = f"""
    {Cy}╔════════════════════════════════════════════════════════════╗
    ║                    📖 HELP & USAGE                         ║
    ╠════════════════════════════════════════════════════════════╣{Wh}
    ║                                                            ║
    ║  {Gr}QUICK COMMANDS:{Wh}                                          ║
    ║    • Enter number (1-12) to select a tool                  ║
    ║    • Type 'q' or '0' to exit                               ║
    ║    • Type 'h' or '?' for this help                         ║
    ║    • Press Ctrl+C to cancel any operation                  ║
    ║                                                            ║
    ║  {Gr}NETWORK TOOLS:{Wh}                                            ║
    ║    [1] IP Tracker    - Get geolocation from IP address     ║
    ║    [2] Show Your IP  - Display your public IP              ║
    ║    [8] Port Scanner  - Scan for open ports                 ║
    ║    [9] Subnet Calc   - Calculate network ranges            ║
    ║                                                            ║
    ║  {Gr}OSINT TOOLS:{Wh}                                              ║
    ║    [3] Phone Tracker - Lookup phone number details         ║
    ║    [4] Username Search - Find social media profiles        ║
    ║    [5] WHOIS Lookup  - Get domain registration info        ║
    ║    [6] DNS Lookup    - Query DNS records                   ║
    ║                                                            ║
    ║  {Gr}SECURITY TOOLS:{Wh}                                           ║
    ║    [7] Header Check  - Analyze website security headers    ║
    ║    [12] Image EXIF   - Extract metadata from images        ║
    ║                                                            ║
    ║  {Gr}UTILITIES:{Wh}                                                ║
    ║    [10] Password Gen - Generate secure passwords           ║
    ║    [11] Hash Tools   - Generate or identify hashes         ║
    {Cy}║                                                            ║
    ╚════════════════════════════════════════════════════════════╝{Wh}
    """
    print(help_text)


if __name__ == '__main__':
    try:
        # Show welcome animation on first run
        clear()
        print(f"\n\n{Ye}")
        animated_print("    ⚡ Initializing NexRecon...", 0.03)
        time.sleep(0.5)
        print(f"{Gr}    ✓ All modules loaded successfully{Wh}")
        time.sleep(0.3)
        print(f"{Gr}    ✓ Network connection verified{Wh}")
        time.sleep(0.3)
        if PIL_AVAILABLE:
            print(f"{Gr}    ✓ Image processing module ready{Wh}")
        else:
            print(f"{Ye}    ⚠ Image module not available (pip install Pillow){Wh}")
        time.sleep(0.5)
        print(f"\n{Ye}    🚀 Launching NexRecon...{Wh}")
        time.sleep(1)
        main()
    except KeyboardInterrupt:
        print(f'\n\n  {Ye}👋 Goodbye!{Wh}')
        time.sleep(1)
        exit(0)
    except Exception as e:
        print(f'\n{Re}Unexpected error: {e}{Wh}')
        exit(1)
