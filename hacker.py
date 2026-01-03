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
