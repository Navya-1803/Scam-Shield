import re
import logging
import requests
import os
from urllib.parse import urlparse
from typing import Dict, List, Tuple

class SecurityAnalyzer:
    """Security analyzer for SMS messages, URLs, and UPI requests"""
    
    def __init__(self):
        """Initialize the analyzer with patterns and keywords"""
        self.scam_keywords = [
            # Urgency words
            'urgent', 'immediate', 'expires', 'limited time', 'act now', 'hurry',
            'emergency', 'asap', 'deadline', 'today only', 'last chance',
            
            # Financial scam words
            'prize', 'winner', 'congratulations', 'lottery', 'jackpot',
            'refund', 'tax refund', 'cashback', 'bonus', 'reward',
            'verify account', 'suspended', 'blocked', 'frozen',
            'click here', 'click link', 'verify now', 'update details',
            'validate account', 'secure paytm', 'win money', 'verify now',
            'confirm payment', 'update payment', 'secure login',
            
            # Suspicious requests
            'send money', 'transfer funds', 'pay immediately', 'wire transfer',
            'bitcoin', 'cryptocurrency', 'gift card', 'voucher',
            'personal information', 'bank details', 'pin', 'password',
            'otp', 'one time password', 'verification code',
            'moneytransfer', 'paytransfer', 'upi transfer', 'instant transfer',
            
            # Phishing indicators
            'phishing', 'fake', 'scam', 'fraud', 'suspicious'
        ]
        
        # Suspicious domain patterns
        self.suspicious_domains = [
            # URL shorteners
            r'bit\.ly', r'tinyurl\.com', r't\.co', r'short\.link', r'rb\.gy',
            r'ow\.ly', r'goo\.gl', r'buff\.ly', r'is\.gd', r'tiny\.cc',
            
            # IP addresses
            r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',
            
            # Free/suspicious TLDs
            r'[a-z0-9\-]+\.tk$', r'[a-z0-9\-]+\.ml$', r'[a-z0-9\-]+\.ga$',
            r'[a-z0-9\-]+\.cf$', r'[a-z0-9\-]+\.ru$', r'[a-z0-9\-]+\.cn$',
            r'[a-z0-9\-]+\.win$', r'[a-z0-9\-]+\.top$', r'[a-z0-9\-]+\.click$',
            r'[a-z0-9\-]+\.download$', r'[a-z0-9\-]+\.loan$', r'[a-z0-9\-]+\.racing$',
            r'[a-z0-9\-]+\.review$', r'[a-z0-9\-]+\.party$', r'[a-z0-9\-]+\.cricket$',
        ]
        
        # Phishing domain patterns (impersonation)
        self.phishing_patterns = [
            # Banking/Payment services
            r'.*paytm.*(?:secure|verify|update|login|validate).*',
            r'.*phonepe.*(?:secure|verify|update|login|validate).*',
            r'.*amazon.*(?:secure|verify|update|login|validate|giveaway|offer|win).*',
            r'.*google.*(?:secure|verify|update|login|validate).*',
            r'.*facebook.*(?:secure|verify|update|login|validate).*',
            r'.*whatsapp.*(?:secure|verify|update|login|validate).*',
            r'.*instagram.*(?:secure|verify|update|login|validate).*',
            r'.*sbi.*(?:secure|verify|update|login|validate).*',
            r'.*hdfc.*(?:secure|verify|update|login|validate).*',
            r'.*icici.*(?:secure|verify|update|login|validate).*',
            
            # Generic phishing patterns
            r'.*(?:secure|verify|update|validate|confirm).*(?:account|payment|upi|wallet).*',
            r'.*(?:win|prize|lottery|reward|bonus).*(?:money|cash|amount).*',
            r'.*upi.*(?:pay|transfer|send|receive).*(?:\.in|\.com).*',
            r'.*(?:click|tap).*(?:here|now|link).*(?:verify|confirm|claim).*',
        ]
        
        # Suspicious URL path patterns
        self.suspicious_paths = [
            r'/(?:verify|validate|confirm|update|secure)[-_]?(?:account|payment|upi)',
            r'/(?:login|signin).*(?:verify|confirm)',
            r'/(?:win|prize|bonus|reward|giveaway)',
            r'/(?:moneytransfer|paytransfer|upipay)',
            r'/(?:claim|redeem).*(?:prize|reward|bonus)',
        ]
        
        # UPI patterns
        self.upi_pattern = r'[a-zA-Z0-9\.\-_]+@[a-zA-Z0-9\-_]+'
        
        # Phone number patterns
        self.phone_pattern = r'[\+]?[1-9]?[0-9]{7,15}'
        
        # URL patterns
        self.url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        
        # Google Safe Browsing API configuration
        self.safe_browsing_api_key = os.environ.get('GOOGLE_SAFE_BROWSING_API_KEY')
        self.safe_browsing_enabled = bool(self.safe_browsing_api_key)
        
    def analyze_content(self, content: str) -> Dict:
        """
        Analyze content and return security assessment
        
        Args:
            content: The content to analyze (SMS, URL, or UPI request)
            
        Returns:
            Dictionary with analysis results
        """
        content_lower = content.lower()
        
        result = {
            'content': content,
            'risk_level': 'Safe',
            'score': 0,
            'warnings': [],
            'patterns_detected': [],
            'recommendations': []
        }
        
        # Check for suspicious keywords
        keyword_score = self._check_keywords(content_lower, result)
        
        # Check for URLs
        url_score = self._check_urls(content, result)
        
        # Check for UPI patterns
        upi_score = self._check_upi_patterns(content, result)
        
        # Check for phone numbers
        phone_score = self._check_phone_patterns(content, result)
        
        # Calculate total risk score
        total_score = keyword_score + url_score + upi_score + phone_score
        result['score'] = min(total_score, 100)  # Cap at 100
        
        # Determine risk level
        if result['score'] >= 70:
            result['risk_level'] = 'Dangerous'
        elif result['score'] >= 30:
            result['risk_level'] = 'Suspicious'
        else:
            result['risk_level'] = 'Safe'
        
        # Add general recommendations
        self._add_recommendations(result)
        
        logging.debug(f"Analysis complete: {result['risk_level']} (score: {result['score']})")
        return result
    
    def _check_keywords(self, content_lower: str, result: Dict) -> int:
        """Check for suspicious keywords"""
        score = 0
        found_keywords = []
        
        for keyword in self.scam_keywords:
            if keyword in content_lower:
                found_keywords.append(keyword)
                score += 10
        
        if found_keywords:
            result['patterns_detected'].append(f"Suspicious keywords: {', '.join(found_keywords[:5])}")
            result['warnings'].append("Contains words commonly used in scam messages")
        
        return min(score, 50)  # Cap keyword score at 50
    
    def _check_urls(self, content: str, result: Dict) -> int:
        """Check for suspicious URLs"""
        score = 0
        urls = re.findall(self.url_pattern, content)
        
        if urls:
            result['patterns_detected'].append(f"Found {len(urls)} URL(s)")
            
            for url in urls:
                try:
                    parsed = urlparse(url)
                    domain = parsed.netloc.lower()
                    path = parsed.path.lower()
                    query = parsed.query.lower()
                    full_url = url.lower()
                    
                    # Check against suspicious domain patterns
                    suspicious_domain_found = False
                    for pattern in self.suspicious_domains:
                        if re.search(pattern, domain):
                            score += 30
                            result['warnings'].append(f"High-risk domain detected: {domain}")
                            suspicious_domain_found = True
                            break
                    
                    # Check for phishing domain patterns
                    for pattern in self.phishing_patterns:
                        if re.search(pattern, domain):
                            score += 35
                            result['warnings'].append(f"Phishing domain pattern detected: {domain}")
                            suspicious_domain_found = True
                            break
                    
                    # Check suspicious URL paths
                    for pattern in self.suspicious_paths:
                        if re.search(pattern, path):
                            score += 25
                            result['warnings'].append(f"Suspicious URL path detected: {path}")
                            break
                    
                    # Check for UPI-related scam patterns in query parameters
                    if 'upi=' in query and not any(legit in domain for legit in ['paytm.com', 'phonepe.com', 'googlepay.com']):
                        score += 20
                        result['warnings'].append("UPI parameter in non-standard domain detected")
                    
                    # Additional suspicious indicators if not already flagged as high-risk
                    if not suspicious_domain_found:
                        # Very long domain
                        if len(domain) > 50:
                            score += 15
                            result['warnings'].append("Unusually long domain name detected")
                        
                        # Many hyphens in domain
                        if domain.count('-') > 3:
                            score += 12
                            result['warnings'].append("Domain with excessive hyphens detected")
                        
                        # Many numbers in domain
                        if re.search(r'[0-9]{4,}', domain):
                            score += 15
                            result['warnings'].append("Domain with long number sequence detected")
                        
                        # Suspicious keywords in domain/path combination
                        suspicious_keywords = ['secure', 'verify', 'update', 'validate', 'confirm', 'win', 'prize', 'bonus', 'giveaway']
                        keyword_count = sum(1 for keyword in suspicious_keywords if keyword in full_url)
                        if keyword_count >= 2:
                            score += 20
                            result['warnings'].append("Multiple suspicious keywords in URL detected")
                        
                        # Check for typosquatting patterns
                        known_brands = ['amazon', 'google', 'facebook', 'paytm', 'phonepe', 'whatsapp', 'instagram']
                        for brand in known_brands:
                            if brand in domain and not domain.endswith(f'{brand}.com'):
                                # Check if it's a legitimate subdomain vs typosquatting
                                if not (domain.startswith(f'{brand}.') or f'.{brand}.' in domain):
                                    score += 25
                                    result['warnings'].append(f"Potential brand impersonation detected: {brand}")
                    
                    # Check against Google Safe Browsing API if enabled
                    if self.safe_browsing_enabled:
                        safe_browsing_result = self._check_safe_browsing(url)
                        if safe_browsing_result['is_malicious']:
                            score += 50
                            result['warnings'].append(f"URL flagged by Google Safe Browsing: {safe_browsing_result['threat_type']}")
                
                except Exception as e:
                    logging.warning(f"Error parsing URL {url}: {str(e)}")
                    score += 8
        
        return min(score, 80)  # Increased cap for URL score
    
    def _check_upi_patterns(self, content: str, result: Dict) -> int:
        """Check for UPI payment patterns"""
        score = 0
        upi_matches = re.findall(self.upi_pattern, content)
        
        if upi_matches:
            result['patterns_detected'].append(f"Found {len(upi_matches)} UPI ID(s)")
            
            for upi_id in upi_matches:
                # Check for suspicious UPI patterns
                if '@paytm' in upi_id.lower() or '@phonepe' in upi_id.lower():
                    # These are common legitimate UPI providers
                    score += 5
                elif len(upi_id.split('@')[0]) < 4:  # Very short UPI handle
                    score += 15
                    result['warnings'].append("Short UPI handle detected (potentially suspicious)")
                elif re.search(r'[0-9]{8,}', upi_id):  # Long number sequences
                    score += 10
                    result['warnings'].append("UPI ID with long number sequence detected")
                else:
                    score += 8  # Generic UPI detected
            
            result['warnings'].append("UPI payment request detected - verify recipient carefully")
        
        return min(score, 30)  # Cap UPI score at 30
    
    def _check_phone_patterns(self, content: str, result: Dict) -> int:
        """Check for phone number patterns"""
        score = 0
        phone_matches = re.findall(self.phone_pattern, content)
        
        if phone_matches:
            unique_phones = list(set(phone_matches))
            result['patterns_detected'].append(f"Found {len(unique_phones)} phone number(s)")
            
            for phone in unique_phones:
                # Remove non-digits for analysis
                digits_only = re.sub(r'\D', '', phone)
                
                if len(digits_only) == 10 and digits_only.startswith(('6', '7', '8', '9')):
                    # Indian mobile number pattern
                    score += 5
                elif len(digits_only) > 15:  # Unusually long
                    score += 15
                    result['warnings'].append("Unusually long phone number detected")
                else:
                    score += 8
            
            if len(unique_phones) > 2:
                score += 10
                result['warnings'].append("Multiple phone numbers detected")
        
        return min(score, 25)  # Cap phone score at 25
    
    def _check_safe_browsing(self, url: str) -> Dict:
        """Check URL against Google Safe Browsing API"""
        if not self.safe_browsing_enabled:
            return {'is_malicious': False, 'threat_type': None}
        
        try:
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.safe_browsing_api_key}"
            
            payload = {
                "client": {
                    "clientId": "cyberaware-scam-detector",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION"
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            response = requests.post(api_url, json=payload, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if 'matches' in data and data['matches']:
                    threat_type = data['matches'][0].get('threatType', 'UNKNOWN')
                    return {'is_malicious': True, 'threat_type': threat_type}
                else:
                    return {'is_malicious': False, 'threat_type': None}
            else:
                logging.warning(f"Safe Browsing API error: {response.status_code}")
                return {'is_malicious': False, 'threat_type': None}
                
        except requests.RequestException as e:
            logging.warning(f"Safe Browsing API request failed: {str(e)}")
            return {'is_malicious': False, 'threat_type': None}
        except Exception as e:
            logging.error(f"Safe Browsing API unexpected error: {str(e)}")
            return {'is_malicious': False, 'threat_type': None}
    
    def _add_recommendations(self, result: Dict):
        """Add security recommendations based on analysis"""
        if result['risk_level'] == 'Dangerous':
            result['recommendations'].extend([
                "❌ Do NOT click any links or respond to this message",
                "❌ Do NOT provide any personal or financial information",
                "❌ Do NOT make any payments or transfers",
                "🚨 Report this as a scam to relevant authorities",
                "🛡️ Block the sender if possible"
            ])
        elif result['risk_level'] == 'Suspicious':
            result['recommendations'].extend([
                "⚠️ Verify the sender's identity through official channels",
                "⚠️ Do not click links - visit official websites directly",
                "⚠️ Be cautious about providing any information",
                "🔍 Cross-check any claims with official sources",
                "📞 Contact the organization directly if uncertain"
            ])
        else:
            result['recommendations'].extend([
                "✅ Content appears safe, but always remain vigilant",
                "🔍 Verify important information through official channels",
                "🛡️ Never share sensitive information via SMS or email",
                "📱 Keep your security software updated"
            ])
