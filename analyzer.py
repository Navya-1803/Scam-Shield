import re
import logging
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
            
            # Suspicious requests
            'send money', 'transfer funds', 'pay immediately', 'wire transfer',
            'bitcoin', 'cryptocurrency', 'gift card', 'voucher',
            'personal information', 'bank details', 'pin', 'password',
            'otp', 'one time password', 'verification code',
            
            # Phishing indicators
            'phishing', 'fake', 'scam', 'fraud', 'suspicious'
        ]
        
        # Suspicious domain patterns
        self.suspicious_domains = [
            r'bit\.ly', r'tinyurl\.com', r't\.co', r'short\.link',
            r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',  # IP addresses
            r'[a-z0-9\-]+\.tk$', r'[a-z0-9\-]+\.ml$', r'[a-z0-9\-]+\.ga$',  # Free domains
        ]
        
        # UPI patterns
        self.upi_pattern = r'[a-zA-Z0-9\.\-_]+@[a-zA-Z0-9\-_]+'
        
        # Phone number patterns
        self.phone_pattern = r'[\+]?[1-9]?[0-9]{7,15}'
        
        # URL patterns
        self.url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        
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
                    
                    # Check against suspicious domain patterns
                    for pattern in self.suspicious_domains:
                        if re.search(pattern, domain):
                            score += 25
                            result['warnings'].append(f"Suspicious domain detected: {domain}")
                            break
                    else:
                        # Check for other suspicious indicators
                        if len(domain) > 50:  # Very long domain
                            score += 15
                            result['warnings'].append("Unusually long domain name detected")
                        
                        if domain.count('-') > 3:  # Many hyphens
                            score += 10
                            result['warnings'].append("Domain with many hyphens detected")
                        
                        if re.search(r'[0-9]{3,}', domain):  # Many numbers in domain
                            score += 10
                            result['warnings'].append("Domain with many numbers detected")
                
                except Exception as e:
                    logging.warning(f"Error parsing URL {url}: {str(e)}")
                    score += 5
        
        return min(score, 40)  # Cap URL score at 40
    
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
