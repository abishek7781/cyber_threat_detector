import requests
import json
from urllib.parse import urlparse
import hashlib
import hmac
import time

class ThreatIntelligence:
    def __init__(self):
        self.urlhaus_api_url = "https://urlhaus-api.abuse.ch/v1/"
        self.phishtank_api_url = "https://checkurl.phishtank.com/checkurl/"
        self.google_sb_api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        self.ipqs_api_url = "https://www.ipqualityscore.com/api/json/url"
        self.alienvault_api_url = "https://otx.alienvault.com/api/v1/indicators/domain"
        self.threatfox_api_url = "https://threatfox-api.abuse.ch/api/v1/"
        self.talos_api_url = "https://talosintelligence.com/api/v1/domain"
        
        # API Keys (replace with your actual keys)
        self.google_sb_api_key = "YOUR_GOOGLE_SAFE_BROWSING_API_KEY"
        self.ipqs_api_key = "YOUR_IPQUALITYSCORE_API_KEY"
        self.alienvault_api_key = "YOUR_ALIENVAULT_API_KEY"
        self.threatfox_api_key = "YOUR_THREATFOX_API_KEY"
        self.talos_api_key = "YOUR_TALOS_API_KEY"

    def check_urlhaus(self, url):
        """Check if URL is in URLhaus database (Abuse.ch)"""
        try:
            data = {"url": url}
            response = requests.post(self.urlhaus_api_url, data=data)
            if response.status_code == 200:
                result = response.json()
                return {
                    "is_malware": result.get("query_status") == "ok",
                    "threat_type": result.get("threat"),
                    "tags": result.get("tags", []),
                    "date_added": result.get("date_added")
                }
        except Exception as e:
            print(f"URLhaus API error: {str(e)}")
        return None

    def check_phishtank(self, url):
        """Check if URL is in PhishTank database"""
        try:
            data = {
                "url": url,
                "format": "json"
            }
            response = requests.post(self.phishtank_api_url, data=data)
            if response.status_code == 200:
                result = response.json()
                return {
                    "is_phishing": result.get("in_database", False),
                    "verified": result.get("verified", False),
                    "verified_at": result.get("verified_at")
                }
        except Exception as e:
            print(f"PhishTank API error: {str(e)}")
        return None

    def check_google_safe_browsing(self, url):
        """Check URL against Google Safe Browsing API"""
        try:
            api_url = f"{self.google_sb_api_url}?key={self.google_sb_api_key}"
            payload = {
                "client": {
                    "clientId": "cyberthreat-detection",
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
            
            response = requests.post(api_url, json=payload)
            if response.status_code == 200:
                result = response.json()
                return {
                    "is_safe": not bool(result),
                    "threats": result.get("matches", [])
                }
        except Exception as e:
            print(f"Google Safe Browsing API error: {str(e)}")
        return None

    def check_ipqualityscore(self, domain):
        """Check domain reputation using IPQualityScore API"""
        try:
            api_url = f"{self.ipqs_api_url}/{self.ipqs_api_key}/{domain}"
            response = requests.get(api_url)
            if response.status_code == 200:
                result = response.json()
                return {
                    "risk_score": result.get("risk_score", 0),
                    "is_valid": result.get("valid", False),
                    "is_suspicious": result.get("suspicious", False),
                    "is_malware": result.get("malware", False),
                    "is_phishing": result.get("phishing", False),
                    "is_spam": result.get("spam", False),
                    "is_adult": result.get("adult", False),
                    "is_parking": result.get("parking", False),
                    "is_spoofing": result.get("spoofing", False),
                    "is_domain_blacklisted": result.get("domain_blacklisted", False),
                    "is_ip_blacklisted": result.get("ip_blacklisted", False),
                    "is_proxy": result.get("proxy", False),
                    "is_vpn": result.get("vpn", False),
                    "is_tor": result.get("tor", False),
                    "is_bot": result.get("bot", False),
                    "is_high_risk": result.get("high_risk", False)
                }
        except Exception as e:
            print(f"IPQualityScore API error: {str(e)}")
        return None

    def check_alienvault(self, domain):
        """Check domain against AlienVault OTX"""
        try:
            headers = {
                'X-OTX-API-KEY': self.alienvault_api_key
            }
            response = requests.get(f"{self.alienvault_api_url}/{domain}", headers=headers)
            if response.status_code == 200:
                result = response.json()
                return {
                    "pulse_count": result.get("pulse_info", {}).get("count", 0),
                    "malware_count": result.get("malware", {}).get("count", 0),
                    "url_count": result.get("url_list", {}).get("count", 0),
                    "reputation": result.get("reputation", 0),
                    "threat_score": result.get("threat_score", 0),
                    "categories": result.get("categories", []),
                    "tags": result.get("tags", [])
                }
        except Exception as e:
            print(f"AlienVault API error: {str(e)}")
        return None

    def check_threatfox(self, url):
        """Check URL against ThreatFox database"""
        try:
            data = {
                "query": "search_ioc",
                "search_term": url
            }
            headers = {
                'API-KEY': self.threatfox_api_key
            }
            response = requests.post(self.threatfox_api_url, json=data, headers=headers)
            if response.status_code == 200:
                result = response.json()
                return {
                    "is_malware": result.get("query_status") == "ok",
                    "threat_type": result.get("threat_type"),
                    "confidence_level": result.get("confidence_level"),
                    "malware_type": result.get("malware_type"),
                    "tags": result.get("tags", [])
                }
        except Exception as e:
            print(f"ThreatFox API error: {str(e)}")
        return None

    def check_talos(self, domain):
        """Check domain against Cisco Talos"""
        try:
            headers = {
                'Authorization': f'Bearer {self.talos_api_key}'
            }
            response = requests.get(f"{self.talos_api_url}/{domain}", headers=headers)
            if response.status_code == 200:
                result = response.json()
                return {
                    "reputation": result.get("reputation", 0),
                    "category": result.get("category", ""),
                    "web_reputation": result.get("web_reputation", 0),
                    "email_reputation": result.get("email_reputation", 0),
                    "web_risk_score": result.get("web_risk_score", 0),
                    "email_risk_score": result.get("email_risk_score", 0),
                    "web_risk_level": result.get("web_risk_level", ""),
                    "email_risk_level": result.get("email_risk_level", "")
                }
        except Exception as e:
            print(f"Cisco Talos API error: {str(e)}")
        return None

    def analyze_url(self, url):
        """Analyze URL using all available threat intelligence sources"""
        domain = urlparse(url).netloc
        
        results = {
            "urlhaus": self.check_urlhaus(url),
            "phishtank": self.check_phishtank(url),
            "google_safe_browsing": self.check_google_safe_browsing(url),
            "ipqualityscore": self.check_ipqualityscore(domain),
            "alienvault": self.check_alienvault(domain),
            "threatfox": self.check_threatfox(url),
            "talos": self.check_talos(domain)
        }
        
        # Calculate overall threat level
        threat_level = "LOW"
        threat_reasons = []
        threat_score = 0
        
        # URLhaus check
        if results["urlhaus"] and results["urlhaus"].get("is_malware"):
            threat_level = "HIGH"
            threat_reasons.append("URL detected in URLhaus malware database")
            threat_score += 100
            
        # PhishTank check
        if results["phishtank"] and results["phishtank"].get("is_phishing"):
            threat_level = "HIGH"
            threat_reasons.append("URL detected in PhishTank phishing database")
            threat_score += 100
            
        # Google Safe Browsing check
        if results["google_safe_browsing"] and not results["google_safe_browsing"].get("is_safe"):
            threat_level = "HIGH"
            threat_reasons.append("URL flagged by Google Safe Browsing")
            threat_score += 100
            
        # IPQualityScore check
        if results["ipqualityscore"]:
            if results["ipqualityscore"].get("is_high_risk"):
                threat_level = "HIGH"
                threat_reasons.append("High risk score from IPQualityScore")
                threat_score += 80
            threat_score += results["ipqualityscore"].get("risk_score", 0)
            
        # AlienVault check
        if results["alienvault"]:
            if results["alienvault"].get("pulse_count", 0) > 0:
                threat_level = "HIGH"
                threat_reasons.append(f"Domain has {results['alienvault']['pulse_count']} threat pulses in AlienVault")
                threat_score += results["alienvault"].get("threat_score", 0)
                
        # ThreatFox check
        if results["threatfox"] and results["threatfox"].get("is_malware"):
            threat_level = "HIGH"
            threat_reasons.append("URL detected in ThreatFox malware database")
            threat_score += 100
            
        # Cisco Talos check
        if results["talos"]:
            if results["talos"].get("web_risk_level") == "HIGH":
                threat_level = "HIGH"
                threat_reasons.append("High risk level from Cisco Talos")
                threat_score += 80
            threat_score += results["talos"].get("web_risk_score", 0)
            
        # Normalize threat score to 0-100 range
        threat_score = min(100, threat_score / 5)
            
        return {
            "threat_level": threat_level,
            "threat_score": threat_score,
            "threat_reasons": threat_reasons,
            "intelligence_results": results
        } 