import requests
import time
from typing import Dict, Any
from shared.logger import get_logger

logger = get_logger("sensors.god_eye")

class GodEyeTracker:
    def __init__(self):
        self._cache = {}
        
    def geolocate(self, ip: str) -> Dict[str, Any]:
        if ip in self._cache:
            return self._cache[ip]

        # Handle local / reserved IPs
        if ip.startswith("192.168.") or ip.startswith("10.") or ip == "127.0.0.1":
            res = {
                "lat": 34.0522,
                "lon": -118.2437,
                "city": "Los Angeles (Local Hub)",
                "country": "US",
                "isp": "Local Network",
                "org": "Project Ultron",
                "threat_score": 0
            }
            self._cache[ip] = res
            return res

        try:
            resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    res = {
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                        "city": data.get("city", "Unknown City"),
                        "country": data.get("country", "Unknown Country"),
                        "isp": data.get("isp", "Unknown ISP"),
                        "org": data.get("org", "Unknown Org"),
                        "threat_score": 50 # Default baseline
                    }
                    self._cache[ip] = res
                    return res
        except Exception as e:
            logger.warning("Failed to geolocate %s: %s", ip, e)
            
        # Fallback
        res = {
            "lat": 0.0,
            "lon": 0.0,
            "city": "Unknown",
            "country": "Unknown",
            "isp": "Unknown",
            "org": "Unknown",
            "threat_score": 0
        }
        return res
