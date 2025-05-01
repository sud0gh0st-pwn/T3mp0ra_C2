import geoip2.database
from typing import Optional

class GeoIPLookup:
    def __init__(self, db_file: str) -> None:
        self.db_file = db_file

    def get_country(self, ip: str) -> Optional[str]:
        """Get country data from IP"""
        try:
            with geoip2.database.Reader(self.db_file) as reader:
                resp_country = reader.country(ip)
                return resp_country.country.name
        except Exception as e:
            print(f"Error in get_country: {e}")
            return None

    def get_city(self, ip: str) -> Optional[str]:
        """Get city data from IP"""
        try:
            with geoip2.database.Reader(self.db_file) as reader:
                resp_city = reader.city(ip)
                return resp_city.city.name
        except Exception as e:
            print(f"Error in get_city: {e}")
            return None

    def get_postcode(self, ip: str) -> Optional[str]:
        """Get postcode data from IP"""
        try:
            with geoip2.database.Reader(self.db_file) as reader:
                resp_postcode = reader.city(ip)
                return resp_postcode.postal.code
        except Exception as e:
            print(f"Error in get_postcode: {e}")
            return None