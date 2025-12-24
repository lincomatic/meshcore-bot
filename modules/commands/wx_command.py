#!/usr/bin/env python3
"""
Weather command for the MeshCore Bot
Provides weather information using zip codes and NOAA APIs
"""

import re
import json
import requests
import xml.dom.minidom
from datetime import datetime
from geopy.geocoders import Nominatim
import maidenhead as mh
from .base_command import BaseCommand
from ..models import MeshMessage


class WxCommand(BaseCommand):
    """Handles weather commands with zipcode support"""
    
    # Plugin metadata
    name = "wx"
    keywords = ['wx', 'weather', 'wxa', 'wxalert']
    description = "Get weather information for a zip code (usage: wx 12345)"
    category = "weather"
    cooldown_seconds = 5  # 5 second cooldown per user to prevent API abuse
    
    # Error constants
    NO_DATA_NOGPS = "No GPS data available"
    ERROR_FETCHING_DATA = "Error fetching weather data"
    NO_ALERTS = "No weather alerts"
    
    def __init__(self, bot):
        super().__init__(bot)
        self.url_timeout = 10  # seconds
        self.forecast_duration = 3  # days
        self.num_wx_alerts = 2  # number of alerts to show
        self.use_metric = False  # Use imperial units by default
        self.zulu_time = False  # Use local time by default
        
        # Per-user cooldown tracking
        self.user_cooldowns = {}  # user_id -> last_execution_time
        
        # Get default state from config for city disambiguation
        self.default_state = self.bot.config.get('Weather', 'default_state', fallback='WA')
        
        # Initialize geocoder
        self.geolocator = Nominatim(user_agent="meshcore-bot")
        
        # Get database manager for geocoding cache
        self.db_manager = bot.db_manager
    
    def get_help_text(self) -> str:
        return f"Usage: wx <zipcode|city> - Get weather for US zipcode or city in {self.default_state}"
    
    def matches_keyword(self, message: MeshMessage) -> bool:
        """Check if message starts with a weather keyword"""
        content = message.content.strip()
        if content.startswith('!'):
            content = content[1:].strip()
        content_lower = content.lower()
        for keyword in self.keywords:
            if content_lower.startswith(keyword + ' '):
                return True
        return False
    
    def can_execute(self, message: MeshMessage) -> bool:
        """Override cooldown check to be per-user instead of per-command-instance"""
        # Check if command requires DM and message is not DM
        if self.requires_dm and not message.is_dm:
            return False
        
        # Check per-user cooldown
        if self.cooldown_seconds > 0:
            import time
            current_time = time.time()
            user_id = message.sender_id
            
            if user_id in self.user_cooldowns:
                last_execution = self.user_cooldowns[user_id]
                if (current_time - last_execution) < self.cooldown_seconds:
                    return False
        
        return True
    
    def get_remaining_cooldown(self, user_id: str) -> int:
        """Get remaining cooldown time for a specific user"""
        if self.cooldown_seconds <= 0:
            return 0
        
        import time
        current_time = time.time()
        if user_id in self.user_cooldowns:
            last_execution = self.user_cooldowns[user_id]
            elapsed = current_time - last_execution
            remaining = self.cooldown_seconds - elapsed
            return max(0, int(remaining))
        
        return 0
    
    def _record_execution(self, user_id: str):
        """Record the execution time for a specific user"""
        import time
        self.user_cooldowns[user_id] = time.time()
    
    async def execute(self, message: MeshMessage) -> bool:
        """Execute the weather command"""
        content = message.content.strip()
        
        # Parse the command to extract location
        # Support formats: "wx 12345", "wx seattle", "wx paris, tx", "weather everett", "wxa bellingham"
        parts = content.split()
        if len(parts) < 2:
            await self.send_response(message, f"Usage: wx <zipcode|city> - Example: wx 12345 or wx seattle or wx paris, tx")
            return True
        
        # Join all parts after the command to handle "city, state" format
        location = ' '.join(parts[1:]).strip()
        
        # Check if it's a zipcode (5 digits) or city name
        if re.match(r'^\d{5}$', location):
            # It's a zipcode
            location_type = "zipcode"
        else:
            # It's a city name (possibly with state)
            location_type = "city"
        
        try:
            # Record execution for this user
            self._record_execution(message.sender_id)
            
            # Get weather data for the location
            weather_data = await self.get_weather_for_location(location, location_type)
            
            # Check if we need to send multiple messages
            if isinstance(weather_data, tuple) and weather_data[0] == "multi_message":
                # Send weather data first
                await self.send_response(message, weather_data[1])
                
                # Wait for bot TX rate limiter to allow next message
                import asyncio
                rate_limit = self.bot.config.getfloat('Bot', 'bot_tx_rate_limit_seconds', fallback=1.0)
                # Use a conservative sleep time to avoid rate limiting
                sleep_time = max(rate_limit + 1.0, 2.0)  # At least 2 seconds, or rate_limit + 1 second
                await asyncio.sleep(sleep_time)
                
                # Send the special weather statement
                alert_text = weather_data[2]
                alert_count = weather_data[3]
                await self.send_response(message, f"{alert_count} alerts: {alert_text}")
            else:
                # Send single message as usual
                await self.send_response(message, weather_data)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error in weather command: {e}")
            await self.send_response(message, f"Error getting weather data: {e}")
            return True
    
    async def get_weather_for_location(self, location: str, location_type: str) -> str:
        """Get weather data for a location (zipcode or city)"""
        try:
            # Convert location to lat/lon
            if location_type == "zipcode":
                lat, lon = self.zipcode_to_lat_lon(location)
                if lat is None or lon is None:
                    return f"Could not find location for zipcode {location}"
            else:  # city
                result = self.city_to_lat_lon(location)
                if len(result) == 3:
                    lat, lon, address_info = result
                else:
                    lat, lon = result
                    address_info = None
                
                if lat is None or lon is None:
                    return f"Could not find city '{location}' in {self.default_state}"
                
                # Check if the found city is in a different state than default
                actual_city = location
                actual_state = self.default_state
                if address_info:
                    # Try to get the best city name from various address fields
                    actual_city = (address_info.get('city') or 
                                 address_info.get('town') or 
                                 address_info.get('village') or 
                                 address_info.get('hamlet') or 
                                 address_info.get('municipality') or 
                                 location)
                    actual_state = address_info.get('state', self.default_state)
                    # Convert full state name to abbreviation if needed
                    if len(actual_state) > 2:
                        state_abbrev_map = {
                            'Washington': 'WA', 'California': 'CA', 'New York': 'NY', 'Texas': 'TX',
                            'Florida': 'FL', 'Illinois': 'IL', 'Pennsylvania': 'PA', 'Ohio': 'OH',
                            'Georgia': 'GA', 'North Carolina': 'NC', 'Michigan': 'MI', 'New Jersey': 'NJ',
                            'Virginia': 'VA', 'Tennessee': 'TN', 'Indiana': 'IN', 'Arizona': 'AZ',
                            'Massachusetts': 'MA', 'Missouri': 'MO', 'Maryland': 'MD', 'Wisconsin': 'WI',
                            'Colorado': 'CO', 'Minnesota': 'MN', 'South Carolina': 'SC', 'Alabama': 'AL',
                            'Louisiana': 'LA', 'Kentucky': 'KY', 'Oregon': 'OR', 'Oklahoma': 'OK',
                            'Connecticut': 'CT', 'Utah': 'UT', 'Iowa': 'IA', 'Nevada': 'NV',
                            'Arkansas': 'AR', 'Mississippi': 'MS', 'Kansas': 'KS', 'New Mexico': 'NM',
                            'Nebraska': 'NE', 'West Virginia': 'WV', 'Idaho': 'ID', 'Hawaii': 'HI',
                            'New Hampshire': 'NH', 'Maine': 'ME', 'Montana': 'MT', 'Rhode Island': 'RI',
                            'Delaware': 'DE', 'South Dakota': 'SD', 'North Dakota': 'ND', 'Alaska': 'AK',
                            'Vermont': 'VT', 'Wyoming': 'WY'
                        }
                        actual_state = state_abbrev_map.get(actual_state, actual_state)
                    
                    # Also check if the default state needs to be converted for comparison
                    default_state_full = self.default_state
                    if len(self.default_state) == 2:
                        # Convert abbreviation to full name for comparison
                        abbrev_to_full_map = {v: k for k, v in state_abbrev_map.items()}
                        default_state_full = abbrev_to_full_map.get(self.default_state, self.default_state)
            
            # Get weather forecast
            weather, points_data = self.get_noaa_weather(lat, lon)
            if weather == self.ERROR_FETCHING_DATA:
                return "Error fetching weather data from NOAA"
            
            # Add location info if city is in a different state than default
            location_prefix = ""
            if location_type == "city" and address_info:
                # Compare states (handle both full names and abbreviations)
                states_different = (actual_state != self.default_state and 
                                  actual_state != default_state_full)
                if states_different:
                    location_prefix = f"{actual_city}, {actual_state}: "
            
            # Try to get additional current conditions data
            current_conditions = self.get_current_conditions(points_data)
            if current_conditions and len(weather) < 120:
                weather = f"{weather} {current_conditions}"
            
            # Get weather alerts
            alerts_result = self.get_weather_alerts_noaa(lat, lon)
            if alerts_result == self.ERROR_FETCHING_DATA:
                alerts_info = None
            elif alerts_result == self.NO_ALERTS:
                alerts_info = None
            else:
                full_alert_text, abbreviated_alert_text, alert_count = alerts_result
                if alert_count > 0:
                    # Always send weather first, then alerts in separate message
                    self.logger.info(f"Found {alert_count} alerts - using two-message mode")
                    return ("multi_message", f"{location_prefix}{weather}", full_alert_text, alert_count)
            
            return f"{location_prefix}{weather}"
            
        except Exception as e:
            self.logger.error(f"Error getting weather for {location_type} {location}: {e}")
            return f"Error getting weather data: {e}"
    
    async def get_weather_for_zipcode(self, zipcode: str) -> str:
        """Get weather data for a specific zipcode (legacy method)"""
        return await self.get_weather_for_location(zipcode, "zipcode")
    
    def zipcode_to_lat_lon(self, zipcode: str) -> tuple:
        """Convert zipcode to latitude and longitude"""
        try:
            # Use Nominatim to geocode the zipcode
            location = self.geolocator.geocode(f"{zipcode}, USA")
            if location:
                return location.latitude, location.longitude
            else:
                return None, None
        except Exception as e:
            self.logger.error(f"Error geocoding zipcode {zipcode}: {e}")
            return None, None
    
    def city_to_lat_lon(self, city: str) -> tuple:
        """Convert city name to latitude and longitude using default state"""
        try:
            # Check cache first for default state query
            cache_query = f"{city}, {self.default_state}, USA"
            cached_lat, cached_lon = self.db_manager.get_cached_geocoding(cache_query)
            if cached_lat is not None and cached_lon is not None:
                self.logger.debug(f"Using cached geocoding for {city}")
                # Still need to do reverse geocoding for address details
                try:
                    reverse_location = self.geolocator.reverse(f"{cached_lat}, {cached_lon}")
                    if reverse_location:
                        return cached_lat, cached_lon, reverse_location.raw.get('address', {})
                except:
                    pass
                return cached_lat, cached_lon, {}
            
            # Check if the input contains a comma (city, state format)
            if ',' in city:
                # Parse city, state format
                city_parts = [part.strip() for part in city.split(',')]
                if len(city_parts) >= 2:
                    city_name = city_parts[0]
                    state = city_parts[1]
                    
                    # Try the specific city, state combination first
                    location = self.geolocator.geocode(f"{city_name}, {state}, USA")
                    if location:
                        # Cache the result
                        self.db_manager.cache_geocoding(f"{city_name}, {state}, USA", location.latitude, location.longitude)
                        
                        # Use reverse geocoding to get detailed address info
                        try:
                            reverse_location = self.geolocator.reverse(f"{location.latitude}, {location.longitude}")
                            if reverse_location:
                                return location.latitude, location.longitude, reverse_location.raw.get('address', {})
                        except:
                            pass
                        return location.latitude, location.longitude, location.raw.get('address', {})
            
            # For common city names, try major cities first to avoid small towns
            major_city_mappings = {
                'albany': ['Albany, NY, USA', 'Albany, OR, USA', 'Albany, CA, USA'],
                'portland': ['Portland, OR, USA', 'Portland, ME, USA'],
                'boston': ['Boston, MA, USA'],
                'paris': ['Paris, TX, USA', 'Paris, IL, USA', 'Paris, TN, USA'],
                'springfield': ['Springfield, IL, USA', 'Springfield, MO, USA', 'Springfield, MA, USA'],
                'franklin': ['Franklin, TN, USA', 'Franklin, MA, USA'],
                'georgetown': ['Georgetown, TX, USA', 'Georgetown, SC, USA'],
                'madison': ['Madison, WI, USA', 'Madison, AL, USA'],
                'auburn': ['Auburn, AL, USA', 'Auburn, WA, USA'],
                'troy': ['Troy, NY, USA', 'Troy, MI, USA'],
                'clinton': ['Clinton, IA, USA', 'Clinton, MS, USA']
            }
            
            # If it's a major city with multiple locations, try the major ones first
            if city.lower() in major_city_mappings:
                for major_city_query in major_city_mappings[city.lower()]:
                    location = self.geolocator.geocode(major_city_query)
                    if location:
                        # Cache the result
                        self.db_manager.cache_geocoding(major_city_query, location.latitude, location.longitude)
                        
                        # Use reverse geocoding to get detailed address info
                        try:
                            reverse_location = self.geolocator.reverse(f"{location.latitude}, {location.longitude}")
                            if reverse_location:
                                return location.latitude, location.longitude, reverse_location.raw.get('address', {})
                        except:
                            pass
                        return location.latitude, location.longitude, location.raw.get('address', {})
            
            # First try with default state
            location = self.geolocator.geocode(f"{city}, {self.default_state}, USA")
            if location:
                # Cache the result
                self.db_manager.cache_geocoding(f"{city}, {self.default_state}, USA", location.latitude, location.longitude)
                
                # Use reverse geocoding to get detailed address info
                try:
                    reverse_location = self.geolocator.reverse(f"{location.latitude}, {location.longitude}")
                    if reverse_location:
                        return location.latitude, location.longitude, reverse_location.raw.get('address', {})
                except:
                    pass
                return location.latitude, location.longitude, location.raw.get('address', {})
            else:
                # Try without state as fallback
                location = self.geolocator.geocode(f"{city}, USA")
                if location:
                    # Cache the result
                    self.db_manager.cache_geocoding(f"{city}, USA", location.latitude, location.longitude)
                    
                    # Use reverse geocoding to get detailed address info
                    try:
                        reverse_location = self.geolocator.reverse(f"{location.latitude}, {location.longitude}")
                        if reverse_location:
                            return location.latitude, location.longitude, reverse_location.raw.get('address', {})
                    except:
                        pass
                    return location.latitude, location.longitude, location.raw.get('address', {})
                else:
                    return None, None, None
        except Exception as e:
            self.logger.error(f"Error geocoding city {city}: {e}")
            return None, None, None
    
    def get_noaa_weather(self, lat: float, lon: float) -> tuple:
        """Get weather forecast from NOAA and return both weather string and points data"""
        try:
            # Get weather data from NOAA
            weather_api = f"https://api.weather.gov/points/{lat},{lon}"
            
            # Get the forecast URL
            weather_data = requests.get(weather_api, timeout=self.url_timeout)
            if not weather_data.ok:
                self.logger.warning("Error fetching weather data from NOAA")
                return self.ERROR_FETCHING_DATA, None
            
            weather_json = weather_data.json()
            forecast_url = weather_json['properties']['forecast']
            
            # Get the forecast
            forecast_data = requests.get(forecast_url, timeout=self.url_timeout)
            if not forecast_data.ok:
                self.logger.warning("Error fetching weather forecast from NOAA")
                return self.ERROR_FETCHING_DATA
            
            forecast_json = forecast_data.json()
            forecast = forecast_json['properties']['periods']
            
            # Format the forecast - focus on current conditions and key info
            if not forecast:
                return "No forecast data available"
            
            current = forecast[0]
            day_name = self.abbreviate_noaa(current['name'])
            temp = current.get('temperature', 'N/A')
            temp_unit = current.get('temperatureUnit', 'F')
            short_forecast = current.get('shortForecast', 'Unknown')
            wind_speed = current.get('windSpeed', '')
            wind_direction = current.get('windDirection', '')
            detailed_forecast = current.get('detailedForecast', '')
            
            # Extract additional useful info from detailed forecast
            humidity = self.extract_humidity(detailed_forecast)
            precip_chance = self.extract_precip_chance(detailed_forecast)
            
            # Create compact but complete weather string with emoji
            weather_emoji = self.get_weather_emoji(short_forecast)
            weather = f"{day_name}: {weather_emoji}{short_forecast} {temp}°{temp_unit}"
            
            # Add wind info if available
            if wind_speed and wind_direction:
                import re
                wind_match = re.search(r'(\d+)', wind_speed)
                if wind_match:
                    wind_num = wind_match.group(1)
                    wind_dir = self.abbreviate_wind_direction(wind_direction)
                    if wind_dir:
                        weather += f" {wind_dir}{wind_num}"
            
            # Add humidity if available and space allows
            if humidity and len(weather) < 90:
                weather += f" {humidity}%RH"
            
            # Add precipitation chance if available and space allows
            if precip_chance and len(weather) < 100:
                weather += f" 🌦️{precip_chance}%"
            
            # Add UV index if available and space allows
            uv_index = self.extract_uv_index(detailed_forecast)
            if uv_index and len(weather) < 110:
                weather += f" UV{uv_index}"
            
            # Add dew point if available and space allows
            dew_point = self.extract_dew_point(detailed_forecast)
            if dew_point and len(weather) < 120:
                weather += f" 💧{dew_point}°"
            
            # Add visibility if available and space allows
            visibility = self.extract_visibility(detailed_forecast)
            if visibility and len(weather) < 130:
                weather += f" 👁️{visibility}mi"
            
            # Add precipitation probability if available and space allows
            precip_prob = self.extract_precip_probability(detailed_forecast)
            if precip_prob and len(weather) < 140:
                weather += f" 🌦️{precip_prob}%"
            
            # Add wind gusts if available and space allows
            wind_gusts = self.extract_wind_gusts(detailed_forecast)
            if wind_gusts and len(weather) < 140:
                weather += f" 💨{wind_gusts}"
            
            # Add tomorrow with high/low if available
            if len(forecast) > 1:
                tomorrow = forecast[1]
                tomorrow_temp = tomorrow.get('temperature', '')
                tomorrow_short = tomorrow.get('shortForecast', '')
                tomorrow_detailed = tomorrow.get('detailedForecast', '')
                tomorrow_wind_speed = tomorrow.get('windSpeed', '')
                tomorrow_wind_direction = tomorrow.get('windDirection', '')
                
                if tomorrow_temp and tomorrow_short:
                    # Try to get high/low for tomorrow
                    tomorrow_high_low = self.extract_high_low(tomorrow_detailed)
                    
                    tomorrow_emoji = self.get_weather_emoji(tomorrow_short)
                    if tomorrow_high_low:
                        tomorrow_str = f" | Tmrw: {tomorrow_emoji}{tomorrow_short} {tomorrow_high_low}"
                    else:
                        tomorrow_str = f" | Tmrw: {tomorrow_emoji}{tomorrow_short} {tomorrow_temp}°"
                    
                    # Add tomorrow wind info if space allows
                    if tomorrow_wind_speed and tomorrow_wind_direction and len(weather + tomorrow_str) < 120:
                        import re
                        wind_match = re.search(r'(\d+)', tomorrow_wind_speed)
                        if wind_match:
                            wind_num = wind_match.group(1)
                            wind_dir = self.abbreviate_wind_direction(tomorrow_wind_direction)
                            if wind_dir:
                                wind_info = f" {wind_dir}{wind_num}"
                                if len(weather + tomorrow_str + wind_info) <= 130:
                                    tomorrow_str += wind_info
                    
                    # Only add if we have space
                    if len(weather + tomorrow_str) <= 130:  # Leave room for alerts
                        weather += tomorrow_str
            
            return weather, weather_json
            
        except Exception as e:
            self.logger.error(f"Error fetching NOAA weather: {e}")
            return self.ERROR_FETCHING_DATA, None
    
    def get_weather_alerts_noaa(self, lat: float, lon: float) -> tuple:
        """Get weather alerts from NOAA"""
        try:
            alert_url = f"https://api.weather.gov/alerts/active.atom?point={lat},{lon}"
            
            alert_data = requests.get(alert_url, timeout=self.url_timeout)
            if not alert_data.ok:
                self.logger.warning("Error fetching weather alerts from NOAA")
                return self.ERROR_FETCHING_DATA
            
            full_alert_titles = []  # Store original full titles
            abbreviated_alert_titles = []  # Store abbreviated titles for single message mode
            alertxml = xml.dom.minidom.parseString(alert_data.text)
            
            for i in alertxml.getElementsByTagName("entry"):
                title = i.getElementsByTagName("title")[0].childNodes[0].nodeValue
                full_alert_titles.append(title)
                
                # Abbreviate alert title for brevity (for single message mode)
                short_title = self.abbreviate_alert_title(title)
                abbreviated_alert_titles.append(short_title)
            
            if not full_alert_titles:
                return self.NO_ALERTS
            
            alert_num = len(full_alert_titles)
            
            # For multi-message, we need the full first alert title
            full_first_alert_text = full_alert_titles[0]
            
            # For single message, we need the abbreviated first alert title, further abbreviated by abbreviate_noaa
            abbreviated_first_alert_text = self.abbreviate_noaa(abbreviated_alert_titles[0])
            
            # Return both full and abbreviated versions, along with count
            return full_first_alert_text, abbreviated_first_alert_text, alert_num
            
        except Exception as e:
            self.logger.error(f"Error fetching NOAA weather alerts: {e}")
            return self.ERROR_FETCHING_DATA
    
    
    def abbreviate_alert_title(self, title: str) -> str:
        """Abbreviate alert title for brevity"""
        # Common alert type abbreviations
        replacements = {
            "warning": "Warn",
            "watch": "Watch", 
            "advisory": "Adv",
            "statement": "Stmt",
            "severe thunderstorm": "SvrT-Storm",
            "tornado": "Tornado",
            "flash flood": "FlashFlood",
            "flood": "Flood",
            "winter storm": "WinterStorm",
            "blizzard": "Blizzard",
            "ice storm": "IceStorm",
            "freeze": "Freeze",
            "frost": "Frost",
            "heat": "Heat",
            "excessive heat": "ExHeat",
            "extreme heat": "ExtHeat",
            "wind": "Wind",
            "high wind": "HighWind",
            "wind advisory": "WindAdv",
            "fire weather": "FireWx",
            "red flag": "RedFlag",
            "dense fog": "DenseFog",
            "issued": "iss",
            "until": "til",
            "effective": "eff",
            "expires": "exp",
            "dense smoke": "DenseSmoke",
            "air quality": "AirQuality",
            "coastal flood": "CoastalFlood",
            "lakeshore flood": "LakeshoreFlood",
            "rip current": "RipCurrent",
            "high surf": "HighSurf",
            "hurricane": "Hurricane",
            "tropical storm": "TropStorm",
            "tropical depression": "TropDep",
            "storm surge": "StormSurge",
            "tsunami": "Tsunami",
            "earthquake": "Earthquake",
            "volcano": "Volcano",
            "avalanche": "Avalanche",
            "landslide": "Landslide",
            "debris flow": "DebrisFlow",
            "dust storm": "DustStorm",
            "sandstorm": "Sandstorm",
            "blowing dust": "BlwDust",
            "blowing sand": "BlwSand"
        }
        
        result = title
        for key, value in replacements.items():
            # Case insensitive replace
            result = result.replace(key, value).replace(key.capitalize(), value).replace(key.upper(), value)
        
        # Limit to reasonable length
        if len(result) > 30:
            result = result[:27] + "..."
        
        return result

    def abbreviate_wind_direction(self, direction: str) -> str:
        """Abbreviate wind direction to emoji + 2-3 characters"""
        if not direction:
            return ""
        
        direction = direction.upper()
        replacements = {
            "NORTHWEST": "↖️NW",
            "NORTHEAST": "↗️NE",
            "SOUTHWEST": "↙️SW", 
            "SOUTHEAST": "↘️SE",
            "NORTH": "⬆️N",
            "EAST": "➡️E",
            "SOUTH": "⬇️S",
            "WEST": "⬅️W"
        }
        
        for full, abbrev in replacements.items():
            if full in direction:
                return abbrev
        
        # If no match, return first 2 characters with generic wind emoji
        return f"💨{direction[:2]}" if len(direction) >= 2 else f"💨{direction}"

    def extract_humidity(self, text: str) -> str:
        """Extract humidity percentage from forecast text"""
        if not text:
            return ""
        
        import re
        # Look for patterns like "humidity 45%" or "45% humidity"
        humidity_patterns = [
            r'humidity\s+(\d+)%',
            r'(\d+)%\s+humidity',
            r'relative humidity\s+(\d+)%',
            r'(\d+)%\s+relative humidity'
        ]
        
        for pattern in humidity_patterns:
            match = re.search(pattern, text.lower())
            if match:
                return match.group(1)
        
        return ""

    def extract_precip_chance(self, text: str) -> str:
        """Extract precipitation chance from forecast text"""
        if not text:
            return ""
        
        import re
        # Look for patterns like "20% chance" or "chance of rain 30%"
        precip_patterns = [
            r'(\d+)%\s+chance',
            r'chance\s+of\s+\w+\s+(\d+)%',
            r'(\d+)%\s+probability',
            r'probability\s+of\s+\w+\s+(\d+)%'
        ]
        
        for pattern in precip_patterns:
            match = re.search(pattern, text.lower())
            if match:
                return match.group(1)
        
        return ""

    def extract_high_low(self, text: str) -> str:
        """Extract high/low temperatures from forecast text"""
        if not text:
            return ""
        
        import re
        # Look for more specific patterns to avoid false matches
        high_low_patterns = [
            r'high\s+near\s+(\d+).*?low\s+around\s+(\d+)',
            r'high\s+(\d+).*?low\s+(\d+)',
            r'(\d+)\s+to\s+(\d+)\s+degrees',  # More specific
            r'temperature\s+(\d+)\s+to\s+(\d+)',
            r'high\s+near\s+(\d+).*?temperatures\s+falling\s+to\s+around\s+(\d+)',  # "High near 82, with temperatures falling to around 80"
            r'low\s+around\s+(\d+)',  # Just low temp
            r'high\s+near\s+(\d+)'   # Just high temp
        ]
        
        for pattern in high_low_patterns:
            match = re.search(pattern, text.lower())
            if match:
                if len(match.groups()) == 2:
                    high, low = match.groups()
                    # Validate that these are reasonable temperatures (20-120°F)
                    try:
                        high_val = int(high)
                        low_val = int(low)
                        if 20 <= high_val <= 120 and 20 <= low_val <= 120 and high_val > low_val:
                            return f"{high}°/{low}°"
                    except ValueError:
                        continue
                elif len(match.groups()) == 1:
                    # Single temperature - could be high or low
                    temp = match.group(1)
                    try:
                        temp_val = int(temp)
                        if 20 <= temp_val <= 120:
                            return f"{temp}°"
                    except ValueError:
                        continue
        
        return ""

    def extract_uv_index(self, text: str) -> str:
        """Extract UV index from forecast text"""
        if not text:
            return ""
        
        import re
        # Look for UV index patterns
        uv_patterns = [
            r'uv\s+index\s+(\d+)',
            r'uv\s+(\d+)',
            r'ultraviolet\s+index\s+(\d+)'
        ]
        
        for pattern in uv_patterns:
            match = re.search(pattern, text.lower())
            if match:
                uv_val = match.group(1)
                # Validate UV index (0-11+ is reasonable)
                try:
                    if 0 <= int(uv_val) <= 15:
                        return uv_val
                except ValueError:
                    continue
        
        return ""

    def extract_dew_point(self, text: str) -> str:
        """Extract dew point temperature from forecast text"""
        if not text:
            return ""
        
        import re
        # Look for dew point patterns
        dew_point_patterns = [
            r'dew point\s+(\d+)',
            r'dewpoint\s+(\d+)',
            r'dew\s+point\s+(\d+)°'
        ]
        
        for pattern in dew_point_patterns:
            match = re.search(pattern, text.lower())
            if match:
                dp_val = match.group(1)
                # Validate dew point (reasonable range -20 to 80°F)
                try:
                    if -20 <= int(dp_val) <= 80:
                        return dp_val
                except ValueError:
                    continue
        
        return ""

    def extract_visibility(self, text: str) -> str:
        """Extract visibility from forecast text"""
        if not text:
            return ""
        
        import re
        # Look for visibility patterns
        visibility_patterns = [
            r'visibility\s+(\d+)\s+miles',
            r'visibility\s+(\d+)\s+mi',
            r'(\d+)\s+mile\s+visibility',
            r'(\d+)\s+mi\s+visibility'
        ]
        
        for pattern in visibility_patterns:
            match = re.search(pattern, text.lower())
            if match:
                vis_val = match.group(1)
                # Validate visibility (reasonable range 0-20 miles)
                try:
                    if 0 <= int(vis_val) <= 20:
                        return vis_val
                except ValueError:
                    continue
        
        return ""

    def extract_precip_probability(self, text: str) -> str:
        """Extract precipitation probability from forecast text"""
        if not text:
            return ""
        
        import re
        # Look for precipitation probability patterns
        precip_prob_patterns = [
            r'(\d+)%\s+chance\s+of\s+(?:rain|precipitation|showers)',
            r'chance\s+of\s+(?:rain|precipitation|showers)\s+(\d+)%',
            r'(\d+)%\s+probability\s+of\s+(?:rain|precipitation|showers)',
            r'probability\s+of\s+(?:rain|precipitation|showers)\s+(\d+)%',
            r'(\d+)%\s+chance',
            r'chance\s+(\d+)%'
        ]
        
        for pattern in precip_prob_patterns:
            match = re.search(pattern, text.lower())
            if match:
                prob_val = match.group(1)
                # Validate probability (0-100%)
                try:
                    if 0 <= int(prob_val) <= 100:
                        return prob_val
                except ValueError:
                    continue
        
        return ""

    def extract_wind_gusts(self, text: str) -> str:
        """Extract wind gusts from forecast text"""
        if not text:
            return ""
        
        import re
        # Look for wind gust patterns
        gust_patterns = [
            r'gusts\s+to\s+(\d+)\s+mph',
            r'gusts\s+up\s+to\s+(\d+)\s+mph',
            r'wind\s+gusts\s+to\s+(\d+)\s+mph',
            r'wind\s+gusts\s+up\s+to\s+(\d+)\s+mph',
            r'gusts\s+(\d+)\s+mph',
            r'wind\s+gusts\s+(\d+)\s+mph'
        ]
        
        for pattern in gust_patterns:
            match = re.search(pattern, text.lower())
            if match:
                gust_val = match.group(1)
                # Validate wind gust (reasonable range 10-100 mph)
                try:
                    if 10 <= int(gust_val) <= 100:
                        return gust_val
                except ValueError:
                    continue
        
        return ""

    def get_current_conditions(self, points_data: dict) -> str:
        """Get additional current conditions data from NOAA using existing points data"""
        try:
            if not points_data:
                return ""
            
            weather_json = points_data
            station_url = weather_json['properties'].get('observationStations')
            if not station_url:
                return ""
            
            # Get the nearest station
            stations_data = requests.get(station_url, timeout=self.url_timeout)
            if not stations_data.ok:
                return ""
            
            stations_json = stations_data.json()
            if not stations_json.get('features'):
                return ""
            
            # Get current observations from the nearest station
            station_id = stations_json['features'][0]['properties']['stationIdentifier']
            obs_url = f"https://api.weather.gov/stations/{station_id}/observations/latest"
            
            obs_data = requests.get(obs_url, timeout=self.url_timeout)
            if not obs_data.ok:
                return ""
            
            obs_json = obs_data.json()
            if not obs_json.get('properties'):
                return ""
            
            props = obs_json['properties']
            conditions = []
            
            # Extract useful current conditions with emojis
            if props.get('relativeHumidity', {}).get('value'):
                humidity = int(props['relativeHumidity']['value'])
                conditions.append(f"{humidity}%RH")
            
            if props.get('dewpoint', {}).get('value'):
                dewpoint = int(props['dewpoint']['value'] * 9/5 + 32)  # Convert C to F
                conditions.append(f"💧{dewpoint}°")
            
            if props.get('visibility', {}).get('value'):
                visibility = int(props['visibility']['value'] * 0.000621371)  # Convert m to miles
                if visibility > 0:
                    conditions.append(f"👁️{visibility}mi")
            
            if props.get('windGust', {}).get('value'):
                wind_gust = int(props['windGust']['value'] * 2.237)  # Convert m/s to mph
                if wind_gust > 10:
                    conditions.append(f"💨{wind_gust}")
            
            if props.get('barometricPressure', {}).get('value'):
                pressure = int(props['barometricPressure']['value'] / 100)  # Convert Pa to hPa
                conditions.append(f"📊{pressure}hPa")
            
            return " ".join(conditions[:3])  # Limit to 3 conditions to avoid overflow
            
        except Exception as e:
            self.logger.debug(f"Error getting current conditions: {e}")
            return ""

    def get_weather_emoji(self, condition: str) -> str:
        """Get emoji for weather condition"""
        if not condition:
            return ""
        
        condition_lower = condition.lower()
        
        # Weather condition emojis
        if any(word in condition_lower for word in ['sunny', 'clear']):
            return "☀️"
        elif any(word in condition_lower for word in ['cloudy', 'overcast']):
            return "☁️"
        elif any(word in condition_lower for word in ['partly cloudy', 'mostly cloudy']):
            return "⛅"
        elif any(word in condition_lower for word in ['rain', 'showers']):
            return "🌦️"
        elif any(word in condition_lower for word in ['thunderstorm', 'thunderstorms']):
            return "⛈️"
        elif any(word in condition_lower for word in ['snow', 'snow showers']):
            return "❄️"
        elif any(word in condition_lower for word in ['fog', 'mist', 'haze']):
            return "🌫️"
        elif any(word in condition_lower for word in ['smoke']):
            return "💨"
        elif any(word in condition_lower for word in ['windy', 'breezy']):
            return "💨"
        else:
            return "🌤️"  # Default weather emoji

    def abbreviate_noaa(self, text: str) -> str:
        """Replace long strings with shorter ones for display"""
        replacements = {
            "monday": "Mon",
            "tuesday": "Tue", 
            "wednesday": "Wed",
            "thursday": "Thu",
            "friday": "Fri",
            "saturday": "Sat",
            "sunday": "Sun",
            "northwest": "NW",
            "northeast": "NE", 
            "southwest": "SW",
            "southeast": "SE",
            "north": "N",
            "south": "S",
            "east": "E",
            "west": "W",
            "precipitation": "precip",
            "showers": "shwrs",
            "thunderstorms": "t-storms",
            "thunderstorm": "t-storm",
            "quarters": "qtrs",
            "quarter": "qtr",
            "january": "Jan",
            "february": "Feb",
            "march": "Mar",
            "april": "Apr",
            "may": "May",
            "june": "Jun",
            "july": "Jul",
            "august": "Aug",
            "september": "Sep",
            "october": "Oct",
            "november": "Nov",
            "december": "Dec",
            "degrees": "°",
            "percent": "%",
            "department": "Dept.",
            "amounts less than a tenth of an inch possible.": "< 0.1in",
            "temperatures": "temps.",
            "temperature": "temp.",
        }
        
        line = text
        for key, value in replacements.items():
            # Case insensitive replace
            line = line.replace(key, value).replace(key.capitalize(), value).replace(key.upper(), value)
        
        return line
