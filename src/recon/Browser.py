import json
import hashlib
import logging
from datetime import datetime
import re
from typing import Dict, List, Any

class BrowserFingerprinter:
    """
    Class for comprehensive browser fingerprinting
    Can be used server-side to process client browser data or
    client-side to collect the fingerprinting information
    """
    
    def __init__(self, config: Dict[str, bool] = None, log_level=logging.INFO):
        """
        Initialize the fingerprinter with logging capabilities and configuration
        
        Args:
            config (Dict[str, bool], optional): Configuration to enable/disable specific fingerprinting techniques
            log_level: Logging level for the fingerprinter
        """
        self.logger = logging.getLogger('BrowserFingerprinter')
        logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.fingerprint_id = None
        self.fingerprint_data = {}
        
        # Default configuration
        self.config = {
            "collect_headers": True,
            "collect_cookies": True,
            "parse_user_agent": True,
            "collect_webgl": True,
            "collect_canvas": True,
            "collect_audio": True,
            "collect_webrtc": True,
            "collect_behavioral": False,
            "collect_performance": True,
            "use_cache": True
        }
        
        # Override with user config if provided
        if config:
            self.config.update(config)
        
        # Cache for fingerprints to improve performance
        self._cache = {}
    
    def collect_browser_info(self, headers: Dict[str, str], cookies: Dict[str, str], client_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Collect browser information from HTTP headers, cookies and client-provided data
        
        Args:
            headers (Dict[str, str]): HTTP headers from the request
            cookies (Dict[str, str]): Cookies from the request
            client_data (Dict[str, Any], optional): Additional client-side collected data like canvas, WebGL, etc.
        
        Returns:
            Dict[str, Any]: Complete fingerprint data
        """
        timestamp = datetime.now().isoformat()
        
        # Generate a cache key based on headers and cookies
        cache_key = hashlib.md5((json.dumps(headers, sort_keys=True) + json.dumps(cookies, sort_keys=True)).encode()).hexdigest()
        
        # Check cache if enabled
        if self.config["use_cache"] and cache_key in self._cache:
            self.logger.debug(f"Using cached fingerprint for {cache_key}")
            cached_fingerprint = self._cache[cache_key].copy()
            cached_fingerprint["timestamp"] = timestamp  # Update timestamp
            cached_fingerprint["cache_hit"] = True
            self.fingerprint_data = cached_fingerprint
            self.fingerprint_id = cached_fingerprint["fingerprint_id"]
            return cached_fingerprint
        
        # Start with basic browser info from headers
        fingerprint = {
            "timestamp": timestamp,
        }
        
        # Collect components based on configuration
        if self.config["collect_headers"]:
            fingerprint["headers"] = self._process_headers(headers)
        
        if self.config["collect_cookies"]:
            fingerprint["cookies"] = self._process_cookies(cookies)
        
        # Add client-side collected data if available
        if client_data:
            fingerprint.update(client_data)
        
        # Add performance metrics
        if self.config["collect_performance"]:
            fingerprint["performance"] = {
                "server_processing_time_ms": 0,  # Will be updated at the end
                "collection_start_time": timestamp
            }
        
        # Generate a unique fingerprint ID
        try:
            fingerprint_str = json.dumps(fingerprint, sort_keys=True)
            self.fingerprint_id = hashlib.sha256(fingerprint_str.encode()).hexdigest()
            fingerprint["fingerprint_id"] = self.fingerprint_id
        except TypeError as e:
            self.logger.error(f"Error generating fingerprint ID: {e}")
            # Fallback for non-serializable objects
            self.fingerprint_id = hashlib.sha256(str(fingerprint).encode()).hexdigest()
            fingerprint["fingerprint_id"] = self.fingerprint_id
        
        # Update performance metrics
        if self.config["collect_performance"]:
            end_time = datetime.now()
            start_time = datetime.fromisoformat(timestamp)
            processing_time = (end_time - start_time).total_seconds() * 1000
            fingerprint["performance"]["server_processing_time_ms"] = processing_time
            fingerprint["performance"]["collection_end_time"] = end_time.isoformat()
        
        # Store in cache
        if self.config["use_cache"]:
            self._cache[cache_key] = fingerprint.copy()
            
            # Limit cache size
            if len(self._cache) > 1000:
                # Remove oldest entries
                sorted_keys = sorted(self._cache.keys(), key=lambda k: self._cache[k]["timestamp"])
                for old_key in sorted_keys[:100]:
                    del self._cache[old_key]
        
        self.fingerprint_data = fingerprint
        return fingerprint
    
    def _process_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Extract and organize HTTP headers
        
        Args:
            headers (Dict[str, str]): HTTP request headers
            
        Returns:
            Dict[str, Any]: Processed header information
        """
        processed_headers = {}
        
        # Map important headers to look for
        important_headers = {
            "user-agent": "userAgent",
            "accept-language": "acceptLanguage",
            "accept-encoding": "acceptEncoding",
            "accept": "accept",
            "connection": "connection",
            "dnt": "doNotTrack",
            "upgrade-insecure-requests": "upgradeInsecureRequests",
            "referer": "referer",
            "origin": "origin",
            "cache-control": "cacheControl",
            "pragma": "pragma",
            "host": "host",
            "x-forwarded-for": "xForwardedFor",
            "x-requested-with": "xRequestedWith"
        }
        
        # Extract basic browser info from user agent
        user_agent = headers.get("user-agent", "")
        browser_info = self._parse_user_agent(user_agent) if self.config["parse_user_agent"] else {"raw": user_agent}
        
        # Process all headers
        for header_name, header_value in headers.items():
            header_key = header_name.lower()
            # Use mapped name if it's an important header
            if header_key in important_headers:
                processed_headers[important_headers[header_key]] = header_value
            # Include Sec-* headers for security features detection
            elif header_key.startswith("sec-"):
                processed_headers[header_key] = header_value
            # Include other potentially useful headers
            elif header_key in ["x-forwarded-for", "x-real-ip", "cf-connecting-ip", "x-requested-with"]:
                processed_headers[header_key] = header_value
        
        # Add extracted browser info
        processed_headers["browserInfo"] = browser_info
        
        return processed_headers
    
    def _process_cookies(self, cookies: Dict[str, str]) -> Dict[str, Any]:
        """
        Process and analyze cookies
        
        Args:
            cookies (Dict[str, str]): Request cookies
            
        Returns:
            Dict[str, Any]: Processed cookie information
        """
        cookie_data = {
            "count": len(cookies),
            "names": list(cookies.keys()),
            "has_tracking_cookies": False,
            "has_session_cookies": False,
        }
        
        # Look for common tracking and session cookies
        tracking_patterns = [
            r'_ga', r'_gid', r'_fbp', r'_pin_', r'_gcl_', r'_ym_', 
            r'analytics', r'track', r'visitor'
        ]
        
        session_patterns = [
            r'session', r'sessionid', r'sid', r'PHPSESSID', r'JSESSIONID'
        ]
        
        # Analyze cookie size
        total_size = 0
        largest_cookie = {"name": None, "size": 0}
        
        for cookie_name, cookie_value in cookies.items():
            # Calculate size
            cookie_size = len(cookie_name) + len(str(cookie_value))
            total_size += cookie_size
            
            if cookie_size > largest_cookie["size"]:
                largest_cookie = {"name": cookie_name, "size": cookie_size}
                
            # Check for tracking cookies
            if any(re.search(pattern, cookie_name, re.IGNORECASE) for pattern in tracking_patterns):
                cookie_data["has_tracking_cookies"] = True
                
            # Check for session cookies
            if any(re.search(pattern, cookie_name, re.IGNORECASE) for pattern in session_patterns):
                cookie_data["has_session_cookies"] = True
        
        # Add size information
        cookie_data["total_size_bytes"] = total_size
        cookie_data["largest_cookie"] = largest_cookie
        
        return cookie_data
    
    def _parse_user_agent(self, user_agent: str) -> Dict[str, Any]:
        """
        Extract browser and OS information from User-Agent string
        
        Args:
            user_agent (str): Browser User-Agent string
            
        Returns:
            Dict[str, Any]: Parsed user agent information
        """
        browser_info = {
            "raw": user_agent,
            "browser_name": "Unknown",
            "browser_version": "Unknown",
            "os_name": "Unknown",
            "os_version": "Unknown",
            "device_type": "Unknown",
            "is_mobile": False,
            "is_bot": False,
            "engine": "Unknown"
        }
        
        # Check for common browsers
        browser_patterns = [
            (r'MSIE|Trident.*rv', 'Internet Explorer', 'Trident'),
            (r'Edge|Edg/', 'Edge', 'EdgeHTML'),
            (r'Firefox', 'Firefox', 'Gecko'),
            (r'Chrome(?!.*Safari)', 'Chrome', 'Blink'),
            (r'Safari(?!.*Chrome)', 'Safari', 'WebKit'),
            (r'Opera|OPR', 'Opera', 'Blink'),
            (r'UCBrowser', 'UC Browser', 'WebKit'),
            (r'SamsungBrowser', 'Samsung Browser', 'Blink'),
            (r'YaBrowser', 'Yandex Browser', 'Blink'),
            (r'Brave', 'Brave', 'Blink')
        ]
        
        for pattern, name, engine in browser_patterns:
            if re.search(pattern, user_agent):
                browser_info["browser_name"] = name
                browser_info["engine"] = engine
                # Extract version
                version_match = None
                if name == 'Internet Explorer':
                    version_match = re.search(r'MSIE (\d+\.\d+)|rv:(\d+\.\d+)', user_agent)
                elif name == 'Edge':
                    version_match = re.search(r'Edge/(\d+\.\d+)|Edg/(\d+\.\d+)', user_agent)
                elif name == 'Chrome':
                    version_match = re.search(r'Chrome/(\d+\.\d+)', user_agent)
                elif name == 'Firefox':
                    version_match = re.search(r'Firefox/(\d+\.\d+)', user_agent)
                elif name == 'Safari':
                    version_match = re.search(r'Version/(\d+\.\d+)', user_agent)
                elif name == 'Opera':
                    version_match = re.search(r'OPR/(\d+\.\d+)', user_agent)
                elif name == 'Brave':
                    # Brave uses Chrome's UA but may include "Brave" string
                    version_match = re.search(r'Chrome/(\d+\.\d+)', user_agent)
                
                if version_match:
                    # Get first non-None group
                    version = next((g for g in version_match.groups() if g is not None), "Unknown")
                    browser_info["browser_version"] = version
                break
        
        # Check for OS
        if re.search(r'Windows', user_agent):
            browser_info["os_name"] = "Windows"
            win_version = re.search(r'Windows NT (\d+\.\d+)', user_agent)
            if win_version:
                nt_versions = {
                    '10.0': '10/11',
                    '6.3': '8.1',
                    '6.2': '8',
                    '6.1': '7',
                    '6.0': 'Vista',
                    '5.1': 'XP'
                }
                browser_info["os_version"] = nt_versions.get(win_version.group(1), win_version.group(1))
        elif re.search(r'Macintosh|Mac OS X', user_agent):
            browser_info["os_name"] = "macOS"
            mac_version = re.search(r'Mac OS X (\d+[._]\d+[._]?\d*)', user_agent)
            if mac_version:
                browser_info["os_version"] = mac_version.group(1).replace('_', '.')
        elif re.search(r'Android', user_agent):
            browser_info["os_name"] = "Android"
            browser_info["is_mobile"] = True
            android_version = re.search(r'Android (\d+\.\d+)', user_agent)
            if android_version:
                browser_info["os_version"] = android_version.group(1)
        elif re.search(r'iOS|iPhone|iPad|iPod', user_agent):
            browser_info["os_name"] = "iOS"
            browser_info["is_mobile"] = True
            ios_version = re.search(r'OS (\d+[._]\d+)', user_agent)
            if ios_version:
                browser_info["os_version"] = ios_version.group(1).replace('_', '.')
        elif re.search(r'Linux', user_agent):
            browser_info["os_name"] = "Linux"
            if re.search(r'Ubuntu', user_agent):
                browser_info["os_version"] = "Ubuntu"
        
        # Check for mobile devices
        if re.search(r'Mobile|Android|iPhone|iPad|iPod|Windows Phone', user_agent):
            browser_info["is_mobile"] = True
            
            if re.search(r'iPhone|iPod', user_agent):
                browser_info["device_type"] = "iPhone"
            elif re.search(r'iPad', user_agent):
                browser_info["device_type"] = "iPad"
            elif re.search(r'Android', user_agent):
                if re.search(r'Tablet|SM-T', user_agent):
                    browser_info["device_type"] = "Android Tablet"
                else:
                    browser_info["device_type"] = "Android Phone"
            elif re.search(r'Windows Phone', user_agent):
                browser_info["device_type"] = "Windows Phone"
        else:
            browser_info["device_type"] = "Desktop"
            
        # Check for bots
        bot_patterns = [
            r'bot', r'crawler', r'spider', r'slurp', r'search', 
            r'Googlebot', r'Bingbot', r'YandexBot', r'Baiduspider',
            r'facebookexternalhit', r'DuckDuckBot'
        ]
        
        if any(re.search(pattern, user_agent, re.IGNORECASE) for pattern in bot_patterns):
            browser_info["is_bot"] = True
            browser_info["device_type"] = "Bot"
            # Try to identify bot type
            for bot_pattern in bot_patterns:
                bot_match = re.search(bot_pattern, user_agent, re.IGNORECASE)
                if bot_match:
                    browser_info["bot_type"] = bot_match.group(0)
                    break
            
        return browser_info
    
    def compare_fingerprints(self, fingerprint1: Dict[str, Any], fingerprint2: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compare two fingerprints and determine similarity
        
        Args:
            fingerprint1 (Dict[str, Any]): First fingerprint
            fingerprint2 (Dict[str, Any]): Second fingerprint
            
        Returns:
            Dict[str, Any]: Comparison results with similarity scores
        """
        comparison = {
            "overall_similarity": 0.0,
            "component_similarity": {},
            "likely_same_user": False,
            "timestamp": datetime.now().isoformat()
        }
        
        # Components to compare with their weights
        components = {
            "headers.browserInfo.browser_name": 0.1,
            "headers.browserInfo.os_name": 0.1,
            "headers.browserInfo.os_version": 0.05,
            "headers.userAgent": 0.15,
            "headers.acceptLanguage": 0.05,
            "canvas.hash": 0.2,
            "webgl.renderHash": 0.2,
            "audio.hash": 0.1,
            "screen.width": 0.025,
            "screen.height": 0.025
        }
        
        total_weight = 0
        total_similarity = 0
        
        for path, weight in components.items():
            # Extract values using path
            parts = path.split('.')
            try:
                value1 = fingerprint1
                value2 = fingerprint2
                for part in parts:
                    value1 = value1.get(part)
                    value2 = value2.get(part)
                    if value1 is None or value2 is None:
                        break
                
                if value1 is not None and value2 is not None:
                    # Calculate similarity based on type
                    if isinstance(value1, (str, int, float, bool)):
                        similarity = 1.0 if value1 == value2 else 0.0
                    else:
                        # For complex types, fall back to string comparison
                        similarity = 1.0 if str(value1) == str(value2) else 0.0
                    
                    comparison["component_similarity"][path] = similarity
                    total_similarity += similarity * weight
                    total_weight += weight
            except (AttributeError, TypeError, KeyError):
                # Skip if component not found
                continue
        
        # Calculate overall similarity
        if total_weight > 0:
            comparison["overall_similarity"] = total_similarity / total_weight
        
        # Determine if likely same user (threshold can be adjusted)
        comparison["likely_same_user"] = comparison["overall_similarity"] > 0.85
        
        return comparison

    def detect_browser_anomalies(self, fingerprint_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect potential anomalies or inconsistencies in browser fingerprint
        that might indicate spoofing or privacy tools
        
        Args:
            fingerprint_data (Dict[str, Any]): Fingerprint to analyze
            
        Returns:
            Dict[str, Any]: Detected anomalies
        """
        anomalies = {
            "detected": False,
            "inconsistencies": [],
            "spoofing_score": 0.0,
            "analysis": {}
        }
        
        # Check user agent inconsistencies
        try:
            headers = fingerprint_data.get("headers", {})
            browser_info = headers.get("browserInfo", {})
            client_data = fingerprint_data.get("navigator", {})
            
            # User-Agent OS vs JavaScript platform mismatch
            if "platform" in client_data and browser_info.get("os_name") != "Unknown":
                platform = client_data["platform"].lower()
                os_name = browser_info["os_name"].lower()
                
                if "win" in platform and "windows" not in os_name:
                    anomalies["inconsistencies"].append("User-Agent OS and JavaScript platform mismatch")
                elif "mac" in platform and "mac" not in os_name:
                    anomalies["inconsistencies"].append("User-Agent OS and JavaScript platform mismatch")
                elif "linux" in platform and "linux" not in os_name and "android" not in os_name:
                    anomalies["inconsistencies"].append("User-Agent OS and JavaScript platform mismatch")
            
            # Screen resolution inconsistencies
            if "screen" in fingerprint_data and "window" in fingerprint_data:
                screen = fingerprint_data["screen"]
                window = fingerprint_data["window"]
                
                if (screen.get("width") < window.get("outerWidth", 0) or 
                    screen.get("height") < window.get("outerHeight", 0)):
                    anomalies["inconsistencies"].append("Window size larger than screen size")
            
            # WebGL inconsistencies
            if "webgl" in fingerprint_data and browser_info.get("browser_name") != "Unknown":
                webgl = fingerprint_data["webgl"]
                if webgl.get("vendor") and webgl.get("renderer"):
                    # Check for virtual machines or emulators
                    suspicious_renderers = ["VMware", "VirtualBox", "llvmpipe", "SwiftShader"]
                    if any(r in webgl["renderer"] for r in suspicious_renderers):
                        anomalies["inconsistencies"].append("WebGL renderer indicates virtualization")
                    
                    # Check for mismatches between OS and GPU vendor
                    if "Apple" in webgl["vendor"] and browser_info.get("os_name") != "macOS":
                        anomalies["inconsistencies"].append("Apple GPU reported on non-macOS system")
                        
            # Browser feature inconsistencies
            if "features" in fingerprint_data and browser_info.get("browser_name") != "Unknown":
                features = fingerprint_data["features"]
                browser_name = browser_info["browser_name"]
                
                # Chrome-specific features in non-Chrome browsers
                if browser_name not in ["Chrome", "Edge"] and features.get("chrome") is True:
                    anomalies["inconsistencies"].append("Chrome object available in non-Chrome browser")
            
            # Calculate spoofing score based on number of inconsistencies
            anomalies["spoofing_score"] = min(1.0, len(anomalies["inconsistencies"]) * 0.2)
            anomalies["detected"] = anomalies["spoofing_score"] > 0.1
                
        except Exception as e:
            self.logger.error(f"Error during anomaly detection: {e}")
            anomalies["error"] = str(e)
        
        return anomalies
    
    def generate_client_side_collector_js(self, include_components: List[str] = None) -> str:
        """
        Generate JavaScript code that collects browser fingerprinting data from the client
        This can be sent to the client and the results sent back to the server
        
        Args:
            include_components (List[str], optional): List of specific components to include
                                                      (e.g. ['canvas', 'webgl', 'audio'])
        
        Returns:
            str: JavaScript code for fingerprint collection
        """
        # Default components to include
        if include_components is None:
            include_components = [
                'screen', 'navigator', 'window', 'timezone', 'storage',
                'plugins', 'canvas', 'webgl', 'audio', 'mediaDevices',
                'touch', 'battery', 'network', 'webrtc', 'features', 'performance'
            ]
            
        # Convert to set for O(1) lookups
        components_set = set(include_components)
        
        js_code = """
        /**
         * Browser Fingerprinting Collection Script
         * Collects various browser attributes for identification purposes
         */
        const BrowserFingerprinter = {
            /**
             * Main collection method - gathers all fingerprinting data
             * @returns {Promise<Object>} The complete fingerprint data
             */
            collectFingerprint: async function() {
                const startTime = performance.now();
                const fingerprint = {
                    timestamp: new Date().toISOString()
                };
        """
        
        # Add screen component
        if 'screen' in components_set:
            js_code += """
                // Screen information
                fingerprint.screen = {
                    width: window.screen.width,
                    height: window.screen.height,
                    availWidth: window.screen.availWidth,
                    availHeight: window.screen.availHeight,
                    colorDepth: window.screen.colorDepth,
                    pixelDepth: window.screen.pixelDepth,
                    orientation: window.screen.orientation ? window.screen.orientation.type : 'unknown'
                };
            """
        
        # Add navigator component
        if 'navigator' in components_set:
            js_code += """
                // Navigator information
                fingerprint.navigator = {
                    language: navigator.language,
                    languages: Array.from(navigator.languages || []),
                    userAgent: navigator.userAgent,
                    platform: navigator.platform,
                    vendor: navigator.vendor,
                    doNotTrack: navigator.doNotTrack,
                    cookieEnabled: navigator.cookieEnabled,
                    maxTouchPoints: navigator.maxTouchPoints || 0,
                    hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
                    deviceMemory: navigator.deviceMemory || 'unknown',
                    cpuClass: navigator.cpuClass || 'unknown',
                    pdfViewerEnabled: navigator.pdfViewerEnabled || false,
                    webdriver: navigator.webdriver || false
                };
            """
        
        # Add window component
        if 'window' in components_set:
            js_code += """
                // Window information
                fingerprint.window = {
                    innerHeight: window.innerHeight,
                    innerWidth: window.innerWidth,
                    outerHeight: window.outerHeight,
                    outerWidth: window.outerWidth,
                    devicePixelRatio: window.devicePixelRatio,
                    screenX: window.screenX,
                    screenY: window.screenY,
                    pageXOffset: window.pageXOffset,
                    pageYOffset: window.pageYOffset
                };
            """
        
        # Add timezone component
        if 'timezone' in components_set:
            js_code += """
                // Timezone information
                fingerprint.timezone = {
                    offset: new Date().getTimezoneOffset(),
                    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                    dst: this._isDaylightSavingTime()
                };
            """
        
        # Add storage component
        if 'storage' in components_set:
            js_code += """
                // Storage capabilities
                fingerprint.storage = {
                    localStorage: this._isLocalStorageEnabled(),
                    sessionStorage: this._isSessionStorageEnabled(),
                    indexedDB: 'indexedDB' in window,
                    cookiesEnabled: navigator.cookieEnabled
                };
            """
        
        # Add plugins component
        if 'plugins' in components_set:
            js_code += """
                // Browser plugins
                fingerprint.plugins = this._getPlugins();
            """
        
        # Add canvas component
        if 'canvas' in components_set:
            js_code += """
                // Canvas fingerprinting
                fingerprint.canvas = await this._getCanvasFingerprint();
            """
        
        # Add WebGL component
        if 'webgl' in components_set:
            js_code += """
                // WebGL information
                fingerprint.webgl = await this._getWebGLInfo();
            """
        
        # Add audio component
        if 'audio' in components_set:
            js_code += """
                // Audio fingerprinting
                fingerprint.audio = await this._getAudioFingerprint();
            """
        
        # Add media devices component
        if 'mediaDevices' in components_set:
            js_code += """
                // Media devices information
                try {
                    fingerprint.mediaDevices = await this._getMediaDevices();
                } catch (e) {
                    fingerprint.mediaDevices = { error: e.toString(), supported: false };
                }
            """
        
        # Add touch component
        if 'touch' in components_set:
            js_code += """
                // Touch capabilities
                fingerprint.touch = this._getTouchCapabilities();
            """
        
        # Add battery component
        if 'battery' in components_set:
            js_code += """
                // Battery information
                try {
                    fingerprint.battery = await this._getBatteryInfo();
                } catch (e) {
                    fingerprint.battery = { error: e.toString(), supported: false };
                }
            """
        
        # Add network component
        if 'network' in components_set:
            js_code += """
                // Network information
                fingerprint.network = this._getNetworkInfo();
            """
        
        # Add WebRTC component
        if 'webrtc' in components_set:
            js_code += """
                // WebRTC fingerprinting
                try {
                    fingerprint.webrtc = await this._getWebRTCFingerprint();
                } catch (e) {
                    fingerprint.webrtc = { error: e.toString(), supported: false };
                }
            """
        
        # Add features detection component
        if 'features' in components_set:
            js_code += """
                // Browser features detection
                fingerprint.features = this._detectFeatureSupport();
            """
        
        # Add performance metrics
        if 'performance' in components_set:
            js_code += """
                // Performance metrics
                const endTime = performance.now();
                fingerprint.performance = {
                    collectionTime: endTime - startTime,
                    timing: performance.timing ? {
                        navigationStart: performance.timing.navigationStart,
                        loadEventEnd: performance.timing.loadEventEnd,
                        domComplete: performance.timing.domComplete,
                        connectEnd: performance.timing.connectEnd,
                        responseEnd: performance.timing.responseEnd
                    } : 'Not supported'
                };
            """
        
        # Add behavioral biometrics if requested
        if 'behavioral' in components_set:
            js_code += """
                // Behavioral biometrics
                fingerprint.behavioral = this._behavioralData;
                
                // Start collecting behavioral data for future fingerprints
                if (!this._behavioralCollectionStarted) {
                    this._startBehavioralCollection();
                }
            """
        
        # Complete the main collection function
        js_code += """
            _behavioralCollectionStarted: false,

            _startBehavioralCollection: function() {
                // Mouse movement tracking
                document.addEventListener('mousemove', (e) => {
                    this._behavioralData.mouseMovements.push({
                        x: e.clientX,
                        y: e.clientY,
                        t: performance.now()
                    });
                });

                // Keystroke dynamics
                document.addEventListener('keydown', (e) => {
                    this._behavioralData.keyPressTimings.push({
                        key: e.key,
                        code: e.code,
                        t: performance.now()
                    });
                });

                // Scroll patterns
                let lastScroll = 0;
                window.addEventListener('scroll', (e) => {
                    const now = performance.now();
                    this._behavioralData.scrollPatterns.push({
                        x: window.scrollX,
                        y: window.scrollY,
                        delta: now - lastScroll
                    });
                    lastScroll = now;
                });

                this._behavioralCollectionStarted = true;
            },

            // Helper Functions
            _isDaylightSavingTime: function() {
                const jan = new Date(new Date().getFullYear(), 0, 1);
                const jul = new Date(new Date().getFullYear(), 6, 1);
                return Math.max(jan.getTimezoneOffset(), jul.getTimezoneOffset()) > 
                       new Date().getTimezoneOffset();
            },

            _isLocalStorageEnabled: function() {
                try {
                    localStorage.setItem('test', 'test');
                    localStorage.removeItem('test');
                    return true;
                } catch (e) {
                    return false;
                }
            },

            _isSessionStorageEnabled: function() {
                try {
                    sessionStorage.setItem('test', 'test');
                    sessionStorage.removeItem('test');
                    return true;
                } catch (e) {
                    return false;
                }
            },

            _getPlugins: function() {
                const plugins = [];
                if (navigator.plugins) {
                    for (let i = 0; i < navigator.plugins.length; i++) {
                        const plugin = navigator.plugins[i];
                        const pluginInfo = {
                            name: plugin.name,
                            description: plugin.description,
                            filename: plugin.filename,
                            mimeTypes: []
                        };
                        
                        for (let j = 0; j < plugin.length; j++) {
                            const mimeType = plugin[j];
                            pluginInfo.mimeTypes.push({
                                type: mimeType.type,
                                description: mimeType.description,
                                suffixes: mimeType.suffixes
                            });
                        }
                        
                        plugins.push(pluginInfo);
                    }
                }
                return plugins;
            },

            _getCanvasFingerprint: async function() {
                try {
                    const canvas = document.createElement('canvas');
                    const ctx = canvas.getContext('2d');
                    canvas.width = 240;
                    canvas.height = 60;
                    
                    // Draw operations
                    ctx.fillStyle = 'rgb(255,255,255)';
                    ctx.fillRect(0, 0, canvas.width, canvas.height);
                    ctx.font = '16px Arial';
                    ctx.fillStyle = '#069';
                    ctx.fillText('Browser Fingerprint', 10, 30);
                    ctx.strokeStyle = 'rgb(120,186,176)';
                    ctx.beginPath();
                    ctx.arc(50, 50, 20, 0, Math.PI * 2);
                    ctx.stroke();
                    
                    return {
                        dataURL: canvas.toDataURL(),
                        winding: ctx.isPointInPath(50, 50),
                        hash: await this._hashString(canvas.toDataURL())
                    };
                } catch (e) {
                    return { error: e.toString() };
                }
            },

            _getWebGLInfo: async function() {
                try {
                    const canvas = document.createElement('canvas');
                    const gl = canvas.getContext('webgl') || 
                              canvas.getContext('experimental-webgl');
                    if (!gl) return { supported: false };

                    const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                    return {
                        renderer: debugInfo ? 
                            gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'protected',
                        vendor: debugInfo ? 
                            gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : 'protected',
                        version: gl.getParameter(gl.VERSION),
                        shadingLanguage: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
                        hash: await this._hashString(gl.getParameter(gl.VERSION))
                    };
                } catch (e) {
                    return { error: e.toString() };
                }
            },

            _getAudioFingerprint: async function() {
                try {
                    const audioContext = new (window.AudioContext || 
                                            window.webkitAudioContext)();
                    const analyser = audioContext.createAnalyser();
                    const oscillator = audioContext.createOscillator();
                    
                    analyser.fftSize = 1024;
                    oscillator.type = 'sine';
                    oscillator.frequency.setValueAtTime(10000, audioContext.currentTime);
                    
                    oscillator.connect(analyser);
                    analyser.connect(audioContext.destination);
                    
                    const dataArray = new Uint8Array(analyser.frequencyBinCount);
                    oscillator.start();
                    analyser.getByteFrequencyData(dataArray);
                    oscillator.stop(audioContext.currentTime + 0.1);
                    
                    return {
                        hash: await this._hashString(dataArray.join(',')),
                        sampleRate: audioContext.sampleRate
                    };
                } catch (e) {
                    return { error: e.toString() };
                }
            },

            _getMediaDevices: async function() {
                try {
                    const devices = await navigator.mediaDevices.enumerateDevices();
                    return devices.map(d => ({
                        kind: d.kind,
                        groupId: d.groupId,
                        deviceId: d.deviceId
                    }));
                } catch (e) {
                    return { error: e.toString() };
                }
            },

            _getTouchCapabilities: function() {
                return {
                    maxTouchPoints: navigator.maxTouchPoints || 0,
                    touchEvent: 'ontouchstart' in window,
                    hasCoarsePointer: matchMedia('(pointer: coarse)').matches
                };
            },

            _getBatteryInfo: async function() {
                if (navigator.getBattery) {
                    try {
                        const battery = await navigator.getBattery();
                        return {
                            level: battery.level,
                            charging: battery.charging,
                            chargingTime: battery.chargingTime
                        };
                    } catch (e) {
                        return { error: e.toString() };
                    }
                }
                return { supported: false };
            },

            _getNetworkInfo: function() {
                return navigator.connection ? {
                    type: navigator.connection.type,
                    effectiveType: navigator.connection.effectiveType,
                    rtt: navigator.connection.rtt
                } : { supported: false };
            },

            _getWebRTCFingerprint: async function() {
                try {
                    const pc = new RTCPeerConnection();
                    const ips = [];
                    
                    pc.onicecandidate = e => {
                        if (!e.candidate) return;
                        const ip = e.candidate.candidate.match(/([0-9]{1,3}\.){3}[0-9]{1,3}/);
                        if (ip) ips.push(ip[0]);
                    };

                    pc.createDataChannel('');
                    const offer = await pc.createOffer();
                    await pc.setLocalDescription(offer);
                    
                    return new Promise(resolve => {
                        setTimeout(() => {
                            pc.close();
                            resolve({ ips: [...new Set(ips)] });
                        }, 1000);
                    });
                } catch (e) {
                    return { error: e.toString() };
                }
            },

            _detectFeatureSupport: function() {
                return {
                    serviceWorker: 'serviceWorker' in navigator,
                    webAssembly: 'WebAssembly' in window,
                    webGL: !!window.WebGLRenderingContext,
                    webAudio: !!window.AudioContext,
                    webShare: 'share' in navigator
                };
            },

            _hashString: async function(str) {
                const encoder = new TextEncoder();
                const data = encoder.encode(str);
                const hashBuffer = await crypto.subtle.digest('SHA-256', data);
                const hashArray = Array.from(new Uint8Array(hashBuffer));
                return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            },

            _hashObject: async function(obj) {
                const str = JSON.stringify(obj);
                return this._hashString(str);
            }
        };

        // Initialize and expose the collector
        if (typeof window !== 'undefined') {
            window.BrowserFingerprinter = BrowserFingerprinter;
        }

        return BrowserFingerprinter;
        """ + "\n});"

        return js_code