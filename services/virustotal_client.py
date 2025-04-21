import base64
import logging
import time
import requests
from services.reputation_service import ReputationService

class VirusTotalClient(ReputationService):
    """
    VirusTotal API client for URL reputation checking.
    Implementation of the ReputationService interface.
    """
    
    def __init__(self, api_key):
        """
        Initialize the VirusTotal client.
        
        Args:
            api_key (str): VirusTotal API key
        """
        super().__init__(api_key)
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Content-Type": "application/json"
        }
        
        if not self.api_key:
            logging.warning("VirusTotal API key is not provided")
    
    def check_url(self, url):
        """
        Check a URL's reputation using VirusTotal API.
        
        Args:
            url (str): The URL to check
            
        Returns:
            dict: Reputation data for the URL
            
        Raises:
            Exception: If there's an error checking the URL
        """
        if not self.api_key:
            raise ValueError("VirusTotal API key is required")
        
        self.log_request(url)
        
        try:
            # Get URL identifier
            url_id = self._get_url_id(url)
            
            # Submit URL for analysis or get existing analysis
            analysis_id = self._submit_url(url_id)
            
            # Poll for analysis results
            response = self._poll_analysis(analysis_id)
            
            # Parse response
            results = self.parse_response(response)
            
            self.log_response(url, "Successfully received results")
            return results
            
        except Exception as e:
            error_message = str(e)
            logging.error(f"Error checking URL {url}: {error_message}")
            
            # Handle specific API errors
            if "WrongCredentialsError" in error_message or "401" in error_message:
                raise ValueError("The VirusTotal API key appears to be invalid. Please check your API key configuration.")
            elif "403" in error_message:
                raise ValueError("The VirusTotal API key doesn't have permission to access this resource.")
            elif "429" in error_message:
                raise ValueError("The VirusTotal API rate limit has been exceeded. Please try again later.")
            else:
                raise
    
    def _get_url_id(self, url):
        """
        Get VirusTotal URL identifier.
        
        Args:
            url (str): The URL to identify
            
        Returns:
            str: Base64 encoded URL identifier
        """
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    def _submit_url(self, url_id):
        """
        Submit a URL for scanning or retrieve existing analysis.
        
        Args:
            url_id (str): The URL identifier
            
        Returns:
            str: Analysis ID for polling results
            
        Raises:
            Exception: If submission fails
        """
        # First check if URL has already been analyzed recently
        url = f"{self.base_url}/urls/{url_id}"
        response = requests.get(url, headers=self.headers)
        
        # If URL not found, submit it for analysis
        if response.status_code == 404:
            logging.info(f"URL not found in VirusTotal, submitting for analysis")
            url = f"{self.base_url}/urls"
            data = {"url": url_id}
            response = requests.post(url, headers=self.headers, json=data)
            
            if response.status_code != 200:
                logging.error(f"Error submitting URL: {response.text}")
                raise Exception(f"Failed to submit URL for analysis: {response.status_code}")
            
            result = response.json()
            return result.get("data", {}).get("id")
        
        elif response.status_code == 200:
            logging.info(f"URL found in VirusTotal, retrieving latest analysis")
            result = response.json()
            
            # Get the most recent analysis ID
            analysis_id = result.get("data", {}).get("id")
            return analysis_id
        
        else:
            logging.error(f"Error checking URL: {response.text}")
            raise Exception(f"Failed to check URL: {response.status_code}")
    
    def _poll_analysis(self, analysis_id, max_attempts=3, wait_time=2):
        """
        Poll for analysis results with timeout.
        
        Args:
            analysis_id (str): The analysis ID to poll
            max_attempts (int): Maximum number of polling attempts
            wait_time (int): Seconds to wait between attempts
            
        Returns:
            dict: Analysis results
            
        Raises:
            Exception: If polling fails
        """
        url = f"{self.base_url}/analyses/{analysis_id}"
        result = None
        
        for attempt in range(max_attempts):
            logging.info(f"Polling analysis results, attempt {attempt + 1}/{max_attempts}")
            
            response = requests.get(url, headers=self.headers)
            
            if response.status_code != 200:
                logging.error(f"Error polling analysis: {response.text}")
                raise Exception(f"Failed to poll analysis: {response.status_code}")
            
            result = response.json()
            status = result.get("data", {}).get("attributes", {}).get("status")
            
            if status == "completed":
                logging.info(f"Analysis completed")
                return result
            
            logging.info(f"Analysis not completed, status: {status}, waiting {wait_time}s")
            time.sleep(wait_time)
        
        # If we got here, analysis didn't complete in time, but return what we have
        if result:
            logging.warning(f"Analysis timed out after {max_attempts} attempts")
            return result
        else:
            # This shouldn't happen but handle it just in case
            raise Exception(f"No result obtained after {max_attempts} polling attempts")
    
    def parse_response(self, response):
        """
        Parse VirusTotal API response into a standardized format.
        
        Args:
            response (dict): The raw API response
            
        Returns:
            dict: Standardized reputation data
        """
        try:
            attributes = response.get("data", {}).get("attributes", {})
            stats = attributes.get("stats", {})
            results = attributes.get("results", {})
            
            # Standardize the response
            standardized = {
                "stats": {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0)
                },
                "results": {},
                "meta": {
                    "last_analysis_date": attributes.get("date", 0),
                    "status": attributes.get("status", "unknown")
                }
            }
            
            # Extract individual engine results
            for engine_name, engine_result in results.items():
                category = engine_result.get("category", "undetected")
                standardized["results"][engine_name] = {
                    "category": category,
                    "result": engine_result.get("result", ""),
                    "method": engine_result.get("method", ""),
                    "engine_name": engine_name
                }
            
            return standardized
            
        except Exception as e:
            logging.error(f"Error parsing VirusTotal response: {str(e)}")
            # Return minimal data in case of parsing error
            return {
                "stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 0,
                    "undetected": 0
                },
                "results": {},
                "meta": {
                    "last_analysis_date": 0,
                    "status": "error",
                    "error": str(e)
                }
            }