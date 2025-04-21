import logging
from abc import ABC, abstractmethod

class ReputationService(ABC):
    """
    Abstract base class that defines the interface for reputation checking services.
    Follows the Interface Segregation Principle (ISP) by defining only essential methods.
    """
    
    def __init__(self, api_key=None):
        """
        Initialize the reputation service.
        
        Args:
            api_key (str, optional): API key for the service
        """
        self.api_key = api_key
        
    @abstractmethod
    def check_url(self, url):
        """
        Check the reputation of a URL.
        
        Args:
            url (str): The URL to check
            
        Returns:
            dict: The reputation data
            
        Raises:
            NotImplementedError: If the method is not implemented by a subclass
        """
        raise NotImplementedError("Subclasses must implement check_url")
    
    @abstractmethod
    def parse_response(self, response):
        """
        Parse the response from the reputation service.
        
        Args:
            response: The response from the service
            
        Returns:
            dict: The parsed reputation data
            
        Raises:
            NotImplementedError: If the method is not implemented by a subclass
        """
        raise NotImplementedError("Subclasses must implement parse_response")
    
    def log_request(self, url):
        """
        Log a request to check a URL.
        
        Args:
            url (str): The URL being checked
        """
        logging.info(f"Requesting reputation check for URL: {url}")
    
    def log_response(self, url, response):
        """
        Log a response from the reputation service.
        
        Args:
            url (str): The URL that was checked
            response: The response from the service
        """
        logging.info(f"Received reputation response for URL: {url}")