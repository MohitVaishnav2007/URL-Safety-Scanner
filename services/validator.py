import re
import logging
import validators
from urllib.parse import urlparse, urlunsplit, urlsplit

class URLValidator:
    """
    Class responsible for validating and sanitizing URLs.
    Follows the Single Responsibility Principle (SRP) by focusing only on URL validation.
    """
    
    def __init__(self):
        """Initialize the URL validator."""
        # Common malicious patterns to check during validation
        self.malicious_patterns = [
            r'javascript:',
            r'data:',
            r'vbscript:',
            r'file:',
        ]
    
    def is_valid(self, url):
        """
        Check if a URL is valid.
        
        Args:
            url (str): The URL to validate
            
        Returns:
            bool: True if the URL is valid, False otherwise
        """
        if not url:
            logging.warning("Empty URL provided")
            return False
        
        # Check for malicious patterns
        for pattern in self.malicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                logging.warning(f"URL contains potentially malicious pattern: {pattern}")
                return False
        
        # Try to normalize the URL first
        try:
            normalized_url = self.normalize(url)
        except Exception as e:
            logging.warning(f"Error normalizing URL: {str(e)}")
            return False
        
        # Use validators library to check URL validity
        valid = validators.url(normalized_url)
        if not valid:
            logging.warning(f"URL failed validation: {normalized_url}")
            return False
        
        return True
    
    def normalize(self, url):
        """
        Normalize a URL by ensuring it has a scheme, removing fragments, etc.
        
        Args:
            url (str): The URL to normalize
            
        Returns:
            str: The normalized URL
        """
        url = url.strip()
        
        # Add scheme if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Parse the URL
        parsed = urlsplit(url)
        
        # Reconstruct without fragments
        normalized = urlunsplit((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.query,
            '' # Remove fragment
        ))
        
        return normalized
    
    def sanitize(self, url):
        """
        Sanitize a URL to prevent potential injection attacks.
        
        Args:
            url (str): The URL to sanitize
            
        Returns:
            str: The sanitized URL
        """
        # Start with normalization
        normalized = self.normalize(url)
        
        # Parse the URL
        parsed = urlparse(normalized)
        
        # Ensure netloc is lowercased
        netloc = parsed.netloc.lower()
        
        # Reconstruct with lowercased netloc
        sanitized = urlunsplit((
            parsed.scheme,
            netloc,
            parsed.path,
            parsed.query,
            ''
        ))
        
        return sanitized