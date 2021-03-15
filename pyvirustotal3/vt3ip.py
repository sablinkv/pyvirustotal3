import requests

from vt3exception import VT3Exception
from vt3base import VT3Request

class VT3IPAddresses(VT3Request):
    """Class for the IP Addresses endpoints."""

    def report(self, ip, timeout=None):
        """Retrieve information about an IP address.
        Args:
            ip(str): IP address.
            timeout(float, optional): The amount of time per seconds, for the request to wait until the timeout expires.
        
        Returns:
            The response from the server as a json or byte sequence.
        
        Exceptions:
            RequestException: Response timeout from the server is exceeded or server connection error.
            VT3Exception: If the request failed.
        """
        pass

    def get_comments(self, ip, limit=10, cursor=None, timeout=None):
        """Retrieve comments for an IP address.
        Args:
            ip(str): IP address.
            limit(int, optional): Maximum number of comments to retrieve(default limit = 10).
            cursor(str, optional): Continuation cursor.
            timeout(float, optional): The amount of time per seconds, for the request to wait until the timeout expires.
        
        Returns:
            The response from the server as a json or byte sequence.
        
        Exceptions:
            RequestException: Response timeout from the server is exceeded or server connection error.
            VT3Exception: If the request failed.
        """
        pass

    def add_comments(self, ip, text, timeout=None):
        """Add a comment to an IP address.
        Args:
            ip(str): IP address.
            text(str): The text of the comment.
            timeout(float, optional): The amount of time per seconds, for the request to wait until the timeout expires.
        
        Returns:
            The response from the server as a json or byte sequence.

        Exceptions:
            RequestException: Response timeout from the server is exceeded or server connection error.
            VT3Exception: If the request failed.
        """
        pass

    @staticmethod
    def is_valid_relationship(relationship):
        """Check relationship name."""
        relationships = [
            'comments', 'communicating_files', 'downloaded_files', 'graphs', 'historical_ssl_certificates',
            'historical_whois', 'related_comments', 'referrer_files', 'resolutions', 'urls'
        ]
        if relationship not in relationships:
            return False
        return True

    def get_relationship(self, ip, relationship, limit=10, cursor=None, timeout=None):
        """Retrieve objects related to an IP address.
        Args:
            ip(str): IP address.
            relationship(str): Relationship name (see table https://developers.virustotal.com/v3.0/reference#ip-object).
            limit(int, optional): Maximum number of comments to retrieve(default limit = 10).
            cursor(str, optional): Continuation cursor.
            timeout(float, optional): The amount of time per seconds, for the request to wait until the timeout expires.
        
        Returns:
            The response from the server as a json or byte sequence.

        Exceptions:
            ValueError: Invalid relationships value.
            RequestException: Response timeout from the server is exceeded or server connection error.
            VT3Exception: If the request failed.
        """
        pass

    def get_votes(self, ip, limit=10, cursor=None, timeout=None):
        """Retrieve votes for an IP address.
        Args:
            ip(str): IP address.
            limit(int, optional): Maximum number of comments to retrieve(default limit = 10).
            cursor(str, optional): Continuation cursor.
            timeout(float, optional): The amount of time per seconds, for the request to wait until the timeout expires.
        
        Returns:
            The response from the server as a json or byte sequence.
        
        Exceptions:
            RequestException: Response timeout from the server is exceeded or server connection error.
            VT3Exception: If the request failed.
        """
        pass

    def add_votes(self, id, malicious=True, timeout=None):
        """Add a vote for a IP address.
        Args:
            ip(str): IP address.
            malicious(bool, optional): The verdict attribute: malicious(True), harmless(False).
            timeout(float, optional): The amount of time per seconds, for the request to wait until the timeout expires.
        
        Returns:
            The response from the server as a json or byte sequence.

        Exceptions:
            RequestException: Response timeout from the server is exceeded or server connection error.
            VT3Exception: If the request failed.
        """
        pass