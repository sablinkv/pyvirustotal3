import requests

from ipaddress import ip_address, IPv4Address as IPv4
from vt3exception import VT3Exception
from vt3base import VT3Request

class VT3IPAddresses(VT3Request):
    """Class for the IP Addresses endpoints."""

    @staticmethod
    def is_valid_IPv4(ip):
        try:
            return type(ip_address(ip)) is IPv4
        except ValueError:
            return False
    

    def report(self, ip, timeout=None):
        """Retrieve information about an IP address.
        Args:
            ip(str): IP address.
            timeout(float, optional): The amount of time per seconds, for the request to wait until the timeout expires.
        
        Returns:
            The response from the server as a json or byte sequence.
        
        Exceptions:
            ValueError: Invalid IPv4.
            RequestException: Response timeout from the server is exceeded or server connection error.
            VT3Exception: If the request failed.
        """
        if not self.is_valid_IPv4(ip):
            raise ValueError('Invalid IPv4')
        
        return self._get(f'/ip_addresses/{ip}', timeout=timeout)

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
            ValueError: Invalid IPv4.
            RequestException: Response timeout from the server is exceeded or server connection error.
            VT3Exception: If the request failed.
        """
        if not self.is_valid_IPv4(ip):
            raise ValueError('Invalid IPv4')
        
        return self._get(f'/ip_addresses/{ip}/comments', limit=str(limit), cursor=cursor, timeout=timeout)

    def add_comments(self, ip, text, timeout=None):
        """Add a comment to an IP address.
        Args:
            ip(str): IP address.
            text(str): The text of the comment.
            timeout(float, optional): The amount of time per seconds, for the request to wait until the timeout expires.
        
        Returns:
            The response from the server as a json or byte sequence.

        Exceptions:
            ValueError: Invalid IPv4.
            RequestException: Response timeout from the server is exceeded or server connection error.
            VT3Exception: If the request failed.
        """
        if not self.is_valid_IPv4(ip):
            raise ValueError('Invalid IPv4')
        
        comment = {"data": {"type": "comment", "attributes": {"text": text}}}
        return self._post(f'/ip_addresses/{ip}/comments', json=comment, timeout=timeout)

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
            ValueError: Invalid IPv4 or relationships value.
            RequestException: Response timeout from the server is exceeded or server connection error.
            VT3Exception: If the request failed.
        """
        if not self.is_valid_IPv4(ip):
            raise ValueError('Invalid IPv4')
        
        relship = relationship.lower()
        if not self.is_valid_relationship(relship):
            raise ValueError('Invalid relationships value')

        return self._get(f'/ip_addresses/{ip}/{relship}', limit=str(limit), cursor=cursor, timeout=timeout)

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
            ValueError: Invalid IPv4.
            RequestException: Response timeout from the server is exceeded or server connection error.
            VT3Exception: If the request failed.
        """
        if not self.is_valid_IPv4(ip):
            raise ValueError('Invalid IPv4')

        return self._get(f'/ip_addresses/{ip}/votes', limit=str(limit), cursor=cursor, timeout=timeout)

    def add_votes(self, ip, malicious=True, timeout=None):
        """Add a vote for a IP address.
        Args:
            ip(str): IP address.
            malicious(bool, optional): The verdict attribute: malicious(True), harmless(False).
            timeout(float, optional): The amount of time per seconds, for the request to wait until the timeout expires.
        
        Returns:
            The response from the server as a json or byte sequence.

        Exceptions:
            ValueError: Invalid IPv4.
            RequestException: Response timeout from the server is exceeded or server connection error.
            VT3Exception: If the request failed.
        """
        if not self.is_valid_IPv4(ip):
            raise ValueError('Invalid IPv4')

        verdict = 'malicious' if malicious else 'harmless'
        votes = {"data": {"type": "vote", "attributes": {"verdict": verdict}}}
        return self._post(f'/ip_addresses/{ip}/votes', json=votes, timeout=timeout)