import requests

from vt3exception import VT3Exception
from vt3base import VT3Base

class VT3Domains(VT3Base):
    """Class for the Domains endpoints"""

    def report(self, domain, timeout=None):
        """Retrieve information about an Internet domain.
        Args:
            domain(str): Domain name.
            timeout(float, optional): The amount of time per seconds, for the request to wait until the timeout expires.
        Returns:
            The response from the server as a json or byte sequence.
        Exceptions:
            RequestException: Response timeout from the server is exceeded or server connection error.
            VT3Exception: If the request failed.
        """
        pass

    def get_comments(self, domain, limit=10, cursor=None, timeout=None):
        """Retrieve comments for an Internet domain.
        Args:
            domain(str): Domain name.
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

    def add_commnets(self, domain, text, timeout=None):
        """Add a comment to an Internet domain.
        Args:
            domain(str): Domain name.
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
            'historical_whois', 'immediate_parent', 'parent', 'referrer_files', 'related_comments', 'resolutions',
            'siblings', 'subdomains', 'urls'
        ]
        if relationship not in relationships:
            return False
        return True

    def get_relationship(self, domain, relationship, limit=10, cursor=None, timeout=None):
        """Retrieve related objects to an Internet domain.
        Args:
            domain(str): Domain name.
            relationship(str): Relationship name (see table https://developers.virustotal.com/v3.0/reference#files).
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

    def get_votes(self, domain, limit=10, cursor=None, timeout=None):
        """Retrieve votes for an Internet domain.
        Args:
            domain(str): Domain name.
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

    def add_votes(self, domain, malicious=True, timeout=None):
        """Add a vote for a hostname or domain.
        Args:
            domain(str): Domain name.
            malicious(bool, optional): The verdict attribute: malicious(True), harmless(False).
            timeout(float, optional): The amount of time per seconds, for the request to wait until the timeout expires.
        
        Returns:
            The response from the server as a json or byte sequence.

        Exceptions:
            RequestException: Response timeout from the server is exceeded or server connection error.
            VT3Exception: If the request failed.
        """
        verdict = 'malicious' if malicious else 'harmless'
        votes = {"data": {"type": "vote", "attributes": {"verdict": verdict}}}
        pass

    def resolution(self, id, timeout=None):
        """Retrieve a resolution object.
                This endpoint retrieves a Resolution object by its ID. A resolution object ID is made by appending the IP 
                and the domain it resolves to together.
        Args:
            id(str): Resolution object ID.
            timeout(float, optional): The amount of time per seconds, for the request to wait until the timeout expires.
        
        Returns:
            The response from the server as a json or byte sequence.

        Exceptions:
            RequestException: Response timeout from the server is exceeded or server connection error.
            VT3Exception: If the request failed.
        """
        pass