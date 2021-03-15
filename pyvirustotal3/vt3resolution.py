from vt3base import VT3Request

class VT3Resolution(VT3Request):
    """Class for the Resolution endpoints"""
    def get_object(self, id, timeout=None):
        """Retrieve a resolution object.
        Args:
            id(str): Resolution object ID. A resolution object ID is made by appending the IP and the domain it resolves to together.
            timeout(float, optional): The amount of time per seconds, for the request to wait until the timeout expires.
        
        Returns:
            The response from the server as a json or byte sequence.

        Exceptions:
            RequestException: Response timeout from the server is exceeded or server connection error.
            VT3Exception: If the request failed.
        """
        return self._get(f'resolutions/{id}', timeout=timeout)