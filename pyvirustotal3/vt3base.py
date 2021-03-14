import requests
from vt3exception import VT3Exception

class VT3Base():
    def __init__(self, access_key, proxies=None, json_format=True):
        """
        Args:
            proxies(dict, optional): Dictionary containing proxies.
            json_format(bool, optional): Output format : 
                                        - JSON(True);
                                        - Byte sequence(False).

        Exceptions:
            Exception: Invalid API key.
        """
        self.headers = {'x-apikey' : access_key}
        self.proxies = proxies
        self.version = 3
        self.url = 'https://www.virustotal.com/api/v3'
        self.json_format = json_format

        if access_key is None:
            raise Exception('Invalid API key')

    @staticmethod
    def _check_status_code(response):
        """Check status code request.
        Args:
            response(requests.Response): Request response.

        Exception:
            VT3Exception: If the request fails, this exception is thrown, which contains an error code and an error message.
        """
        code = response.status_code
        if code != 200:
            error = response.json()["error"]
            # For further details, see: https://developers.virustotal.com/v3.0/reference#errors
            raise VT3Exception(code, error["code"], error["message"])

    def _post(self, path, data=None, json=None, files=None, **params):
        """ Send a POST request.
        """
        response = requests.post(self.url + path,
                                headers=self.headers,
                                data=data,
                                json=json,
                                files=files,
                                params=params, 
                                proxies=self.proxies)

        self._check_status_code(response)
            
        if self.json_format:
            return response.json()
        else:
            return response.content

    def _get(self, path, **params):
        """ Send a GET request.
        """
        response = requests.get(self.url + path, 
                                headers=self.headers, 
                                params=params,
                                proxies=self.proxies)


        self._check_status_code(response)
        
        if self.json_format:
            return response.json()
        else:
            return response.content
        
    