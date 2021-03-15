import os
import requests

from vt3exception import VT3Exception
from vt3base import VT3Request

class VT3Files(VT3Request):
    """Class for the Files endpoints."""

    def __upload_lerge_file(self, files, timeout):
        """Upload lerge file."""
        response = self._get('/files/upload_url', timeout=timeout)
        
        self._check_status_code(response)

        upload_url = response.json()["data"]
        response = requests.post(upload_url, headers=self.headers, files=files, proxies=self.proxies, timeout=timeout)
        self._check_status_code(response)

        if self.json_format:
            return response.json()
        else:
            return response.content 

    def upload(self, filepath, timeout=None):
        """Upload the file to VirusTotal.   
        Args:
            filepath(str): Path to the file to upload.
            timeout(float, optional): The amount of time per seconds, for the request to wait until the timeout expires.
        
        Returns:
            The response from the server as a json or byte sequence.

        Exceptions:
            RequestException: Response timeout from the server is exceeded or server connection error.
            VT3Exception: If the request failed.
        """
        if not os.path.isfile(filepath):
            raise FileNotFoundError('File not found')
        
        file_max_size = 33554432
        with open(filepath, 'rb') as file:
            files = {'file' : (filepath, file)}
            filesize = os.path.getsize(filepath)
            
            if filesize < file_max_size:
                return self._post('/files', files=files, timeout=timeout)
            else:
                return self.__upload_lerge_file(files, timeout)

    def upload_url(self, timeout=None):
        """Get a URL for uploading files larger than 32MB.
        Args:
            timeout(float, optional): The amount of time per seconds, for the request to wait until the timeout expires.

        Returns:
            The response from the server as a json or byte sequence.
        
        Exceptions:
            RequestException: Response timeout from the server is exceeded or server connection error.
            VT3Exception: If the request failed.
        """
        return self._get('/files/upload_url', timeout=timeout)

    def report(self, id, timeout=None):
        """Retrieve information about a file.
        Args:
            id(str): SHA-256/SHA-1/MD5 identifying the file.
            timeout(float, optional): The amount of time per seconds, for the request to wait until the timeout expires.
        
        Returns:
            The response from the server as a json or byte sequence.
        
        Exceptions:
            RequestException: Response timeout from the server is exceeded or server connection error.
            VT3Exception: If the request failed.
        """
        return self._get(f'/files/{id}', timeout=timeout)

    def analyse(self, id, timeout=None):
        """Reanalyze the file already uploaded to VirusTotal.
        Args:
            id(str): SHA-256/SHA-1/MD5 identifying the file.
            timeout(float, optional): The amount of time per seconds, for the request to wait until the timeout expires.

        Returns:
            The response from the server as a json or byte sequence.

        Exceptions:
            RequestException: Response timeout from the server is exceeded or server connection error.
            VT3Exception: If the request failed.
        """
        return self._post(f'/files/{id}/analyse', timeout=timeout)

    def get_comments(self, id, limit=10, cursor=None, timeout=None):
        """Retrieve comments for a file.
        Args:
            id(str): SHA-256/SHA-1/MD5 identifying the file.
            limit(int, optional): Maximum number of comments to retrieve(default limit = 10).
            cursor(str, optional): Continuation cursor.
            timeout(float, optional): The amount of time per seconds, for the request to wait until the timeout expires.
        
        Returns:
            The response from the server as a json or byte sequence.
        
        Exceptions:
            RequestException: Response timeout from the server is exceeded or server connection error.
            VT3Exception: If the request failed.
        """
        return self._get(f'/files/{id}/comments', limit=str(limit), cursor=cursor, timeout=timeout)

    def add_comments(self, id, text, timeout=None):
        """Add a comment to a file.
        Args:
            id(str): SHA-256/SHA-1/MD5 identifying the file.
            text(str): The text of the comment.
            timeout(float, optional): The amount of time per seconds, for the request to wait until the timeout expires.
        
        Returns:
            The response from the server as a json or byte sequence.

        Exceptions:
            RequestException: Response timeout from the server is exceeded or server connection error.
            VT3Exception: If the request failed.
        """
        comment = {"data": {"type": "comment", "attributes": {"text": text}}}
        return self._post(f'/files/{id}/comments', json=comment, timeout=timeout)

    def get_votes(self, id, limit=10, cursor=None, timeout=None):
        """Retrieve votes for a file.
        Args:
            id(str): SHA-256/SHA-1/MD5 identifying the file.
            limit(int, optional): Maximum number of comments to retrieve(default limit = 10).
            cursor(str, optional): Continuation cursor.
            timeout(float, optional): The amount of time per seconds, for the request to wait until the timeout expires.
        
        Returns:
            The response from the server as a json or byte sequence.
        
        Exceptions:
            RequestException: Response timeout from the server is exceeded or server connection error.
            VT3Exception: If the request failed.
        """
        return self._get(f'/files/{id}/votes', limit=str(limit), cursor=cursor, timeout=timeout)

    def add_votes(self, id, malicious=True, timeout=None):
        """Add a verdict to a file.
        Args:
            id(str): SHA-256/SHA-1/MD5 identifying the file.
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
        return self._post(f'/files/{id}/votes', json=votes, timeout=timeout)

    @staticmethod
    def is_valid_relationship(relationship):
        """Check relationship name."""
        relationships = [
            'analyses', 'behaviours', 'bundled_files', 'carbonblack_children','carbonblack_parents', 'ciphered_parents'
            'clues', 'comments', 'compressed_parents', 'contacted_domains', 'contacted_ips', 'contacted_urls', 'dropped_files',
            'email_attachments','email_parents', 'embedded_domains', 'embedded_ips', 'embedded_urls', 'execution_parents',
            'graphs', 'itw_ips', 'itw_urls', 'overlay_children', 'overlay_parents', 'pcap_children', 'pcap_parents', 'pe_resource_children', 
            'pe_resource_parents', 'sigma_analysis', 'similar_files',  'submissions', 'screenshots', 'votes'
        ]
        if relationship not in relationships:
            return False
        return True

    def get_relationship(self, id, relationship, limit=10, cursor=None, timeout=None):
        """Retrieve objects related to a file.
        Args:
            id(str): SHA-256/SHA-1/MD5 identifying the file.
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
        relship = relationship.lower()
        if not self.is_valid_relationship(relship):
            raise ValueError('Invalid relationships value')

        return self._get(f'/files/{id}/{relship}', limit=str(limit), cursor=cursor, timeout=timeout)

    def get_file_behaviours(self, sandbox_id, report = None, timeout=None):
        """File behaviour report from a sandbox.
        Args:
            sandbox_id(str): Sandbox report ID. A Sandbox report ID has two main components: the analysed file's SHA256 and the sandbox name. 
                            These two components are joined by a _ character. For example, ID 5353e23f3653402339c93a8565307c6308ff378e03fcf23a4378f31c434030b0_VirusTotal 
                            Jujubox fetches the sandbox report for a file having a SHA256 5353e23f3653402339c93a8565307c6308ff378e03fcf23a4378f31c434030b0 analysed in the 
                            VirusTotal Jujubox sandbox.
            report(str, optional): Report format:
                                        None - JSON or byte sequence
                                        pcap - Extracted PCAP from a sandbox analysis;
                                        html - HTML sandbox report.
            timeout(float, optional): The amount of time per seconds, for the request to wait until the timeout expires.

        Returns:
            The response from the server as a json or byte sequence(html, pcap).

        Exceptions:
            ValueError: Invalid report format value.
            RequestException: Response timeout from the server is exceeded or server connection error.
            VT3Exception: If the request failed.
        """
        if report is None:
            return self._get(f'/file_behaviours/{sandbox_id}')
        else:
            reports = ['html', 'pcap']
            if report.lower() not in reports:
                raise ValueError('Invalid report format value')

            url = self.url + f'/file_behaviours/{sandbox_id}/{report.lower()}'
            response = requests.get(url, headers=self.headers, proxies=self.proxies, timeout=timeout)

            self._check_status_code(response)

            return response.content
