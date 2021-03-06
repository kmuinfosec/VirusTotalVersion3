import os
import requests

class PublicAPI:
    def __init__(self, api_key):
        self.api_key = api_key

    def post_files_scan(self, file_path):
        if not os.path.isfile(file_path):
            raise FileExistsError
        else:
            if os.path.getsize(file_path) < 32000000:
                with open(file_path, 'rb') as f:
                    data = {'file': f.read()}
                response = requests.post(
                    url = 'https://www.virustotal.com/api/v3/files',
                    headers = {'x-apikey': self.api_key},
                    files = data
                )
                return response.json()
            else:
                return {'error' : 'The total payload size can not exceed 32MB. For uploading larger files see the GET /files/upload_url endpoint.'}

    def get_files_upload_url(self):
        response = requests.get(
            url='https://www.virustotal.com/api/v3/files/upload_url',
            headers={'x-apikey': self.api_key}
        )
        return response.json()

    def get_file_info(self, id):
        response = requests.get(
            url='https://www.virustotal.com/api/v3/files/{}'.format(id),
            headers={'x-apikey': self.api_key}
        )
        return response.json()

    def post_files_analyse(self, id):
        response = requests.post(
            url='https://www.virustotal.com/api/v3/files/{}/analyse'.format(id),
            headers={'x-apikey': self.api_key}
        )
        return response.json()

    def get_files_comments(self, id):
        response = requests.get(
            url='https://www.virustotal.com/api/v3/files/{}/comments'.format(id),
            headers={'x-apikey': self.api_key}
        )
        return response.json()

    def post_files_comments(self, text):
        data = {
            'data': {
                'type': 'comment',
                'attributes': {
                    'text': text
                }
            }
        }
        response = requests.post(
            url='https://www.virustotal.com/api/v3/files/{id}/comments'.format(id),
            headers={'x-apikey': self.api_key},
            data=data
        )
        return response.json()

    def get_files_votes(self, id):
        response = requests.get(
            url='https://www.virustotal.com/api/v3/files/{}/votes'.format(id),
            headers={'x-apikey': self.api_key}
        )
        return response.json()

    def post_files_votes(self, id, verdict):
        data = {
            'data': {
                'type': 'vote',
                'attributes': {
                    'verdict': 'harmless'
                }
            }
        }
        response = requests.post(
            url='https://www.virustotal.com/api/v3/files/{}/votes'.format(id),
            headers={'x-apikey': self.api_key},
            data=data
        )
        return response.json()

    def get_files_relationships(self, id, relationship):
        response = requests.get(
            url='https://www.virustotal.com/api/v3/files/{}/{}'.format(id, relationship),
            headers={'x-apikey': self.api_key},
        )
        return response.json()

    def get_file_behaviours_pcap(self, sandbox_id):
        response = requests.get(
            url='https://www.virustotal.com/api/v3/file_behaviours/{}/pcap'.format(sandbox_id),
            headers={'x-apikey': self.api_key},
        )
        return response.json()

class PrivateAPI(PublicAPI):
    def __init__(self, api_key):
        super(PrivateAPI, self).__init__(api_key)

    def get_files_download_url(self, id):
        response = requests.get(
            url='https://www.virustotal.com/api/v3/files/{}/download_url'.format(id),
            headers={'x-apikey': self.api_key}
        )
        return response.json()

    def get_files_download(self, id):
        response = requests.get(
            url='https://www.virustotal.com/api/v3/files/{}/download'.format(id),
            headers={'x-apikey': self.api_key}
        )
        return response.json()