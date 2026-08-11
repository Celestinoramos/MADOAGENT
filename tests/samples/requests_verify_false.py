import requests

resp = requests.get('https://example.com', verify=False)
print(resp.status_code)
