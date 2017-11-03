import requests
import json
import pprint


uri = 'https://investigate.api.umbrella.com/search/[a-z]*.gov.uk'

new_uri = "https://investigate.api.umbrella.com/dnsdb/ip/ns/194.176.105.223.json"
apikey = 'b192381f-f0d2-4780-b107-907982592566'

params = {'start': '-4weeks'}

req = requests.get(url=new_uri, headers={'Authorization': 'Bearer ' + apikey})
data = json.loads(req.text)

print (data)