import requests
import json
import datetime
from pymongo import MongoClient
import time
import secrets

def query_investigate(domain, query):

    uri = 'https://investigate.api.umbrella.com/search/'
    apikey = secrets.apikey

    params = {'start': '-4weeks'}

    req = requests.get(url=uri+query+domain, headers={'Authorization': 'Bearer ' + apikey}, params=params)

    return json.loads(req.text)

def query_ip(address):
    # Go and search the investigate API with the supplied IP address
    # Grab the ASN number (which can be added to the DB) and IP Owner information
    # Also grab known malicious domains hosted by the IP
    # Also identify if the IP hosts non-HMG domains
    # Also work out GeoIP?

    uri = 'https://investigate.api.umbrella.com/ips/'
    apikey = secrets.apikey

    req = requests.get(url=uri+address+'/latest_domains', headers={'Authorization': 'Bearer ' + apikey})

    data = json.loads(req.text)


    if len(data) == 0:
        return 'clean'
    else:
        return 'bad'

def grab_new_domains():

    new_domains = []
    item = {}

    #query = '.*'
    query = '[a-z,0-9]*'
    domains = ['\.gov.uk', '\.ac.uk', '\.sch.uk', '\.police.uk', '\.nhs.uk']

    for dom in domains:
        data = query_investigate(dom, query)

        for entry in data['matches']:
            item['domain'] = entry['name']
            firstseen = datetime.datetime.strptime(entry['firstSeenISO'], "%Y-%m-%dT%H:%M:%S.%fZ")
            item['seen'] = firstseen.strftime("%A, %d. %B %Y %I:%M%p")
            new_domains.append(item)
            item = {}

    return new_domains

def grab_odd_domains():

    odd_domains = []
    item = {}

    query = '[a-z,0-9]*'
    domains = ['gov.uk']

    for dom in domains:
        data = query_investigate(dom, query)

        for entry in data['matches']:
            item['domain'] = entry['name']
            firstseen = datetime.datetime.strptime(entry['firstSeenISO'], "%Y-%m-%dT%H:%M:%S.%fZ")
            item['seen'] = firstseen.strftime("%A, %d. %B %Y %I:%M%p")
            odd_domains.append(item)
            item = {}

    return odd_domains

def grab_domains(type):
    # Wrapper function to check for DB entry freshness

    myClient = MongoClient('localhost', 27017)
    db = myClient.test_db


    if type == 'new':
        new_db = db.newdomains
        return check_freshness(new_db, type)

    elif type =='odd':
        odd_db = db.odddomains
        return check_freshness(odd_db, type)

def check_freshness(db, type):

    data = {}
    delta = datetime.timedelta(days=1)

    if db.count() == 0:
        data['timestamp'] = datetime.datetime.utcnow()

        if type == 'new':
            data['domains'] = grab_new_domains()
        elif type == 'odd':
            data['domains'] = grab_odd_domains()

        db.insert_one(data)
        return data['domains']
    else:
        for result in db.find():
            timestamp = result['timestamp']
            now = datetime.datetime.now()

            if (now - timestamp > delta):
                # Data is one day old so needs refreshing
                db.delete_one({'_id': result['_id']})
                data['timestamp'] = datetime.datetime.utcnow()
                if type == 'new':
                    data['domains'] = grab_new_domains()
                elif type == 'odd':
                    data['domains'] = grab_odd_domains()
                db.insert_one(data)
                return data['domains']
            else:
                return result['domains']