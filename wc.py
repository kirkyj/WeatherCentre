import dns.resolver
import requests
import json
from pymongo import MongoClient
import pymongo
import resources
import ssl
from OpenSSL import crypto
import socket
from collections import OrderedDict, Counter

def request_domains(url, params):
    # Make the request to the API and grab the JSON response
    # Used to collect the information from the GDS Domains Registry

    headers = {'accept': 'application/json'}
    resp = requests.get(url=url, params=params, headers=headers)
    data = json.loads(resp.text)
    return data

def db_connect(collection):

    myClient = MongoClient('localhost', 27017)
    db = myClient.test_db
    wc_1_db = db[collection]

    return wc_1_db

def domain_to_fqdn(domain_data):

    # Helper routine to take the provided domain and add .gov.uk to the end in order
    # to then perform the NS lookup

    fqdn = []
    for key, value in domain_data.items():
        #domain_data['item'][0]['hostname'] = domain_data['item'][0]['hostname'+'.gov.uk']
        fqdn.append(value['item'][0]['hostname'])
    return fqdn

def do_query(domain_to_query, query_type):

    try:
        answer = dns.resolver.query(domain_to_query, query_type)
    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return "NoAnswer"
    except dns.resolver.NoNameservers:
        return "SERVFAIL"

    # Return the set of items from the query, NS, MX, CNAME, A record etc.
    if 'A' in query_type:
        return answer.rrset.items[0]
    else:
        return answer.rrset.items

def add_new_ns_provider(name_server):
    # Need to strip the name server to remove text up to the first dot

    server = '.'.join(name_server.split('.')[1:])

    params = {'domainName': server,
              'username': 'kirky17',
              'password': 'Ds44M6DtAE',
              'outputFormat': 'JSON'}
    whois_url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"

    resp = requests.get(url=whois_url, params=params)
    data = json.loads(resp.text)
    if not 'ErrorMessage' in data:
        if 'registryData' in data['WhoisRecord'] and 'registrant' in data['WhoisRecord']['registryData']:
            resources.dns_providers[server] = data['WhoisRecord']['registryData']['registrant']['name']
            print('\"',server,'\"',':','\"',data['WhoisRecord']['registryData']['registrant']['name'],'\"', sep="")
            return data['WhoisRecord']['registryData']['registrant']['name']
        elif 'registrant' in data['WhoisRecord'] and 'organization' in data['WhoisRecord']['registrant']:
            resources.dns_providers[server] = data['WhoisRecord']['registrant']['organization']
            print('\"', server, '\"', ':', '\"', data['WhoisRecord']['registrant']['organization'], '\"',
                  sep="")
            return data['WhoisRecord']['registrant']['organization']
        else:
            return "Unknown"
    else:
        return "Unknown"

def parse_record(record, type):

    if type == 'NS':
        # Iterate over the DNS provider domain dictionary keys and look for a match against the NS provided
        for provider_domain in resources.dns_providers:
            # If a match is found, return the NS Provider name from the dns_provider dictionary
            if provider_domain in record:
                return resources.dns_providers[provider_domain]
                # If we don't find a match in the current dictionary, we need to lookup using
                # Whois to find out who the provider actually is.

        return add_new_ns_provider(name_server)

    elif type == 'MX':
        for mx_provider in resources.mx_providers:
            if mx_provider in record:
                return resources.mx_providers[mx_provider]

        if 'gov.uk' in record:
            return 'Government Hosted'
        else:
            return 'Unknown'

def parse_ns(name_server):

    # Iterate over the DNS provider domain dictionary keys and look for a match against the NS provided
    for provider_domain in resources.dns_providers:
        # If a match is found, return the NS Provider name from the dns_provider dictionary
        if provider_domain in name_server:
            return resources.dns_providers[provider_domain]
    # If we don't find a match in the current dictionary, we need to lookup using
    # Whois to find out who the provider actually is.

    return add_new_ns_provider(name_server)
    #print (name_server, "is an unknown domain")
    #return "Unknown"

def build_ns_data(domain):

    result = []

    ns = do_query(domain+'.gov.uk', 'NS')
    if 'NXDOMAIN' in ns or 'NoAnswer' in ns:
        print('Domain',domain,"doesn't exist")
    else:
        for server in ns:
            result.append({"ns": str(server), "ns_provider": parse_ns(str(server)), "ns_ip": str(do_query(str(server), 'A'))})
    #print(data)

    return result

def build_mx_data(domain):

    result = []

    mx = do_query(domain+'.gov.uk', 'MX')
    if 'NXDOMAIN' in mx or 'NoAnswer' in mx:
        return 'No MX Record'
    else:
        for server in mx:
            server = str(server).split(' ',1)
            if len(server) > 1:
                result.append({"mx": server[1], "mx_provider": parse_record(server[1],'MX'), "mx_ip": str(do_query(server[1], 'A'))})
            else:
                result.append({"mx": server[0], "mx_provider": parse_record(server[0], 'MX'), "mx_ip": str(do_query(server[0], 'A'))})
        return result

def add_data_to_db(data):

    # Connect to the local MongoDB instance

    myClient = MongoClient('localhost', 27017)

    db = myClient.test_db

    wc_1_db = db.wc_1

    # Iterate over the data captured and check to see if the domain is already in the DB.
    # If it is in the DB, do nothing. If it isn't then insert a new document.

    for entry in data:

        check = wc_1_db.find_one({"domain": entry["domain"]})
        if str(check) == "None":
            print(entry["domain"], " not found in the database")
            obj_id = wc_1_db.insert(entry)
        else:
            print(entry["domain"], " found in the database")

def add_ns_data():

    ns_data = []

    # Get DB Handle
    myClient = MongoClient('localhost', 27017)
    db = myClient.test_db
    wc_1_db = db.wc_1

    # Build the dataset mapping a domain to a number of name servers.
    # Data will be a list of dicts with the format {{"domain": "<domain>"}, {"name_servers" : [{"ns":"<name-server>", "ns_provider":"<ns_provider>"}]}}

    for document in wc_1_db.find():
        ns_data = build_ns_data(document['domain'])
        #print(ns_data)
        wc_1_db.update_one({'_id': document['_id']},
                           {"$set": {"name_servers": ns_data}})


def add_mx_data():

    wc_1_db = db_connect()

    for document in wc_1_db.find():
        #print(document['domain']+'.gov.uk')
        mx_data = build_mx_data(document['domain'])
        if not 'No MX Record' in mx_data:
            wc_1_db.update_one({'_id': document['_id']},
                               {"$set": {"mail_servers": mx_data}})


#add_mx_data()

def add_whois_email():

    uri = 'https://investigate.api.umbrella.com/whois/'

    apikey = 'b192381f-f0d2-4780-b107-907982592566'

    # Get DB Handle
    myClient = MongoClient('localhost', 27017)
    db = myClient.test_db
    wc_1_db = db.wc_1

    for document in wc_1_db.find():
        req = requests.get(url=uri + document['domain'] + '.gov.uk', headers={'Authorization': 'Bearer ' + apikey})
        data = json.loads(req.text)

        if not 'registrantEmail' in data:
            wc_1_db.update_one({'_id': document['_id']},
                               {"$set": {"registrantEmail": "Unknown"}})

        else:
            if data['registrantEmail'] == '':
                wc_1_db.update_one({'_id': document['_id']},
                                   {"$set": {"registrantEmail": "Unknown"}})

            else:
                wc_1_db.update_one({'_id': document['_id']},
                                   {"$set": {"registrantEmail": data['registrantEmail']}})

def build_base(registry_data):

    # Extract the base entries from the hostname and organisation
    # ID within the GDS domain registry

    base = []
    entry = {}

    for key, value in registry_data.items():
        entry["domain"] = value['item'][0]['hostname']
        try:
            entry["reg_org"] = value['item'][0]['organisation']
        except KeyError:
            entry["reg_org"] = "Unknown"

        base.append(entry)

        entry = {}
    return base

def load_domains():

    # Main GDS Register URL for domains information
    API_URL = 'https://government-domain.register.gov.uk/records'

    domain_dict = {}
    domain_list = []

    # Set the number of records to be retrived from the server
    PARAMS = {'page-index': '1', 'page-size': '500'}

    # Grab the raw domain data from the GDS Domains API
    domain_data = request_domains(API_URL, PARAMS)

    #Extract all of the domains and organisation data from the raw GDS domain registry data

    base_data = build_base(domain_data)

    myClient = MongoClient('localhost', 27017)

    db = myClient.test_db

    wc_1_db = db.wc_1

    # Dump the extracted data to MongoDB

    obj_id = wc_1_db.insert_many(base_data)

def add_org_type():

    #Function to enrich the domain data with organisational details

    # Get DB Handle
    myClient = MongoClient('localhost', 27017)
    db = myClient.test_db
    wc_1_db = db.wc_1

    # Check to see if the domain includes 'parish', 'towncouncil' or '-dc' and set the Org L3 accordingly

    for document in wc_1_db.find():
        if 'parish' in document['domain'] or '-pc' in document['domain']:
            wc_1_db.update_one({'_id': document['_id']},
                               {"$set": {"org-l3": "Parish Council"}})

        elif 'towncouncil' in document['domain'] or '-tc' in document['domain']:
            wc_1_db.update_one({'_id': document['_id']},
                               {"$set": {"org-l3": "Town Council"}})

        elif '-dc' in document['domain']:
            wc_1_db.update_one({'_id': document['_id']},
                               {"$set": {"org-l3": "District Council"}})

    # Go over the domains in the DB and extract the Org details from the domain registry
    # Extract the org code and type and then handle the parsing of this accordingly
    # Once we know the details, set the relavent details in the DB

    for document in wc_1_db.find():
        if not 'Unknown' in document['reg_org']:

            org_type, org_code = document['reg_org'].split(':')

            if 'local-authority-eng' in document['reg_org']:

                org_name, org_l2 = add_lgov_org(org_code)

                wc_1_db.update_one({'_id': document['_id']},
                                   {"$set": {"org-l1": "Local Government"}})
                wc_1_db.update_one({'_id': document['_id']},
                                   {"$set": {"org-l2": org_l2}})
                wc_1_db.update_one({'_id': document['_id']},
                                   {"$set": {"org-name": org_name}})

            elif 'government-organisation' in document['reg_org']:

                org_name = add_gov_org(org_code)
                wc_1_db.update_one({'_id': document['_id']},
                                   {"$set": {"org-l1": "Government Organisation"}})
                wc_1_db.update_one({'_id': document['_id']},
                                   {"$set": {"org-name": org_name}})

            elif 'internal-drainage-board' in document['reg_org']:

                org_name = add_idb_org(org_code)
                wc_1_db.update_one({'_id': document['_id']},
                                   {"$set": {"org-l1": "Internal Drainage Board"}})
                wc_1_db.update_one({'_id': document['_id']},
                                   {"$set": {"org-name": org_name}})

            elif 'principal-local-authority' in document['reg_org']:

                org_name = add_pla_org(org_code)

                wc_1_db.update_one({'_id': document['_id']},
                                   {"$set": {"org-l1": "Local Government"}})
                wc_1_db.update_one({'_id': document['_id']},
                                   {"$set": {"org-l2": "Principal Local Authority"}})
                wc_1_db.update_one({'_id': document['_id']},
                                   {"$set": {"org-name": org_name}})

def add_pla_org(org_code):

    API_URL = 'https://principal-local-authority.register.gov.uk/record/' + org_code

    headers = {'accept': 'application/json'}
    resp = requests.get(url=API_URL, headers=headers)

    data = json.loads(resp.text)

    return data[org_code]['item'][0]['official-name']

def add_idb_org(org_code):

    API_URL = 'https://internal-drainage-board.register.gov.uk/record/' + org_code

    headers = {'accept': 'application/json'}
    resp = requests.get(url=API_URL, headers=headers)

    data = json.loads(resp.text)

    return data[org_code]['item'][0]['name']

def add_gov_org(org_code):

    API_URL = 'https://government-organisation.register.gov.uk/record/' + org_code

    headers = {'accept': 'application/json'}
    resp = requests.get(url=API_URL, headers=headers)

    data = json.loads(resp.text)

    return data[org_code]['item'][0]['name']

def add_lgov_org(org_code):

    API_URL = 'https://local-authority-eng.register.gov.uk/record/' + org_code

    headers = {'accept': 'application/json'}
    resp = requests.get(url=API_URL, headers=headers)

    data = json.loads(resp.text)

    org_name = data[org_code]['item'][0]['official-name']
    org_type_code = data[org_code]['item'][0]['local-authority-type']

    if 'UA' in org_type_code:
        org_type = 'Unitary Authority'
    elif 'NMD' in org_type_code:
        org_type = 'Non-metropolitan District'
    elif 'CTY' in org_type_code:
        org_type = 'County Council'
    elif 'MD' in org_type_code:
        org_type = 'Metropolitan district'
    elif 'SLA' in org_type_code:
        org_type = 'Strategic Regional Authority'
    elif 'CC' in org_type_code:
        org_type = 'City corporation'
    elif 'LBO' in org_type_code:
        org_type = 'London Borough'

    return org_name, org_type

def add_ca_details():

    myClient = MongoClient('localhost', 27017)
    db = myClient.test_db
    wc_1_db = db.wc_1

    for document in wc_1_db.find():
        target = 'www.'+document['domain']+'.gov.uk'

        try:

            sock = socket.create_connection((target, 443), timeout=2)

            cert = ssl.get_server_certificate((target, 443))
            sock.close()
            new_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
            issuer = new_cert.get_issuer()
            subject = new_cert.get_subject()

            for component in issuer.get_components():
                if component[0] == b'O':
                    wc_1_db.update_one({'_id': document['_id']},
                                      {"$set": {"ca-issuer": str(component[1], 'utf-8')}})


        except socket.error:
            print("Socket Error")
            #pass

def add_a_rr():

    myClient = MongoClient('localhost', 27017)
    db = myClient.test_db
    wc_1_db = db.wc_1

    for document in wc_1_db.find():
        target = 'www.'+document['domain']+'.gov.uk'

        result = do_query(target,'A')
        print (result)

def create_ns_collection():

    myClient = MongoClient('localhost', 27017)
    db = myClient.test_db

    wc_1_db = db.wc_1
    ns_db = db.nameservers

    name_servers = {}

    # List of servers that a provider operates. Each server has an entry of the form
    # {'ns': ns_name, 'ns_ip': ns_ip}
    provider = {}
    providers = []
    servers = []

    for document in wc_1_db.find():
        for entry in document['name_servers']:
            providers.append(entry['ns_provider'])
    providers = list(set(providers))

    for item in providers:
        provider['provider'] = item
        ns_db.insert_one(provider)
    #print (provider)
            #servers.append({'ns': entry['ns'], 'ns_ip': entry['ns_ip']})
        #name_servers['servers'] = servers
        #servers = []
        #print (name_servers)
        #ns_db.find({"provider": {"$regex": name_servers['provider']}})
        #obj_id = ns_db.insert_one(name_servers)
        #else:
        #    pass
        #name_servers = {}

#load_domains()
#add_org_type()
#add_ns_data()
#add_whois_email()
#add_ca_details()
#add_a_rr()
#create_ns_collection()

def new_main():

    from collections import Counter

    myClient = MongoClient('localhost', 27017)

    db = myClient.test_db

    wc_1_db = db.wc_1
    #count = 0
    #ns_search = input('What NS are you interested in searching for?')

    #for result in wc_1_db.find({"name_servers.ns_provider": {"$regex" : ns_search}},{"domain":1}):
    #    print(result["domain"]+".gov.uk")
    #   count += 1

    #print ("\nThere are", count, "domains using", ns_search, "as a DNS provider.")

    counts = []
    servers = []

    for totals in wc_1_db.find({},{"name_servers.ns_provider":1}):
        #print (totals["name_servers"])
        for ns in totals["name_servers"]:
            servers.append(ns["ns_provider"])

        unique = list(set(servers))
        for provider in unique:
            counts.append(provider)
        servers.clear()

    converted = list(counts)
    output = Counter(converted)

    print (output)

def testing():

    query = "City and County of Swansea Council"

    myClient = MongoClient('localhost', 27017)
    db = myClient.test_db
    wc_1_db = db.wc_1

    domains = []
    ns_providers = []
    ca_providers = []

    for result in wc_1_db.find({"org-name": {"$regex": query}}):

        domains.append(result['domain'])
        ca_providers.append(result['ca-issuer'])
        for ns in result['name_servers']:
            ns_providers.append(ns['ns_provider'])

    print (domains)
    print (ns_providers)
    print (ca_providers)

#testing()



def build_top_providers():

    # Function to extract and identify the top providers

    wc_1_db = db_connect('wc_1')
    ns_db = db_connect('nameservers')
    ns_db = db_connect('ca')

    ns_provider = []
    ns_totals = []
    ns_other = 0
    ns_summary = {}

    ca_providers = []

    mx_providers = []
    mx_totals = []


    for document in wc_1_db.find():
        for entry in document['name_servers']:
            ns_provider.append(entry['ns_provider'])

        # Convert to set and then a list to remove duplicate entries.
        # We now have a list of the providers covering the domain
        ns_provider = list(set(ns_provider))

        # Now we need to add these providers to the master list, ns_totals

        for entry in ns_provider:
            ns_totals.append(entry)

        ns_provider = []

        # Lets also grab the CA Issuer details at the same time and add
        # this to the ca_providers

        try:
            if document['ca-issuer']:
                ca_providers.append(document['ca-issuer'])
        except:
            pass

        # TODO - Also need to grab the mail server details and add this to its own list

    # ns_totals now contains a list of all of the NS providers used across all of the domains with duplicates
    # per domain removed i.e. domain x has three NS and all are Rackspace will be reduced to a single entry
    # through the set conversion.

    ns_totals = dict(Counter(ns_totals))
    ca_providers = dict(Counter(ca_providers))

    # Summarise the data such that any provider with less than 5 domains
    # associated with it is put in to an 'Other' Bucket.

    # Todo - Should we store the data associated with the summary somehow so that this can be retrieved?

    for entry in ns_totals:
        if ns_totals[entry] > 5:
            ns_summary[entry] = ns_totals[entry]
        else:
            ns_other = ns_other + ns_totals[entry]

    ns_summary['Other'] = ns_other

    ca_providers = OrderedDict(sorted(ca_providers.items(), key= lambda t: t[1], reverse=True))

    print(ca_providers)

build_top_providers()