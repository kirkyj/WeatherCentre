import dns.resolver
import requests
import json
from collections import defaultdict
from pymongo import MongoClient
import pymongo
import resources


def request_domains(url, params):
    # Make the request to the API and grab the JSON response
    # Used to collect the information from the GDS Domains Registry

    headers = {'accept': 'application/json'}
    resp = requests.get(url=url, params=params, headers=headers)
    data = json.loads(resp.text)
    return data


def domain_to_fqdn(domain_data):

    # Helper routine to take the provided domain and add .gov.uk to the end in order
    # to then perform the NS lookup

    fqdn = []
    for key, value in domain_data.items():
        #domain_data['item'][0]['hostname'] = domain_data['item'][0]['hostname'+'.gov.uk']
        fqdn.append(value['item'][0]['hostname'])
    return fqdn

def query_nameserver(domain_to_query):

    try:
        answer = dns.resolver.query(domain_to_query, 'NS')
    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return "NoAnswer"

    # Return the first name server entry that we get back from the lookup
    # return answer.rrset[0].to_text()
    return answer.rrset.items

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

def parse_mx(mx_record):

    # Parse the provided MX record and check it against
    # our database of MX providers

    for mx_provider in resources.mx_providers():
        if mx_provider in mx_record:
            return resources.mx_providers[mx_provider]

    # If a match isn't found, return unknown and print it to the console
    print (mx_record, "is unknown")
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

def build_ns_data(domains):

    result = {}
    data = []

    for domain in domains:
        ns = do_query(domain+'.gov.uk', 'NS')
        if 'NXDOMAIN' in ns or 'NoAnswer' in ns:
            print('Domain',domain,"doesn't exist")
        else:
            result["domain"] = domain
            result["name_servers"] = []
            for server in ns:
                result["name_servers"].append({"ns": str(server), "ns_provider": parse_ns(str(server))})
            data.append(result)
            result = {}

    print(data)

    return data

#def build_mx_data(data):

    # data will already have the NS data included and so needs to be augmented with MX data

#    for domain in data:
        # Query the domain for the raw MX data and add the result back in to data
        # Do this in a separate
        # Also need to parse the MX record and identify the name MX provider and add this in as well.

    # Return the augmented data set
#    return data

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

def build_dataset():

    ns_result = {}

    # Main GDS Register URL for domains information
    API_URL = 'https://government-domain.register.gov.uk/records'

    # Set the number of records to be retrived from the server
    PARAMS = {'page-index': '1', 'page-size': '500'}

    # Grab the domain data from the GDS Domains API
    domain_data = request_domains(API_URL,PARAMS)

    # Extract the domain names from the returned data and append '.gov.uk' to each. Store the domains in to a list called 'domains'

    domains = domain_to_fqdn(domain_data)

    # Build the dataset mapping a domain to a number of name servers.
    # Data will be a list of dicts with the format {{"domain": "<domain>"}, {"name_servers" : [{"ns":"<name-server>", "ns_provider":"<ns_provider>"}]}}

    ns_result = build_ns_data(domains)

    # Next we need to add in the MX data on top of the NS data

    mx_result = build_mx_data(ns_result)


    print (resources.dns_providers)

    #try:
    #obj_id = wc_1_db.insert_many(result)
    #print (len(result))
    #obj_id = wc_1_db.update_many({}, result, upsert=True)
    #except pymongo.errors.BulkWriteError as bwe:
        #inserted_ids = [doc['_id'] for doc in result if not is_failed(doc, bwe) ]
    #else:
        #inserted_ids = obj_id.inserted_ids


    #for domain in domains:
    #    mx = do_query(domain+'.gov.uk','MX')
    #    for mailserver in mx:
    #        #result[domain]["email provider"] = mx
    #        print (domain,mailserver)


    #for domain, data in result.items():
     #   for ns_data, ns_entry in data.items():
     #       for entry in ns_entry:
     #           if 'Unknown' in entry['ns_provider']:
     #               print ("\nDomain", domain, "has an unknown DNS provider", entry['ns'])


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
    PARAMS = {'page-index': '1', 'page-size': '50'}

    # Grab the raw domain data from the GDS Domains API
    domain_data = request_domains(API_URL, PARAMS)

    base_data = build_base(domain_data)

    myClient = MongoClient('localhost', 27017)

    db = myClient.test_db

    wc_1_db = db.wc_1

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


#load_domains()
add_org_type()


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