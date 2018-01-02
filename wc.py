import dns.resolver
import dns.reversename
import requests
import json
from pymongo import MongoClient
import pymongo
import resources
import ssl
from OpenSSL import crypto
import socket
from collections import OrderedDict, Counter
from investigate import grab_odd_domains, grab_new_domains
import geoip2.database
import secrets

def db_connect(database, collection):

    myClient = MongoClient('localhost', 27017)
    db = myClient[database]
    db_handle = db[collection]

    return db_handle

def import_nhs_from_file(filename, database, collection):

    db = db_connect(database, collection)
    domain_list = []
    entry = {}

    with open(filename) as fp:
        line = fp.readline().rstrip()
        line = line.split(',')
        while line:
            if len(line) < 3:
                break
            else:
                line[0] = line[0].title()
                if 'Nhs' in line[0]:
                    line[0] = line[0].replace('Nhs', 'NHS')
                entry['org-name'] = line[0]
                entry['org-l1'] = line[1]
                if 'www' in line[3]:
                    entry['domain'] = line[3].replace("www.", "")
                else:
                    entry['domain'] = line[3]
                domain_list.append(entry)
                entry = {}
                line = fp.readline().rstrip()
                line = line.split(',')

    fp.close()
    print (domain_list)
    db.insert_many(domain_list)

#import_nhs_from_file('first-nhs-ingest.csv', 'wcentre_health',  'all_dom')

def request_domains(url, params):
    # Make the request to the API provided by the URL and grab the JSON response
    # Used to collect the information from the GDS Domains Registry

    headers = {'accept': 'application/json'}
    resp = requests.get(url=url, params=params, headers=headers)
    data = json.loads(resp.text)
    return data

def do_query(domain_to_query, query_type):

    # Function to perform a DNS query. Performs A, MX, NS, CNAME query and return the
    # result to the caller. Includes some basic error handling if DNS returns NXDOMAIN, NoAnswer or
    # SERVERFAIL. In this case, these errors are returned

    try:
        answer = dns.resolver.query(domain_to_query, query_type)
    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return "NoAnswer"
    except dns.resolver.NoNameservers:
        return "SERVFAIL"

    # Return the set of items from the query, NS, MX, CNAME, A record etc.
    if 'A' or 'PTR' in query_type:
        return answer.rrset.items[0]
    else:
        return answer.rrset.items

def add_new_ns_provider(name_server):

    # Uses a WHOIS Lookup to query a Name Sever Provider domain
    # to discover the organisation that operates it.

    server = '.'.join(name_server.split('.')[1:])

    params = secrets.params
    params['domainName'] = server
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

add_new_ns_provider('ns1.cisco.com')

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

    # ToDo Consider adding a function to check on CA Provider and CDN provider needs to be added
    # ToDo as well as hosting provder

def build_ns_data(domain):

    result = []

    ns = do_query(domain, 'NS')
    if 'NXDOMAIN' in ns or 'NoAnswer' in ns:
        print('Domain',domain,"doesn't exist")
    else:
        for server in ns:
            result.append({"ns": str(server), "ns_provider": parse_record(str(server), 'NS'), "ns_ip": str(do_query(str(server), 'A'))})

    return result

def build_mx_data(domain):

    # For the provided domain, go and grab any MX record associated with it
    # and parse the result to match to a specific MX provider. Return a list with dict entries for
    # each MX record. Also grabs the IP of the MX server.

    result = []

    mx = do_query(domain, 'MX')
    if 'NXDOMAIN' in mx or 'NoAnswer' in mx:
        print ("No MX record for",domain)
        return 'No MX Record'
    else:
        for server in mx:
            server = str(server).split(' ',1)
            if len(server) > 1:
                result.append({"mx": server[1], "mx_provider": parse_record(server[1],'MX'), "mx_ip": str(do_query(server[1], 'A'))})
            else:
                result.append({"mx": server[0], "mx_provider": parse_record(server[0], 'MX'), "mx_ip": str(do_query(server[0], 'A'))})
        return result

def add_data_to_db(database, data):

    # Connect to the local MongoDB instance

    db = db_connect(database, 'all_dom')

    # Iterate over the data captured and check to see if the domain is already in the DB.
    # If it is in the DB, do nothing. If it isn't then insert a new document.

    for entry in data:

        check = db.find_one({"domain": entry["domain"]})
        if str(check) == "None":
            print(entry["domain"], " not found in the database")
            obj_id = db.insert(entry)
        else:
            print(entry["domain"], " found in the database")

def add_ns_data(database):

    ns_data = []

    db = db_connect(database, 'all_dom')

    # Build the dataset mapping a domain to a number of name servers.
    # Data will be a list of dicts with the format {{"domain": "<domain>"}, {"name_servers" : [{"ns":"<name-server>", "ns_provider":"<ns_provider>"}]}}

    for document in db.find():
        ns_data = build_ns_data(document['domain'])
        db.update_one({'_id': document['_id']},
                           {"$set": {"name_servers": ns_data}})


def add_mx_data(database):

    db = db_connect(database, 'all_dom')

    for document in db.find():
        mx_data = build_mx_data(document['domain'])
        if not 'No MX Record' in mx_data:
            db.update_one({'_id': document['_id']},
                               {"$set": {"mail_servers": mx_data}})


def add_whois_email(database):

    uri = 'https://investigate.api.umbrella.com/whois/'

    apikey = secrets.apikey

    db = db_connect(database, 'all_dom')

    for document in db.find():
        req = requests.get(url=uri + document['domain'], headers={'Authorization': 'Bearer ' + apikey})
        data = json.loads(req.text)

        if not 'registrantEmail' in data:
            db.update_one({'_id': document['_id']},
                               {"$set": {"registrantEmail": "Unknown"}})

        else:
            if data['registrantEmail'] == '':
                db.update_one({'_id': document['_id']},
                                   {"$set": {"registrantEmail": "Unknown"}})

            else:
                db.update_one({'_id': document['_id']},
                                   {"$set": {"registrantEmail": data['registrantEmail']}})

def build_gds_base_data(registry_data):

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

def load_gds_domain_data():

    database = 'wcentre_gov'
    collection = 'all_dom'

    db = db_connect(database, collection)

    # Main GDS Register URL for domains information
    API_URL = 'https://government-domain.register.gov.uk/records'

    # Set the number of records to be retrived from the server
    PARAMS = {'page-index': '1', 'page-size': '2939'}

    # Grab the raw domain data from the GDS Domains API
    domain_data = request_domains(API_URL, PARAMS)

    #Extract all of the domains and organisation data from the raw GDS domain registry data

    base_data = build_gds_base_data(domain_data)

    # Dump the extracted data to MongoDB

    db.insert_many(base_data)

def add_org_type():

    #Function to enrich the domain data with organisational details

    db = db_connect('wcentre_gov','all_dom')

    # Check to see if the domain includes 'parish', 'towncouncil' or '-dc' and set the Org L3 accordingly

    for document in db.find():
        if 'parish' in document['domain'] or '-pc' in document['domain']:
            db.update_one({'_id': document['_id']},
                               {"$set": {"org-l3": "Parish Council"}})

        elif 'towncouncil' in document['domain'] or '-tc' in document['domain']:
            db.update_one({'_id': document['_id']},
                               {"$set": {"org-l3": "Town Council"}})

        elif '-dc' in document['domain']:
            db.update_one({'_id': document['_id']},
                               {"$set": {"org-l3": "District Council"}})

    # Go over the domains in the DB and extract the Org details from the domain registry
    # Extract the org code and type and then handle the parsing of this accordingly
    # Once we know the details, set the relavent details in the DB

    for document in db.find():
        if not 'Unknown' in document['reg_org']:

            org_type, org_code = document['reg_org'].split(':')

            if 'local-authority-eng' in document['reg_org']:

                org_name, org_l2 = add_lgov_org(org_code)

                db.update_one({'_id': document['_id']},
                                   {"$set": {"org-l1": "Local Government"}})
                db.update_one({'_id': document['_id']},
                                   {"$set": {"org-l2": org_l2}})
                db.update_one({'_id': document['_id']},
                                   {"$set": {"org-name": org_name}})

            elif 'government-organisation' in document['reg_org']:

                org_name = add_gov_org(org_code)
                db.update_one({'_id': document['_id']},
                                   {"$set": {"org-l1": "Government Organisation"}})
                db.update_one({'_id': document['_id']},
                                   {"$set": {"org-name": org_name}})

            elif 'internal-drainage-board' in document['reg_org']:

                org_name = add_idb_org(org_code)
                db.update_one({'_id': document['_id']},
                                   {"$set": {"org-l1": "Internal Drainage Board"}})
                db.update_one({'_id': document['_id']},
                                   {"$set": {"org-name": org_name}})

            elif 'principal-local-authority' in document['reg_org']:

                org_name = add_pla_org(org_code)

                db.update_one({'_id': document['_id']},
                                   {"$set": {"org-l1": "Local Government"}})
                db.update_one({'_id': document['_id']},
                                   {"$set": {"org-l2": "Principal Local Authority"}})
                db.update_one({'_id': document['_id']},
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
    else:
        org_type = 'Unknown'

    return org_name, org_type

def add_ca_details(database):

    # Query each domain by adding www on the front and trying to connect to
    # port 443. If a cert is returned, parse it for the Issuer Name and Subject name and
    # add this to the DB

    # ToDo Do something with the Subject Name.
    # ToDo Look at the Issuer name and infer something from this (public, private, self-signed)

    db = db_connect(database, 'all_dom')

    for document in db.find():
        target = 'www.'+document['domain']

        try:

            sock = socket.create_connection((target, 443), timeout=2)

            cert = ssl.get_server_certificate((target, 443))
            sock.close()
            new_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
            issuer = new_cert.get_issuer()
            subject = new_cert.get_subject()

            db.update_one({'_id': document['_id']},
                          {"$set": {"https": 'True'}})

            for component in issuer.get_components():
                if component[0] == b'O':
                    db.update_one({'_id': document['_id']},
                                      {"$set": {"ca-issuer": str(component[1], 'utf-8')}})

            for component in subject.get_components():
                if component[0] == b'O':
                    db.update_one({'_id': document['_id']},
                                    {"$set": {"ca-subject-org": str(component[1], 'utf-8')}})
                elif component[0] == b'CN':
                    db.update_one({'_id': document['_id']},
                                  {"$set": {"ca-subject-cn": str(component[1], 'utf-8')}})

        except socket.error:
            print("Socket Error")
            db.update_one({'_id': document['_id']},
                          {"$set": {"https": 'False'}})


def add_a_rr(database):

    # Parse each domain in the DB, prepend with www and then query the A record
    # Take the A record information and query to get the ASN number and other associated
    # IP information. Save all this in the DB

    asn_collection = 'asn_map'

    db = db_connect(database, 'all_dom')

    asn_db = db_connect(database, asn_collection)

    # MaxMind GeoIP2 Lite DB readers

    city_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
    asn_reader = geoip2.database.Reader('GeoLite2-ASN.mmdb')

    # Will need to adjust this for the new domains being sucked in as they won't need 'www' added to the front

    for document in db.find():
        target = 'www.'+document['domain']

        result = do_query(target,'A')

        try:
            if result.address:

                asn, asn_org = grab_asn(result.address, asn_reader)
                city, country = grab_geoip(result.address, city_reader)

                db.update_one({'_id': document['_id']},
                               {"$set": {"a_rr": result.address, "asn": asn, "asn_org": asn_org, "city": city, "country": country}})

                if asn_db.find({"asn": asn}).count() == 0:
                    asn_entry = {}
                    asn_entry['asn'] = asn
                    asn_entry['asn_org'] = asn_org
                    asn_db.insert_one(asn_entry)
        except:
            pass


def add_reverse_dns(database):

    db = db_connect(database, 'all_dom')

    for document in db.find():
        # Grab the a_rr from the document and find the reversename
        # from it. Then grab the PTR record for that reverse name result.
        if document['a_rr']:
            rev_name = dns.reversename.from_address(document['a_rr'])
            reverse_dns = do_query(rev_name, "PTR")

              #  resolver.query(rev_name, "PTR")[0])
            print (document['domain'],reverse_dns,rev_name)

#add_reverse_dns('test_db')

def grab_asn(address, reader):

    response = reader.asn(address)
    asn = response.autonomous_system_number
    asn_org = response.autonomous_system_organization

    return asn, asn_org

def grab_geoip(address, reader):

    response = reader.city(address)
    country = response.country.name
    city = response.city.name

    return city, country

# Check to see if the below function is still being used....

def create_ns_collection():

    # Creates a new collection which matches the nameserver name to the
    # name server provider

    wc_1_db = db_connect('wc_1')
    ns_db = db_connect('nameservers')

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

#load_domains()
#add_org_type()
#add_ns_data()
add_whois_email('wcentre_health')
#add_ca_details('wcentre_health')
#add_a_rr('wcentre_health')
#add_mx_data()


def build_top_providers(database):

    # Function to extract and identify the top providers from the all_dom collection
    # and save in new collections in the DB

    db = db_connect(database, 'all_dom')
    ns_col = db_connect(database, 'top_nsp')
    ca_col = db_connect(database, 'top_ca')
    asn_col = db_connect(database, 'top_asn')
    mx_col = db_connect(database, 'top_mx')

    nsp = []
    mxp = []
    cap_list = []
    asn_list = []
    nsp_list = []
    mxp_list = []
    ns_other = 0
    ns_summary = {}

    mx_providers = []
    mx_totals = []

    for document in db.find():
        for entry in document['name_servers']:
            nsp.append(entry['ns_provider'])

        # Convert to set and then a list to remove duplicate entries.
        # We now have a list of the providers covering the domain in the collection

        nsp = list(set(nsp))

        # Now we need to add these providers to the master list, nsp_list

        for entry in nsp:
            nsp_list.append(entry)

        nsp = []

        # Lets also grab the CA Issuer details at the same time and add
        # this to the ca_providers

        try:
            if document['ca-issuer']:
                cap_list.append(document['ca-issuer'])
        except:
            pass

        try:
            if document['mail_servers']:
                for entry in document['mail_servers']:
                    mxp.append(entry['mx_provider'])

            mxp = list(set(mxp))

            for entry in mxp:
                mxp_list.append(entry)
            mxp = []

        except:
            pass

        try:
            if document['asn']:
                asn_list.append(document['asn'])

        except:
            pass

    # Lists now contains a list of all of the providers used across all of the domains with duplicates
    # per domain removed i.e. domain x has three NS and all are Rackspace will be reduced to a single entry
    # through the set conversion.

    nsp_list = dict(Counter(nsp_list))
    mxp_list = dict(Counter(mxp_list))
    cap_list = dict(Counter(cap_list))
    asn_list = dict(Counter(asn_list))

    # Summarise the data such that any provider with less than 5 domains
    # associated with it is put in to an 'Other' Bucket.

    ns_col.insert_many(prep_top(database, nsp_list, 'nsp'))
    asn_col.insert_many(prep_top(database, asn_list, 'asn'))
    ca_col.insert_many(prep_top(database, cap_list, 'cap'))
    mx_col.insert_many(prep_top(database, mxp_list, 'mxp'))

    # Todo - Should we store the data associated with the summary somehow so that this can be retrieved?

    #for entry in nsp_list:
    #    if nsp_list[entry] > 5:
    #        ns_summary[entry] = nsp_list[entry]
    #    else:
    #        ns_other = ns_other + nsp_list[entry]

    #ns_summary['Other'] = ns_other

    #cap = OrderedDict(sorted(cap.items(), key= lambda t: t[1], reverse=True))

    #print(ca_providers)


# ToDo Grab other domains that are hosted on the same IP (Umbrella)
# ToDo Grab TXT records to see if this identifies anything interesting i.e. mail server or similar.

def prep_top(database, list, type):

    # Reformat the supplied list in to the right dict format for
    # insertion in to MongoDB

    doc = {}
    totals = []

    if type == 'asn':
        asn_db = db_connect(database, 'asn_map')

    for entry in list:
        if type == 'asn':
            doc['asn'] = entry
            result = asn_db.find_one({"asn": entry})
            doc['asn_org'] = result['asn_org']
        else:
            doc['provider'] = entry
        doc['count'] = list[entry]
        totals.append(doc)
        doc = {}

    return totals

#build_top_providers()

