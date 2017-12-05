from flask import Flask, render_template, request, url_for, redirect
from pymongo import MongoClient
from collections import Counter, OrderedDict
from flask import Markup
import requests
import json

app = Flask(__name__)

def db_connect():

    myClient = MongoClient('localhost', 27017)
    db = myClient.test_db
    wc_1_db = db.wc_1

    return wc_1_db

@app.route("/")
def show_home():

   return render_template('summary.html')

@app.route("/search")
def show_search():
    return render_template('search.html')

@app.route("/domain", methods=['GET','POST'])
def search_domain():

    query = request.form['domain']

    wc_1_db = db_connect()

    count = 0
    found = {}

    for result in wc_1_db.find({"domain": {"$regex": query}}):
        count += 1
        if not 'org-name' in result:
            found[result["domain"]] = "Unknown"
        else:
            found[result["domain"]] = result["org-name"]

    return render_template('domainlist.html', count=count, list=found)

@app.route("/org", methods=['GET','POST'])
def search_org():

    query = request.form['org']

    wc_1_db = db_connect()

    count = 0
    found = {}

    for result in wc_1_db.find({"org-name": {"$regex": query, "$options": 'i'}}):
        count += 1

        if result["org-name"] in found:
            found[result["org-name"]].append(result["domain"])
        else:
            found[result["org-name"]] = []
            found[result["org-name"]].append(result["domain"])

    return render_template('orglist.html', count=count, list=found)

@app.route("/domaindd")
def domaindd():

    # Domain drill down view shows details for a specific domain

    query = request.args.get("domain")

    wc_1_db = db_connect()

    result = wc_1_db.find({"domain": {"$regex": query}})

    for document in result:
        return render_template('drilldown.html', document=document, domain=query)

@app.route("/nsdd")
def nameserver_drilldown():

    # Drill down view of a specific name server (e.g. ns1.domain.org)
    # Identify provider, domains that are supported by this NS and the IP
    # of the name server.

    query = request.args.get("ns")

    wc_1_db = db_connect()

    domains = []
    ns_provider = ''
    ns_ip = ''

    result = wc_1_db.find({"name_servers.ns": {"$regex": query}})

    for document in result:
        domains.append(document['domain'])
        for ns in document['name_servers']:
            if ns['ns'] == query:
                ns_provider = ns['ns_provider']
                ns_ip = ns['ns_ip']

    return render_template('nsdd.html', ns_ip=ns_ip, ns=query, ns_provider=ns_provider, domains=domains)

@app.route("/emaildd")
def email_drilldown():

    # Drill down view on WHOIS email address
    # Scrape Cisco Investigate API to grab other domains associated with
    # this e-mail address

    query = request.args.get("email")

    domains = []

    uri = 'https://investigate.api.umbrella.com/whois/emails/'
    apikey = 'b192381f-f0d2-4780-b107-907982592566'

    req = requests.get(url=uri + query, headers={'Authorization': 'Bearer ' + apikey})

    data = json.loads(req.text)
    if data[query]['totalResults'] > 0:
        for dom in data[query]['domains']:
            domains.append(dom['domain'])

    return render_template('emaildd.html', email=query, domains=domains)


@app.route("/summary")
def summary_view():

    # Summary page showing charts of NS Providers and CA Providers (Currently)

    wc_1_db = db_connect()

    prov = []
    totals = []
    ca_prov = []

    for document in wc_1_db.find():
        for entry in document['name_servers']:
            prov.append(entry['ns_provider'])
        # Convert to set and then a list to remove duplicate entries
        prov = list(set(prov))

        for entry in prov:
            totals.append(entry)
        prov = []

        try:
            if document['ca-issuer']:
                ca_prov.append(document['ca-issuer'])
        except:
            pass


    # totals now contains a list of all of the NS providers used across all of the domains with duplicates
    # per domain removed i.e. domain x has three NS and all are Rackspace will be reduced to a single entry
    # through the set conversion.

    count = Counter(totals)
    count = dict(count)

    other = 0
    summary_count = {}

    for entry in count:
        if count[entry] > 8:
            summary_count[entry] = count[entry]
        else:
            other = other + count[entry]

    summary_count['Other'] = other

    ca_prov = dict(Counter(ca_prov))

    # Create descending sorted dicts

    summary_count = OrderedDict(sorted(summary_count.items(), key=lambda t: t[1], reverse=True))
    ca_prov = OrderedDict(sorted(ca_prov.items(), key=lambda t: t[1], reverse=True))

    return render_template("summary.html", ns_providers=summary_count, ca_providers=ca_prov)


@app.route("/orgdd")
def org_drilldown():

    # Present the organisation Drill Down page. Will show the organisation details, name servers, CA providers etc

    query = request.args.get("org")

    wc_1_db = db_connect()

    domains = []
    ns_providers = []
    ca_providers = []

    for result in wc_1_db.find({"org-name": {"$regex": query}}):

        domains.append(result['domain'])
        if 'ca-issuer' in result:
            ca_providers.append(result['ca-issuer'])
        for ns in result['name_servers']:
            ns_providers.append(ns['ns_provider'])



    return render_template('orgdd.html', ns_providers=list(set(ns_providers)), ca_providers=list(set(ca_providers)), domains=domains, org=query)

@app.route("/nspdd")
def nsp_drilldown():

    query = request.args.get("provider")

    result = []

    wc_1_db = db_connect()

    for document in wc_1_db.find():
        for entry in document['name_servers']:
            if query in entry['ns_provider']:
                result.append(document['domain'])

    return render_template("nspdd.html", domains=list(set(result)), nsp=query)

