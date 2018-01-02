from flask import Flask, render_template, request, url_for, redirect, jsonify
from pymongo import MongoClient
from collections import Counter, OrderedDict
from flask import Markup
import requests
import json
from investigate import grab_domains, query_ip

app = Flask(__name__)
app.config['DEBUG'] = True

datasets = {'gds': 'wc_1',
           'cni': 'cni_domains'}

def db_connect(collection):

    myClient = MongoClient('localhost', 27017)
    db = myClient.test_db
    col = db[collection]

    return col

@app.route("/")
def show_home():

   return render_template('summary.html')

@app.route("/search")
def show_search():
    return render_template('search.html')

@app.route("/domain", methods=['GET','POST'])
def search_domain():

    query = request.form['domain']

    wc_1_db = db_connect('wc_1')

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

    wc_1_db = db_connect('wc_1')

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

@app.route("/asn", methods=['GET','POST'])
def search_asn():

    query = request.form['asn']

    print (query)

    wc_1_db = db_connect('wc_1')

    # Broken. Searching for a text string on an integer field
    # Need to treat as a string (or store as a string :/

    count = 0
    found = {}

    for result in wc_1_db.find({"asn": {"$regex": query}}):
        count += 1

        found[result["asn"]] = result["asn_org"]

    return render_template('asnlist.html', count=count, list=found)

@app.route("/domaindd")
def domaindd():

    # Domain drill down view shows details for a specific domain

    query = request.args.get("domain")

    wc_1_db = db_connect('wc_1')

    result = wc_1_db.find({"domain": {"$regex": query}})

    # ToDo Check to see if there is a result. If there isn't, return aa different template to ask
    # if the domain should be added to the database.

    status = ''
    if result.count() > 0:
        for document in result:
            try:
                if document['a_rr']:
                    status = query_ip(document['a_rr'])
            except:
                pass
            return render_template('drilldown.html', document=document, domain=query, ip_status=status)
    else:
        # We didn't find anything so offer to add the domain to the database
        print ("Domain not found in the database")
        return render_template('addnew.html', domain=query)

@app.route("/nsdd")
def nameserver_drilldown():

    # Drill down view of a specific name server (e.g. ns1.domain.org)
    # Identify provider, domains that are supported by this NS and the IP
    # of the name server.

    query = request.args.get("ns")

    wc_1_db = db_connect('wc_1')

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

@app.route("/newdoms")
def new_doms():

    newdom = grab_domains('new')
    odddom = grab_domains('odd')

    return render_template("newdoms.html", odddoms=odddom, newdoms=newdom)

@app.route("/summary")
def summary_view():

    # Summary page showing charts of NS Providers and CA Providers (Currently)

    ca_col = db_connect('ca')
    nsp_col = db_connect('nameservers')
    asn_col = db_connect('asns')

    nsp_dict = {}
    ca_dict = {}
    asn_dict = {}
    ns_other = 0
    ca_other = 0
    asn_other = 0

    for ns_document in nsp_col.find():
        del ns_document['_id']
        if ns_document['count'] > 20:
            nsp_dict[ns_document['provider']] = ns_document['count']
        else:
            ns_other = ns_other + ns_document['count']

    nsp_dict['Other'] = ns_other

    for ca_document in ca_col.find():
        del ca_document['_id']
        if ca_document['count'] > 8:
            ca_dict[ca_document['provider']] = ca_document['count']
        else:
            ca_other = ca_other + ca_document['count']

    ca_dict['Other'] = ca_other

    for asn_document in asn_col.find():
        del asn_document['_id']
        if asn_document['count'] > 15:
            asn_dict[asn_document['asn_org']] = asn_document['count']
        else:
            asn_other = asn_other + asn_document['count']

    asn_dict['Other'] = asn_other

    # Create descending sorted dicts

    nsp_dict = OrderedDict(sorted(nsp_dict.items(), key=lambda t: t[1], reverse=True))
    ca_dict = OrderedDict(sorted(ca_dict.items(), key=lambda t: t[1], reverse=True))
    asn_dict = OrderedDict(sorted(asn_dict.items(), key=lambda t: t[1], reverse=True))

    return render_template("summary.html", ns_providers=nsp_dict, ca_providers=ca_dict, asn_providers=asn_dict)


@app.route("/orgdd")
def org_drilldown():

    # Present the organisation Drill Down page. Will show the organisation details, name servers, CA providers etc

    query = request.args.get("org")

    wc_1_db = db_connect('wc_1')

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

    wc_1_db = db_connect('wc_1')

    for document in wc_1_db.find():
        for entry in document['name_servers']:
            if query in entry['ns_provider']:
                result.append(document['domain'])

    return render_template("nspdd.html", domains=list(set(result)), nsp=query)

@app.route("/nssummary")
def ns_summary():

    nsp_col = db_connect('nameservers')

    nsp_list = []

    for ns_document in nsp_col.find():
        del ns_document['_id']
        nsp_list.append(ns_document)

    return render_template("nssummary.html", nsprov=nsp_list)

    # ToDo Also need to add a NS search to the Advanced Search Tab and this can work with the nameserver collection

@app.route("/casummary")
def ca_summary():

    cap_col = db_connect('ca')

    cap_list = []

    for ca_document in cap_col.find():
        del ca_document['_id']
        cap_list.append(ca_document)

    return render_template("casummary.html", caprov=cap_list)

@app.route("/addnew", methods=['GET','POST'])
def add_new():

    new_domain = request.args.get('domain')
    print("Got to here!")
    print (new_domain)
    return json.dumps({'status':'success'})

# Testing for Ajax callback in to Flask to dynamically alter
# Webdata presented in the testing.html page.

@app.route("/add")
def add_domain():

    return render_template("adddomain.html")

@app.route("/change_summary_data/", methods=['POST'])
def change_data():

    #print (request.json['set'])
    #set = request.json['set']
    #print (set)

    data1 = [{'label1': 15}, {'label2': 27}, {'Label3': 4}]
    data2 = [{'label4': '13'}, {'label5': '45'}, {'Label6': '19'}]

    # Check to see what was passed to us via the AJAX request
    # And then return the correct dataset in JSON format

    return jsonify(results = data1)


food = {
        'fruit': ['apple', 'banana', 'cherry'],
        'vegetables': ['onion', 'cucumber'],
        'meat': ['sausage', 'beef']
}

chosen_food = ''


@app.route("/testing")
def testing():

    foody = []

    for item in food:
        foody.append(item)
    return render_template("testing.html", food=foody, test=chosen_food)


@app.route('/get_food/<foodkind>')
def get_food(foodkind):
    chosen_food = foodkind
    print (chosen_food)
    if foodkind not in food:
        return jsonify([])
    else:
        return jsonify(food[foodkind])