# WeatherCentre

This is some rough proof of concept code that aims to help answer questions about how Internet domains are supported. That is to say that given a list of domains, the code will augment these domains with additional information regarding DNS Name Servers, IP and ASN information, and e-mail service providers.

Once collected, the Flask based web service will serve up a number of pages to display the captured data using a variety of charts and drill-down views.
## Usage

The main script for capturing all of the domain data is wc.py. Within this script are a number of functions which can be run to import and then enrich the data with various information elements.

### load_gds_domain_data()

This function will query the UK Government GDS domain registry and pull in all records. It will extract various fields from the returned JSON data (build_gds_base_data()) and then insert it in to a local MongoDB instance in a database called 'wcentre_gov' using a collection called 'all_dom'. Note these are hardcoded currently.

### add_org_type()

This function will enrich the base domain data with organisation information collected from other GDS registries. It will add information relating to the organisation name, it's type (e.g. Local Government etc.) and store it all in the 'all_dom' collection.

### add_ns_data(database)

This function will add DNS Name Server information in to the 'all_dom' collection within the database specificed when the function is called. The function will make a query and capture all NS records for a given domain. It will parse the returned data to identify the provider of the NS infrastructure using a dictionary in resources.py. If a name service provider isn't known, the script will attempt to collect it via the Whoisxmlapi service. Note that the returned entry is not stored for future use. It will also perform an A record lookup for each name server and store all of this in the all_dom collection.

### add_whois_email(database)

As the name suggests, this function will add the registered e-mail address from Whois. It uses the Cisco Investigate API to perform this lookup. Results are stored in the all_dom collection in the database provided. 

### add_ca_details(database)

This function take each domain in the all_dom collection, pre-pend 'www.' to it and then attempt to connect via TCP/443. If the connection is sucesfull, the server certificate is captured and the issuer-name, subject-name are parsed and added to the all_dom collection. 

### add_a_rr(database)

This function performs and 'A' record lookup against the domain (again, prepended with 'www.') and then uses the MaxMind GeoIP2 Lite DB to perform an ASN and Geolocation lookup. All of this is stored back in the all_dom collection inside the database supplied. 

### add_mx_data(database)

Finally, this function augments the domain record in the all_dom collection with the details of any MX records in DNS. Like the Name Server function, this also uses a dictionary in the resources.py file to attempt to match the MX provider to an actual named provider. The IP address if each MX server is also collected. All of the results are added to the all_dom collection. 

### MongoDB Schema (all_dom)

Once all of the above functions have been run, the all_dom collection will have the following schema:
>
`{
    "_id" : ObjectId("5a306be9ce7fa75b5d32ecb8"),
    "domain" : "forest-heath.gov.uk",
    "reg_org" : "local-authority-eng:SED",
    "org-l1" : "Local Government",
    "org-l2" : "Non-metropolitan District",
    "org-name" : "St Edmundsbury Borough Council",
    "name_servers" : [ 
        {
            "ns_provider" : "BT",
            "ns" : "ns0.bt.net.",
            "ns_ip" : "217.35.209.188"
        }, 
        {
            "ns_provider" : "BT",
            "ns" : "ns2.bt.net.",
            "ns_ip" : "217.32.105.90"
        }, 
        {
            "ns_provider" : "BT",
            "ns" : "ns1.bt.net.",
            "ns_ip" : "217.32.105.91"
        }
    ],
    "registrantEmail" : "******@******",
    "ca-issuer" : "Symantec Corporation",
    "asn" : "2856",
    "country" : "United Kingdom",
    "city" : null,
    "a_rr" : "81.145.21.157",
    "asn_org" : "British Telecommunications PLC"
}
`
