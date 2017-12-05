import dns.resolver
import requests
import json
import resources
import ssl
from OpenSSL import crypto
import socket
from collections import OrderedDict, Counter


class domain:

    ns_data = []
    mx_data = []
    cdn_data = ''
    web_ca_issuer = ''
    web_ca_cn = ''
    mail_ca_issuer = ''

    def __init__(self, name):
        self.name = name
        self.nameservers()
        self.web_ca_providers()

    def ns(self):
        return ns_data

    def nameservers(self):
        # Grab the name server details for the domain
        #
        result = []

        ns = do_query(self.name + '.gov.uk', 'NS')
        if 'NXDOMAIN' in ns or 'NoAnswer' in ns:
            print('Domain', self.name, "doesn't exist")
        else:
            for server in ns:
                self.ns_data.append(
                    {"ns": str(server), "ns_provider": parse_ns(str(server)), "ns_ip": str(do_query(str(server), 'A'))})

        return self.ns_data

    #def mailservers(self):
        # Grab the mail server details for the domain

    def web_ca_providers(self):
        # Grab the CA provider details

        target = 'www.' + self.name + '.gov.uk'

        try:

            sock = socket.create_connection((target, 443), timeout=2)

            cert = ssl.get_server_certificate((target, 443))
            sock.close()
            new_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
            issuer = new_cert.get_issuer()
            subject = new_cert.get_subject()

            for component in issuer.get_components():
                if component[0] == b'O':
                    self.web_ca_issuer = str(component[1], 'utf-8')

            for component in subject.get_components():
                if component[0] == b'CN':
                    self.web_ca_cn = str(component[1], 'utf-8')

        except socket.error:
            print("Socket Error")


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