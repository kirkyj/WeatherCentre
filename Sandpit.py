import urllib3
import urllib3.util
import http.client
import ssl
from OpenSSL import crypto

cert = ssl.get_server_certificate(('sentw.gov.wales', 443))
#print (cert)

new_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
issuer = new_cert.get_issuer()
print (new_cert.get_subject())
print (new_cert.get_pubkey())