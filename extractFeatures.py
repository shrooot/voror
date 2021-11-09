from re import match
import requests
from subprocess import *
import ssl
import socket
import tldextract
import datetime
from dateutil.relativedelta import relativedelta
import whois
import favicon
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# Check the length of the URL


def check_url_length(url):
    URL_len = 1
    if(len(url) >= 75):     # Mark it as a phishing attribute
        URL_len = - 1
    elif(len(url) >= 54 and len(url) <= 74):        # Mark it as a suspicious attribute
        URL_len = 0

    return URL_len

# Check if the url is a shortened url and if it is expand the url


def expand_short_url(short_url):
    req = requests.get(short_url, allow_redirects=False)
    complete_url = (req.headers['location'])
    return complete_url


def check_shortened_url(url):
    short_urls = ["bit.ly", "tinyurl.com", "goo.gl", "rebrand.ly",
                  "t.co", "youtu.be", "ow.ly", "w.wiki", "is.gd"]

    domain_of_url = url.split("://")[1]
    domain_of_url = domain_of_url.split("/")[0]
    status = 1
    if domain_of_url in short_urls:     # Check if the url contains one of the commonly used shortening services
        status = -1

    complete_url = None
    if status == -1:
        # If the url is shortened, expand it and return the expanded url
        complete_url = expand_short_url(url)

    return (status, complete_url)

# Check if the URL contains @ symbol


def check_at_symbol(url):
    sus = 1
    idx = url.find("@")

    if idx != -1:
        sus = -1

    return sus

# Check double slash redirection


def check_double_slash_redirect(url):
    idx = url.find("://")
    sliced_url = url[idx+3:]
    sus = 1
    idx = sliced_url.find("//")

    if(idx != -1):      # If there is a // then edit suspicion to -1
        sus = -1
    return sus

# Check for suffixes and prefixes in the url


def check_suffix_prefix(url):
    idx = url.find("://")
    sliced_url = url[idx+3:]
    idx = sliced_url.find("/")
    sliced_url = sliced_url[:idx]
    sus = 1
    idx = sliced_url.find("-")
    if idx != -1:
        sus = -1

    return sus

# Check for sub domains


def check_sub_domains(url):
    url = url.split("://")[1]
    url = url.split("/")[0]
    index = url.find("www.")
    sliced_url = url
    if index != -1:
        sliced_url = url[index+4:]

    index = sliced_url.rfind(".")

    if index != -1:
        sliced_url = sliced_url[:index]

    counter = 0
    for i in sliced_url:
        if i == ".":
            counter += 1

    label = 1
    if counter == 2:
        label = 0
    elif counter >= 3:
        label = -1

    return label

# check_sub_domains("https://yashraj-personal-portfolio.herokuapp.com/")

# Check if the SSL certificate is issued by a valid authority


def check_valid_ssl(url):
    valid_auth = ["Amazon", "GeoTrust", "GoDaddy", "Network Solutions", "Thawte", "Comodo", "Doster", "VeriSign", "LinkedIn", "Sectigo",
                  "Symantec", "DigiCert", "Network Solutions", "RapidSSLonline", "SSL.com", "Entrust Datacard", "Google", "Facebook"]
    check_https = url.find("https://")

    url = url.split("://")[1]
    url = url.split("/")[0]

    hostname = url
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
        s.connect((hostname, 443))
        cert = s.getpeercert()

    issuer = dict(x[0] for x in cert['issuer'])
    issued_by = issuer['commonName']

    sus = -1
    if issued_by in valid_auth and check_https != -1:
        sus = 1

    return sus


# Check the domain registration length

def dregisterlen(u):
    extract_res = tldextract.extract(u)
    ul = extract_res.domain + "." + extract_res.suffix
    try:
        wres = whois.whois(u)
        f = wres["Creation Date"][0]
        s = wres["Registry Expiry Date"][0]
        if(s > f + relativedelta(months=+12)):
            return 1
        else:
            return -1
    except:
        return -1

# Check if the favicons are getting loaded from a different domain


def check_favicon(url):
    extract_res = tldextract.extract(url)
    domain_of_url = extract_res.domain

    favs = favicon.get(url)
    print(favs)
    matches_found = 0
    for favi in favs:
        fav_url = favi.url
        extract_res = tldextract.extract(fav_url)
        extract_fav_url = extract_res.domain
        # print(extract_fav_url)

        # Check if the domain of the url matches the domain of the url where the favicon was fetched from
        if domain_of_url in extract_fav_url:
            matches_found += 1
        # print(matches_found)

    if matches_found >= len(favs)/3:
        return 1
    return -1


# print(check_favicon("https://stackoverflow.com/questions/7334199/getaddrinfo-failed-what-does-that-mean"))

# check for https tokens in the url eg http://https-some-phishing-link.com

def check_https_tokens(url):
    token1 = "https//"
    token2 = "//https"

    idx1 = url.find(token1)
    idx2 = url.find(token2)

    if(idx1 == -1 and idx2 == -1):
        return 1

    else:
        return -1

# To check whether the external objects contained within a webpage such as images, videos and sounds are loaded from another domain


def check_request_URL(url):
    extract_res = tldextract.extract(url)
    domain_of_url = extract_res.domain

    req = requests.get('https://api.hackertarget.com/pagelinks/?q=' + url)
    links_on_page = req.content.decode('utf-8').split("\n")
    count = 0

    for link in links_on_page:
        extract_res = tldextract.extract(link)
        domains_on_page = extract_res.domain
        if domain_of_url not in domains_on_page:
            count += 1

    count /= len(links_on_page)

    if count < 0.22:
        return 1
    elif count < 0.70:
        return 0
    else:
        return -1


# print(check_request_URL("https://stackabuse.com/python-check-if-string-contains-substring/"))


# Checking the anchor tags on the page to be legtimate

def url_validator(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc, result.path])
    except:
        return False


def check_anchor_tags(url):
    extract_res = tldextract.extract(url)
    domain_of_url = extract_res.domain
    html_content = requests.get(url).text

    soup = BeautifulSoup(html_content, 'lxml')
    links = []
    for link in soup.findAll('a'):
        links.append(link['href'])

    if(len(links) == 0):
        return 1

    invalid_hrefs = ['#', '#content', '#skip', 'JavaScript::void(0)']
    sus_level = 0
    # print(links)
    for link in links:

        if link in invalid_hrefs:
            sus_level += 1

        # check if the urls are directing to some other link
        if(url_validator(link)):
            extract_res = tldextract.extract(link)
            anchor_url_domain = extract_res.domain
            # print(anchor_url_domain)
            if domain_of_url not in anchor_url_domain:
                sus_level += 1

    sus_level /= len(links)

    if sus_level < 0.31:
        return 1
    elif sus_level <= 0.67:
        return 0
    return -1


# print(check_anchor_tags("https://stackabuse.com/python-check-if-string-contains-substring/"))


