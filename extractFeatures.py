import requests
from subprocess import *
import ssl
import socket
from requests.adapters import Response
import tldextract
import datetime
from dateutil.relativedelta import relativedelta
import whois
import favicon
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import urllib.request
import string
import numpy as np
import pickle


# Check if the url has a ip address in it

def check_ip_in_url(url):

    idx = url.find("://")
    sliced_url = url[idx+3:]

    idx = sliced_url.find("/")
    sliced_url = sliced_url[:idx]

    sliced_url = sliced_url.replace(".", "")

    counter_hex = 0
    for i in sliced_url:
        if i in string.hexdigits:
            counter_hex += 1

    total_len = len(sliced_url)
    having_IP_Address = 1
    if counter_hex >= total_len:
        having_IP_Address = -1

    return having_IP_Address

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
    sus = -1
    try:    
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.connect((hostname, 443))
            cert = s.getpeercert()

        issuer = dict(x[0] for x in cert['issuer'])
        issued_by = issuer['commonName']

        if issued_by in valid_auth and check_https != -1:
            sus = 1

        return sus
    except:
        return 0

# Check the domain registration length

def check_domain_reg_len(u):
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
    try:
        favs = favicon.get(url)
        # print(favs)
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
    except:
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
    try:
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
    except:
        return -1

# print(check_anchor_tags("https://stackabuse.com/python-check-if-string-contains-substring/"))


# Checking for phishing links in meta script and link tags

def check_links_in_tags(url):
    try:
        extract_res = tldextract.extract(url)
        domain_of_url = extract_res.domain
        html_content = requests.get(url).text

        soup = BeautifulSoup(html_content, 'lxml')
        meta_tags = soup.findAll('Meta')
        script_tags = soup.findAll('Script')
        link_tags = soup.findAll('Links')
        meta_count = 0
        for m in meta_tags:
            meta = (m['href'])
            extract_res = tldextract.extract(meta)
            link_url_domain = extract_res.domain

            if domain_of_url not in link_url_domain:
                meta_count += 1

        script_count = 0
        for s in script_tags:
            script = (s['href'])
            extract_res = tldextract.extract(script)
            link_url_domain = extract_res.domain

            if domain_of_url not in link_url_domain:
                script_count += 1

        link_count = 0
        for l in link_tags:
            link = (l['href'])
            extract_res = tldextract.extract(link)
            link_url_domain = extract_res.domain

            if domain_of_url not in link_url_domain:
                link_count += 1

        l = 0
        s = 0
        m = 0

        if (len(meta_tags) != 0):
            m = meta_count*100//len(meta_tags)

        if (len(script_tags) != 0):
            s = script_count*100//len(script_tags)

        if (len(link_tags) != 0):
            l = link_count*100//len(link_tags)

        if (l + m + s < 17):
            return 1

        elif(l + m + s < 81):
            return 0

        return -1
    except:
        return -1

# Check the Server Form Handlers for about set to blank or null

def check_sfh(url):
    try:
        html_content = requests.get(url).text
        soup = BeautifulSoup(html_content, 'lxml')
        forms = soup.findAll('form')
        # print(forms[0]['action'])
        if(len(forms) == 0):
            return 1
        try:
            action = forms[0]['action']
            if(action == "" or action == "about:blank"):
                return -1
            if(action[0] == "/"):
                return 1

            extract_res = tldextract.extract(url)
            domain_of_page = extract_res.domain

            extract_res = tldextract.extract(action)
            domain_of_action = extract_res.domain
            if(domain_of_page) in domain_of_action:
                return 1
            return 0

        except:
            return 1
    except:
        return -1

# print(check_sfh("https://login.mailchimp.com/signup/"))


# Check if the web form ask for email using mail() or mailto:

def check_submitting_emails(url):
    try:
        html_content = requests.get(url).text
        soup = BeautifulSoup(html_content, 'lxml')

        form = str(soup.find('form'))
        if(form == None):
            return 1

        idx = form.find("mail()")
        if(idx == -1):
            idx = form.find("mailto:")

        if(idx == -1):
            return 1

        return -1
    except:
        return -1
# print(check_submitting_emails("https://login.mailchimp.com/signup/"))

# Check  redirects


def check_redirects(url):
    try:
        req = requests.get(url)
        hist = req.history
        final_url = url
        if(len(hist) > 0):
            final_url = str(hist[-1].url)
        if(len(hist) <= 1):
            return (1, final_url)

        if(len(hist) >= 2 and len(hist) < 4):
            return (0, final_url)

        return (-1, final_url)

    # If there is a connection error it is mostly likely a phishing link
    except requests.exceptions.ConnectionError:
        return (0, url)


# print(check_redirects("https://bit.ly/3odrkvN"))

# Check if the on mouse over the status changes

def check_for_mouseover(url):
    try:
        html_content = requests.get(url).text
    except:
        return -1
    soup = BeautifulSoup(html_content, "lxml")
    if str(soup).lower().find('onmouseover="window.status') != -1:
        return -1
    return 1


# Check is the website has disabled right click event

def check_right_click(url):
    try:
        html_content = requests.get(url).text
    except:
        return -1

    soup = BeautifulSoup(html_content, "lxml")
    if str(soup).lower().find("preventdefault()") != -1:
        return -1
    elif str(soup).lower().find("event.button==2") != -1:
        return -1
    elif str(soup).lower().find("event.button == 2") != -1:
        return -1
    elif str(soup).lower().find("event.button== 2") != -1:
        return -1
    elif str(soup).lower().find("event.button ==2") != -1:
        return -1

    return 1

# Check for iframe tags


def check_iframe_tags(url):
    try:
        html_content = requests.get(url).text
    except:
        return -1

    soup = BeautifulSoup(html_content, "lxml")
    iframe = soup.iframe
    if(iframe == None):
        return 1

    iframe = str(soup.iframe).lower()
    if(iframe.find("frameborder") == -1):
        return 1

    return -1

# print(check_iframe_tags("https://archive.ics.uci.edu/ml/machine-learning-databases/00327/"))

# Check the domain age of the url


def check_domain_age(url):
    try:
        whois_res = whois.whois(url)
        # print(whois_res)
        if datetime.datetime.now() > whois_res["creation_date"] + relativedelta(months=+6):
            return 1
        else:
            return -1
    except:
        return -1

# print(check_domain_age("https://gdsc-woc.tech/"))

# Check the DNS record for the url (if it is present in the WHOIS database)


def check_dns_record(url):
    try:
        whois_result = whois.whois(url)
        return 1
    except:
        return -1


# Check the alexa rank of the url (to check the traffic of the website)

def check_web_traffic(url):
    extract_res = tldextract.extract(url)
    url_ref = extract_res.domain + "." + extract_res.suffix

    try:
        alexa_rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" +
                                                          url_ref).read(), "xml").find("REACH")['RANK']

        if(int(alexa_rank) < 150000):
            return 1
        return 0
    except:
        return -1


# print(check_web_traffic("http://gdsc-woc.tech"))

# Check the pagerank of the url

def check_pagerank(url):
    API_KEY = "4cwokgc4008cck8g4wss8g0gk4wokwc8wgoc0sok"
    extract_res = tldextract.extract(url)
    url_ref = extract_res.domain + "." + extract_res.suffix
    headers = {'API-OPR': API_KEY}
    req_url = "https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D=" + url_ref
    # print(req_url)
    try:
        req = requests.get(req_url, headers=headers)
        rank = req.json()['response'][0]['page_rank_decimal']
        # print(rank)
        if type(rank) == str:
            rank = 0

        if rank < 2:
            return -1
        return 1
    except:
        return -1
# check_pagerank("https://www.instagram.com/conficker_exe/")


def check_statistical_report(u):
    extract_res = tldextract.extract(u)
    url_ref = extract_res.domain + "." + extract_res.suffix
    ipquality_url = "https://ipqualityscore.com/api/json/url/T0jAvUi65fqY9B8agy4iLs2EYhxEFR7f/" + url_ref

    try:
        result = requests.get(ipquality_url)
        risk_score = result.json()['risk_score']
        if(int(risk_score) > 50):
            return - 1
    except:
        return -1

    return 1


def convertEncodingToPositive(data):
    mapping = {-1: 2, 0: 0, 1: 1}
    i = 0
    for col in data:
        data[i] = mapping[col]
        i += 1
    return data


def get_features_for_model(url):
    extracted_features = [0]*25
    short_url_status, expanded_url = check_shortened_url(url)
    extracted_features[2] = short_url_status

    redirect_url_status, redirect_url = check_redirects(url)
    extracted_features[16] = redirect_url_status

    if expanded_url is not None:
        if len(expanded_url) >= len(url):
            url = expanded_url

    if redirect_url is not None:
        if len(redirect_url) > len(url):
            url = redirect_url

    extracted_features[0] = check_ip_in_url(url)
    extracted_features[1] = check_url_length(url)
    extracted_features[3] = check_at_symbol(url)
    extracted_features[4] = check_double_slash_redirect(url)
    extracted_features[5] = check_suffix_prefix(url)
    extracted_features[6] = check_sub_domains(url)
    extracted_features[7] = check_valid_ssl(url)
    extracted_features[8] = check_domain_reg_len(url)
    extracted_features[9] = check_favicon(url)
    extracted_features[10] = check_https_tokens(url)
    extracted_features[11] = check_request_URL(url)
    extracted_features[12] = check_anchor_tags(url)
    extracted_features[13] = check_links_in_tags(url)
    extracted_features[14] = check_sfh(url)
    extracted_features[15] = check_submitting_emails(url)
    extracted_features[17] = check_for_mouseover(url)
    extracted_features[18] = check_right_click(url)
    extracted_features[19] = check_iframe_tags(url)
    extracted_features[20] = check_domain_age(url)
    extracted_features[21] = check_dns_record(url)
    extracted_features[22] = check_web_traffic(url)
    extracted_features[23] = check_pagerank(url)
    extracted_features[24] = check_statistical_report(url)

    return extracted_features

# get_features_for_model("https://olx-pl.secure-buy.site")

def get_prediction(url):
    features = get_features_for_model(url)
    features = convertEncodingToPositive(features)
    print(features)
    transformed_features = np.array(features).reshape(1,-1)
    print(transformed_features)
    model = pickle.load(open("./Models/SVM_MODEL", "rb"))
    status = model.predict(transformed_features)
    return status

# if __name__ == "__main__":
#     print(get_prediction("https://olx-pl.secure-buy.site"))
#     # print(get_prediction("https://music.amazon.in/"))
#     # print("\n")