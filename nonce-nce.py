#!/usr/bin/env python3

__author__ = "Matteo Golinelli, Francesco Bonomi"
__copyright__ = "Copyright (C) 2023 Matteo Golinelli, Francesco Bonomi"
__license__ = "MIT"

from requests.exceptions import SSLError, ConnectionError, ReadTimeout
from urllib3.exceptions import NewConnectionError, MaxRetryError, ReadTimeoutError
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# import from the libs folder

from lib.crawler import Browser, Crawler
from lib.wcde import WCDE

import traceback
import argparse
import logging
import base64
import random
import json
import time
import sys
import os


# =============================================================================
# =============================================================================
# ============================== GLOBAL VARIABLES =============================
# =============================================================================
# =============================================================================

class bcolors:
    HEADER  = '\033[95m'
    OKBLUE  = '\033[94m'
    OKCYAN  = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL    = '\033[91m'
    ENDC    = '\033[0m'
    BOLD    = '\033[1m'
    UNDERLINE = '\033[4m'


# Logging functions
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('nonce-nce')

# Statistics dictionary
statistics = {
    'site':  '',
    'nonce': False,
    'urls':  {}
}

# Headers dictionary
headers = {}

# CONSTANTS
TIMEOUT = 30  # Timeout for http requests
MAX = 5  # Maximum number of URLs to visit for each domain
MAX_DOMAINS = 10  # Maximum number of subdomains to crawl

BLACKLISTED_DOMAINS = [
    'doubleclick.net', 'googleadservices.com',
    'google-analytics.com', 'googletagmanager.com',
    'googletagservices.com', 'googleapis.com',
    'googlesyndication.com', 'analytics.ticktok.com',
    'gstatic.com',
]


# =============================================================================
# =============================================================================
# ================================= FUNCTIONS =================================
# =============================================================================
# =============================================================================

# =============================================================================
# ============================== CSP functions ================================
# =============================================================================

def get_nonce(html):
    """
    Return the nonce found in the html.
    Return None if no nonce is found.
    """
    soup = BeautifulSoup(html, 'html.parser')
    found = soup.find('script', {"nonce": True})

    if found is not None and found['nonce'] != '':
        return found['nonce']
    else:
        return None


def get_meta_csp(html):
    """
    Return the CSP found in the meta tag.
    Return None if no CSP is found.
    """
    soup = BeautifulSoup(html, 'html.parser')
    found = soup.find('meta', attrs={'http-equiv': 'Content-Security-Policy'})

    if found is not None:
        return found['content']
    else:
        return None


# =============================================================================
# ============================= Helper functions ==============================
# =============================================================================

def clean_url(url):
    """
    Cleans the url to remove any trailing newlines and spaces.
    """
    return url.strip().strip('\n')


def save_dictionaries(site, crawler):
    """
    Save the dictionaries to the files.
    """
    global statistics, visited_urls, queue, headers

    logs = {
        'queue':   crawler.queue,
        'visited': crawler.visited_urls
    }

    with open(f'logs/{site}-logs.json', 'w') as f:
        json.dump(logs, f, indent=4)
    with open(f'stats/{site}-stats.json', 'w') as f:
        json.dump(statistics, f, indent=4)
    with open(f'headers/{site}-headers.json', 'w') as f:
        json.dump(headers, f, indent=4)


def get_dictionaries(site, crawler):
    """
    Load the dictionaries from the files.
    """
    global statistics, visited_urls, queue, headers

    try:

        if os.path.exists(f'logs/{site}-logs.json'):
            with open(f'logs/{site}-logs.json', 'r') as f:
                logs = json.load(f)
                queue = logs['queue']
                visited_urls = logs['visited']

                crawler.set_visited_urls(visited_urls)
                crawler.set_queue(queue)
    except Exception as e:
        logging.error(e)

    try:
        if os.path.exists(f'stats/{site}-stats.json'):
            with open(f'stats/{site}-stats.json', 'r') as f:
                statistics = json.load(f)
        if os.path.exists(f'headers/{site}-headers.json'):
            with open(f'headers/{site}-headers.json') as f:
                headers = json.load(f)
    except Exception as e:
        pass


def save_html(site, html, url, template_url):
    """
    Save html to a file.
    """
    # Replace characters '/' with '-' to ensure legal file names
    legal_template_url = str.replace(template_url, '/', '_')

    soup = BeautifulSoup(html, 'html.parser')
    prettyHTML = soup.prettify()  # Prettify the html

    # Create folder for site if it doesn't exists
    legal_folder_name = str.replace(site, '/', '_')
    if not os.path.exists(f'html/{legal_folder_name}'):
        os.mkdir(f'html/{legal_folder_name}')

    # Save html file
    with open(f'html/{legal_folder_name}/{legal_template_url}.html', 'w') as f:
        f.write(f'<!-- {url} {template_url} -->\n\n')
        f.write(prettyHTML)


def is_base_64(s):
    """
    Check if the string is base64 encoded.
    """
    try:
        # Add padding if missing
        # (base64 encoded strings have a length multiple of 4)
        if len(s) % 4 != 0:
            s += '=' * (4 - len(s) % 4)

        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False


# =============================================================================
# =============================================================================
# =================================== MAIN ====================================
# =============================================================================
# =============================================================================

def main():
    # Create folder if they dont'exist
    if not os.path.exists('logs'):
        os.mkdir('logs')
    if not os.path.exists('stats'):
        os.mkdir('stats')
    if not os.path.exists('html'):
        os.mkdir('html')
    if not os.path.exists('headers'):
        os.mkdir('headers')

    # Arguments parsing
    parser = argparse.ArgumentParser(prog='nonce-nce.py',
                                     description='Investigate CSP Nonces Reuse')

    parser.add_argument('-s', '--site',  required=True,
                        help='Target site')

    parser.add_argument('-m', '--max',   default=MAX,
                        help=f'Maximum number of URLs to crawl (Default: {MAX}) for each domain/subdomain')

    parser.add_argument('-d', '--domains', default=MAX_DOMAINS,
                        help=f'Maximum number of (sub)domains to crawl (Default: {MAX_DOMAINS})')

    parser.add_argument('-t', '--timeout', default=TIMEOUT,
                        help=f'Timeout for http requests (Default: {TIMEOUT})')

    parser.add_argument('-u', '--url',
                        help='Do not crawl the website, just test the given URL(s)')

    parser.add_argument('-r', '--reproducible', action='store_true',
                        help='Reproducible mode')

    parser.add_argument('--retest', action='store_true',
                        help='Retest the URLs that were already tested. Warning: this will overwrite the previous results!')

    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode')
    parser.add_argument('-D', '--debug', action='store_true', help='Debug mode')

    args = parser.parse_args()

    # Logging configuration
    if args.quiet:
        logger.setLevel(logging.ERROR)
    if args.debug:
        logger.setLevel(logging.DEBUG)

    if args.reproducible:
        random.seed(42)

    urls_to_test = []
    if args.url:
        for url in args.url.split(','):
            if url not in list(urls_to_test.values()):
                if 'https://' not in url and 'http://' not in url:
                    url = 'https://' + url
                urls_to_test.append(url)

        if args.site:
            site = (
                args.site
                .strip()
                .lower()
                .replace('http://',  '')
                .replace('https://', '')
                .replace('www.',    '')
            )
        else:
            site = urlparse(urls_to_test[0]).netloc.replace('www.', '')
    else:
        if args.site is None:
            logger.error(f'Target site not specified!')
            exit(1)
        site = (
            args.site
            .strip()
            .lower()
            .replace('http://',  '')
            .replace('https://', '')
            .replace('www.', '')
        )

    statistics['site'] = site

    USER_AGENT = f'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/117.0.{random.randint(1, 50)}'
    _headers = {
        'User-Agent': USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'DNT': '1',
        'Sec-GPC': '1'
    }

    crawler = Crawler(site=site, max=int(args.max), max_domains=int(args.domains))
    browser = Browser(headers=_headers)
    wcde = WCDE()

    try:
        # Get dictionaries from the files
        if not args.retest:
            get_dictionaries(site, crawler)
        if args.url:
            for url in urls_to_test:
                crawler.add_to_queue(url)
        else:
            crawler.add_to_queue(f'https://{site}')
            crawler.add_to_queue(f'https://www.{site}')
            crawler.add_to_queue(f'http://{site}')
            crawler.add_to_queue(f'http://www.{site}')
        # Crawl the website
        while crawler.should_continue():
            url = crawler.get_url_from_queue()
            if url is None:
                break
            else:
                logger.info(f'Visiting {url}')

                response_1 = browser.get(url, allow_redirects=True, timeout=TIMEOUT)
                try:
                    if crawler.get_domain(url).split('.')[-2] not in crawler.get_domain(response_1.url):
                        logger.info(f'URL redirected to another domain, skipping...')
                        continue
                except Exception as e:
                    pass
                crawler.add_to_visited(url)

                # Search for CSP headers
                csp = ''
                csp_report_only = ''
                for header in response_1.headers:
                    if header.lower() == 'content-security-policy':
                        csp = response_1.headers[header]
                    elif header.lower() == 'content-security-policy-report-only':
                        csp_report_only = response_1.headers[header]

                # Search for CSP meta tagu
                csp_meta = get_meta_csp(response_1.text)

                statistics['urls'][url] = {
                    "csp": csp,
                    "csp-report-only": csp_report_only,
                    "csp_meta": csp_meta if csp_meta else "",
                }

                # Check if it contains a CSP nonce, update statistics accordingly
                nonce_found = get_nonce(response_1.text)
                if nonce_found is not None:
                    logger.info(f'Nonce found! ({bcolors.OKGREEN}{nonce_found}{bcolors.ENDC})')
                    statistics['nonce'] = True

                    statistics['urls'][url]["nonces"] = [nonce_found]
                    statistics['urls'][url]['length'] = len(nonce_found)
                    statistics['urls'][url]['base64'] = is_base_64(nonce_found)
                    statistics['urls'][url]['reused'] = False

                    time.sleep(1)  # Wait a second before a new request

                    # Check if the nonce is reused
                    response_2 = browser.get(url, allow_redirects=True, timeout=TIMEOUT)
                    response_html_2 = response_2.text
                    nonce_found_2 = get_nonce(response_html_2)

                    if nonce_found_2 is not None:
                        if nonce_found == nonce_found_2:
                            logger.info(f'Nonce is reused! ({bcolors.FAIL}{nonce_found_2}{bcolors.ENDC})')
                            statistics['urls'][url]['nonces'].append(nonce_found_2)
                            statistics['urls'][url]['reused'] = True

                            # Use the Cache Headers Heuristic to check if the response is coming from the cache
                            cache_status_2 = wcde.cache_headers_heuristics(response_2.headers)
                            statistics['urls'][url]['chh'] = cache_status_2

                            time.sleep(1)  # Wait a second before a new request

                            # Add query parameter to the URL to cache-bust the request
                            parsed = urlparse(url)
                            query = parsed.query
                            if query:
                                query += '&'
                            query += 'cachebuster=true'
                            modified_url = f'{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}'
                            response_3 = browser.get(modified_url, allow_redirects=True, timeout=TIMEOUT)
                            response_html_3 = response_3.text
                            nonce_found_3 = get_nonce(response_html_3)

                            if nonce_found_3 is not None:
                                if nonce_found == nonce_found_3:
                                    logger.info(f'Nonce is reused even with a new query parameter! ({bcolors.FAIL}{nonce_found_3}{bcolors.ENDC})')
                                    statistics['urls'][url]['nonces'].append(nonce_found_3)
                                    statistics['urls'][url]['reused_query'] = True

                                    # Use the Cache Headers Heuristic to check if the response is coming from the cache
                                    cache_status_3 = wcde.cache_headers_heuristics(response_3.headers)
                                    statistics['urls'][url]['chh'] = cache_status_2
                                else:
                                    logger.info(f'Nonce is NOT reused with a new query parameter! ({nonce_found_3})')
                                    statistics['urls'][url]['reused_query'] = False
                            else:
                                statistics['urls'][url]['reused_query'] = False

                            # Use a clean browser to check if the nonce is reused in a new session
                            response_4 = Browser().get(url, allow_redirects=True, timeout=TIMEOUT)
                            response_html_4 = response_4.text
                            nonce_found_4 = get_nonce(response_html_4)

                            if nonce_found_4 is not None:
                                if nonce_found == nonce_found_4:
                                    logger.info(f'Nonce is reused even with a new session! ({bcolors.FAIL}{nonce_found_4}{bcolors.ENDC})')
                                    statistics['urls'][url]['nonces'].append(nonce_found_4)
                                    statistics['urls'][url]['reused_session'] = True
                                else:
                                    logger.info(f'Nonce is NOT reused with a new session! ({nonce_found_4})')
                                    statistics['urls'][url]['reused_session'] = False
                            else:
                                statistics['urls'][url]['reused_session'] = False

                        else:
                            logger.info(f'Nonce is NOT reused! ({nonce_found_2})')
                            statistics['urls'][url]['reused'] = False
                            statistics['urls'][url]['nonces'].append(nonce_found_2)

                    # Save the page to a file
                    save_html(site, response_1.text, url, crawler.get_template_url(url))

                    # Dump the headers to a file
                    headers[url] = [dict(response_1.headers), dict(response_2.headers)]
                else:
                    logger.info(f'Nonce NOT found!')

                links = crawler.get_links(response_1.url, response_1.text)
                for link in links:
                    crawler.add_to_queue(link)

    except SystemExit as e:
        sys.exit(e)
    except (SSLError, NewConnectionError, MaxRetryError, ConnectionError, ReadTimeoutError, ReadTimeout):
        logger.error(f'{site} timed out')
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info(f'Interrupted, exiting...')
        sys.exit(0)
    except Exception as e:
        logger.error(traceback.format_exc())
        sys.exit(1)
    finally:
        save_dictionaries(site, crawler)
        logger.info(f'All done!')
        sys.exit(0)

if __name__ == '__main__':
    main()
