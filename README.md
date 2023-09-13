# The Nonce-nce of Web Security: an Investigation of CSP Nonces Reuse

Code to check for CSP nonces reuse  for the paper "The Nonce-nce of Web Security: an Investigation of CSP Nonces Reuse".

## How to run it

- Install the dependencies: `pip install -r requirements.txt`

### On a single website

Run the script: `python3 nonce-nce.py -s <site>`

#### Script arguments

```bash
  -h, --help            show this help message and exit
  -s SITE, --site SITE  Target site
  -m MAX, --max MAX     Maximum number of URLs to crawl (Default: 5) for each domain/subdomain
  -d DOMAINS, --domains DOMAINS
                        Maximum number of (sub)domains to crawl (Default: 10)
  -t TIMEOUT, --timeout TIMEOUT
                        Timeout for http requests (Default: 30)
  -u URL, --url URL     Do not crawl the website, just test the given URL(s)
  -r, --reproducible    Reproducible mode
  --retest              Retest the URLs that were already tested. Warning: this will overwrite the previous results!
  -q, --quiet           Quiet mode
  -D, --debug           Debug mode
```

### On a list of websites

Run the script: `python3 launcher.py --sites <sites_file>`

The launcher will test the websites in the file concurrently (up to the maximum number of concurrent tests).

#### Launcher arguments

```bash
  -h, --help            show this help message and exit
  -s SITES, --sites SITES
                        Sites list
  -m MAX, --max MAX     Maximum number of sites to test concurrently (default: 5)
  -a ARGUMENTS, --arguments ARGUMENTS
                        Additional arguments to pass to the crawler (use with = sign: -a="--arg1 --arg2")
  -t, --testall         Test also already tested sites
  -c CRAWLER, --crawler CRAWLER
                        Alternative crawler script name to launch
  -d, --debug           Enable debug mode
```

## How it works

![Methodology](img/nonce-nce_methodology.png)

*High-level overview of the methodology. Note that this is a simplified version as we also use the Cache Header Heuristics to identify caches*.

## Authors

This code was developed by me and [Francesco Bonomi](https://github.com/Fra-Bo).
