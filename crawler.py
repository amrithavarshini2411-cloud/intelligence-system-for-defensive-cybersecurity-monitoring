import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin


def crawl(target):

    visited = set()
    urls = []

    try:

        r = requests.get(target, timeout=5)

        soup = BeautifulSoup(r.text, "html.parser")

        for link in soup.find_all("a", href=True):

            full = urljoin(target, link["href"])

            if full not in visited:

                visited.add(full)

                urls.append(full)

    except:
        pass

    return urls