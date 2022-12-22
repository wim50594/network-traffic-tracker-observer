import requests
import json
import time
import pandas as pd

from urllib.parse import urlparse
from utility import write_json, load_json


def batch(iterable, n=1):
    l = len(iterable)
    for ndx in range(0, l, n):
        yield iterable[ndx: min(ndx + n, l)]


def parse_webpages(path):
    with open(path) as f:
        return [url for url in f.read().splitlines()]


#webpages = parse_webpages("lists/crawl/majestic_million.txt")

webpages = ['generatepress.com', 'support.google.com', 'form.jotform.com', 'lh3.googleusercontent.com', 'wireshark.org', 'commons.wikimedia.org', 'widgets.wp.com', 'it.wikipedia.org', 'mp.weixin.qq.com', 'huffingtonpost.co.uk', 'searchenginejournal.com', 'semrush.com', 'aws.amazon.com', 'thebalancemoney.com', 'i.imgur.com',
            'forms.office.com', 'wanwang.aliyun.com', 'auctollo.com', 'scoop.it', 'man7.org', 's3.amazonaws.com', 'ampproject.org', 'ovhcloud.com', 'liveabout.com', 'help.opera.com', 'baike.baidu.com', 'tesla.com', 'accraine.co.uk', 'wetransfer.com', 'apksupply.com', 'cloud.google.com', 'diigo.com', 'msdn.microsoft.com', 'mi.com', 'web.archive.org']

url = "https://api-url.cyren.com/api/v1/free/urls-list"
token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJleHAiOjE2NzA0NTc1OTksImF1ZCI6InVybGZfYXBpX2V2YWwiLCJzdWIiOiJFWU0wT0YwMUExREdQSTBYN1AxRyIsImp0aSI6ImFiYjUzNTdlLTVlYTctMTFlZC05OTdmLTU2NmYxZTAwMDFjMSIsImlzcyI6ImNsbSJ9.Dyw6gX-LoHmqb2rYw36j0P6F-Laky0ntuIXwRQhQXHSFC6ZYnyYGiHIePGVn431yr8LPnWP3aW_dzBo88SLUSqMdZ9SqdbSdQfQ28YuANlZgInPFdr1-4WXwiCvC0l_NQ5W_pJtPGJ_pygT-7UlEly5YLcMHPfBbuXIrqDKBGF5A2HDNRJDGdG69HLNywIs2p_eN8eGc28w3t8OUXEX2e15gmB-KGHndUghOGcGTtejs946SDgGNcrrhOwUDoR9ucQ4pMYnWjXDBid3Vw64Pr36t0CS75hwdBl4CpeAX40UsiUjsBG0_rQxTz_s6bdGMLOT2c2p5bzrPPjPkTVHvoA"

responses = []

for b in batch(webpages, n=100):
    payload = json.dumps({"urls": b})
    headers = {"Authorization": f"Bearer {token}",
               "Content-Type": "application/json"}

    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)
    responses.append(response.json())
    time.sleep(10)

write_json(responses, "categorization.json")
