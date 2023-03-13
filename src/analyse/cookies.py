import sqlite3
import pandas as pd
pd.set_option('display.max_columns', None)
from pathlib import Path


def read_cookie_jar(p):
    con = sqlite3.connect(p)
    cur = con.cursor()
    res = cur.execute("SELECT name, value, host_key FROM cookies")
    return [t + (p, ) for t in res.fetchall()]


#storages = Path("../../data/raw").glob("*/*/*/Cookies.sqlite")

#cookies = []
#for p in storages:
#    cookies.extend(read_cookie_jar(p))

#cookies = pd.DataFrame(cookies, columns=['name', 'value', 'host', 'path'])
#cookies.to_csv('cookies.csv', index=False)
cookies = pd.read_csv('cookies.csv')
cookies['website'] = cookies['path'].apply(lambda x: Path(x).parent.parent.parent.name)
cookies['is_fp'] = cookies.apply(lambda row: row['website'] in row['host'], axis=1)
filtered = cookies[(cookies.duplicated(subset=['value'], keep=False)) & (
    cookies['value'].str.len() >= 8) & (cookies['is_fp'])]

filtered.to_csv('filtered_cookies.csv', index=False)

counts = {'value': [], 'websites': [], 'hosts': [], 'count(value)': [], 'count(websites)': [], 'count(hosts)': []}
for value in filtered['value'].unique():
    hosts = filtered[filtered['value'] == value]['host'].unique()
    websites = filtered[filtered['value'] == value]['website'].unique()
    counts['value'].append(value)
    counts['websites'].append(websites)
    counts['hosts'].append(hosts)
    counts['count(value)'].append(len(filtered[filtered['value'] == value]))
    counts['count(websites)'].append(len(websites))
    counts['count(hosts)'].append(len(hosts))

counts = pd.DataFrame(counts).sort_values('count(hosts)', ascending=False)
counts.to_csv('counts.csv', index=False)
