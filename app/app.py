#!/usr/bin/env python3
import argparse
from cachetools import LRUCache
from sanic import Sanic
from sanic.response import json
from prometheus_client import Gauge
from sanic_prometheus import monitor
from scapy.all import AsyncSniffer, DNS

parser = argparse.ArgumentParser(
    prog="DNS sniffer",
    description="Record DNS responses and build up reverse lookup table")
parser.add_argument("-f", "--filter",
    default="inbound and port 53",
    help="Specify packet capture filter")
parser.add_argument("-i", "--interface",
    help="Specify interace for capturing packets")
parser.add_argument("-v", "--verbose",
    action="store_true",
    help="Log recorded responses")
args = parser.parse_args()

gauge_reverse_records = Gauge("dns_sniffer_record_count",
    "Reverse lookup table record count")

reverse_lookup = LRUCache(maxsize=10000)

app = Sanic("dns-sniffer")


@app.get("/export")
async def reverse_lookup_table(request):
    return json(dict(reverse_lookup))


def process_packet(p):
    if not p.haslayer(DNS):
        return
    a_count = p[DNS].ancount
    i = a_count + 4
    while i > 4:
        try:
            answer, query, answer_type = p[0][i].rdata, p[0][i].rrname, p[0][i].type
        except AttributeError:
            continue
        i -= 1
        if answer_type != 1:
            continue
        hostname = query.decode("ascii").lower().rstrip(".")
        if hostname.endswith(".local"):
            continue
        if args.verbose:
            print("%s: %s" % (answer, hostname))
        reverse_lookup[answer] = hostname
        gauge_reverse_records.set(len(reverse_lookup))


@app.listener("before_server_start")
async def setup_db(app, loop):
    AsyncSniffer(prn=process_packet, filter=args.filter, store=False,
        iface=args.interface).start()


if __name__ == "__main__":
    monitor(app).expose_endpoint()
    app.run(host="0.0.0.0", port=3001, single_process=True, motd=False)
