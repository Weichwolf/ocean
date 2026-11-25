#!/usr/bin/env python3
"""Record logical requests and individual attempts from outside the workload network."""

import argparse
import http.client
import json
import re
import socket
import ssl
import time


def attempt(host, address, context, method, path, timeout):
    connection = http.client.HTTPSConnection(host, context=context, timeout=timeout)
    if address:
        connection._create_connection = lambda dest, wait, source: socket.create_connection((address, dest[1]), wait, source)
    try:
        connection.request(method, path)
        with connection.getresponse() as response:
            body = response.read(4096).decode(errors="replace").strip()
            instance = body if response.status == 200 and re.fullmatch(r"[a-zA-Z0-9-]{4,64}", body) else None
            return str(response.status), instance
    except (OSError, http.client.HTTPException) as error:
        return type(error).__name__, None
    finally:
        connection.close()


def drive(host, address, ca, duration, burn, retry):
    context = ssl.create_default_context(cafile=ca)
    start = time.monotonic()
    requests = []
    while time.monotonic() - start < duration:
        began = time.monotonic()
        key = {"offsetMs": round((began-start)*1000), "attempts": []}
        for index in range(retry):
            remaining = 8 - (time.monotonic() - began)
            if remaining <= 0:
                break
            sent = time.monotonic()
            status, instance = attempt(host, address, context, "POST" if burn else "GET",
                                       "/cgi-bin/load" if burn else "/", min(1.8, remaining))
            key["attempts"].append({"status": status, "durationMs": round((time.monotonic()-sent)*1000)})
            if instance:
                key["instance"] = instance
                break
            if index < retry - 1:
                time.sleep(0.35)
        key["durationMs"] = round((time.monotonic()-began)*1000)
        requests.append(key)
        time.sleep(0.2)
    return requests


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--address")
    parser.add_argument("--ca", required=True)
    parser.add_argument("--duration", type=float, required=True)
    parser.add_argument("--burn", action="store_true")
    parser.add_argument("--retries", type=int, default=4)
    args = parser.parse_args()
    print(json.dumps(drive(args.host, args.address, args.ca, args.duration, args.burn, args.retries)))


if __name__ == "__main__":
    main()
