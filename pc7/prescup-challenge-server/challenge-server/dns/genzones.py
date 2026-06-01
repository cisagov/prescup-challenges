#!/usr/bin/env python3
import json
import logging
import os
import re
import socket
import time
from collections import defaultdict
import ipaddress
import subprocess
import xml.etree.ElementTree as ET

logging.basicConfig( format='%(asctime)s | %(name)s | %(levelname)s | %(message)s', level=logging.INFO)

LOG = logging.getLogger("genzones")

COREDNS_TEMPLATE = """{zone}.:53 {{
    view {subnet_name} {{
        expr incidr(client_ip(), '{subnet}')
    }}
    header {{
        response set ra
    }}

    file /app/dns/db.{zone}.{subnet_name} {zone}. {{
        fallthrough
    }}

    reload 2s
    log
    errors
}}
"""

CORE_DNS_REVERSE_TEMPLATE = """
10.in-addr.arpa.:53 {{
    view {subnet_name} {{
        expr incidr(client_ip(), '{subnet}')
    }}
    header {{  # Workaround to make nslookup accept our response
        response set ra # set RecursionAvailable flag
    }}

    file /app/dns/db.10.{subnet_name} 10.in-addr.arpa. {{
        
    }}
    reload 2s
    log
    errors
}}
"""

COREDNS_REVERSE = """# Reverse for 10/8 (PTR)
10.in-addr.arpa.:53 {
    header {  # Workaround to make nslookup accept our response
        response set ra # set RecursionAvailable flag
    }

    file /app/dns/db.10 10.in-addr.arpa. {
        
    }
    reload 2s
    log
    errors
}
"""

COREDNS_DEFAULT = """# Anything else: just forward (so this DNS doesn't break general resolution)
.:53 {
    forward . 127.0.0.11
    log
    errors
}
"""

def get_ipv4_networks() -> list[str]:
    # Uses Linux `ip` (best source inside containers/hosts).
    out = subprocess.check_output(["ip", "-j", "addr", "show"], text=True)
    data = json.loads(out)

    nets: set[str] = set()
    for iface in data:
        ifname = iface.get("ifname")
        if ifname == "lo":
            continue
        for a in iface.get("addr_info", []):
            if a.get("family") != "inet":
                continue
            ip = a.get("local")
            plen = a.get("prefixlen")
            if not ip or plen is None:
                continue
            net = ipaddress.ip_interface(f"{ip}/{plen}").network
            # Skip host-only /32s etc if you want; keep as-is by default.
            nets.add(str(net))

    return sorted(nets)

def normalize(name: str | None) -> str:
    if name is None:
        return ""
    base = name.split(".", 1)[0]        # remove domain part
    return re.sub(r"-\d+$", "", base)   # remove trailing -number

def nmap_up_hosts_xml(cidr: list[str]) -> list[dict[str, str | None]]:
    result = subprocess.run(["nmap", "-sn", "-R", "-oX", "-"] + cidr, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"nmap failed for {cidr}: {result.stderr.strip()}")

    root = ET.fromstring(result.stdout)
    hosts: list[dict[str, str | None]] = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        ip_elem = host.find("address[@addrtype='ipv4']")
        if ip_elem is None:
            continue
        ip = ip_elem.get("addr")

        hn_elem = host.find("hostnames/hostname")
        hostname = normalize(hn_elem.get("name")) if hn_elem is not None else ""

        hosts.append({"ip": ip, "hostname": hostname})

    return hosts

def write_atomic(path: str, data: str) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

def wait_for_all(hosts, retries=30, delay=5):
    expected = len(hosts)

    for attempt in range(1, retries + 1):
        result = subprocess.run(
            ["nmap", "-sn", "-oG", "-"] + hosts,
            capture_output=True,
            text=True
        )

        up_count = result.stdout.count("Status: Up")

        if up_count == expected:
            LOG.info("All %d hosts are up", expected)
            return True

        LOG.info("Attempt %d: %d/%d hosts up", attempt, up_count, expected)
        LOG.info("Output: %s ", result.stdout)
        time.sleep(delay)

    LOG.error("Not all hosts came up")
    return False

def ip_in_subnet(ip: str, cidr: str) -> bool:
    return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)

def create_records(hosts, zone, db_forward):
    serial = int(time.time())

    a_records = []

    # A for canonical + aliases (repeat IP)
    for name, result in hosts.items():
        a_records.append(f"{name} 1 IN A {result["ip"]}")
        for alias in result["aliases"]:
            a_records.append(f"{alias} 1 IN A {result["ip"]}")

    forward_lines = []
    forward_lines.append(f"@ 60 IN SOA ns.{zone} hostmaster.{zone} {serial} 60 60 60 60")
    forward_lines.append(f"@ 60 IN NS ns.{zone}")
    forward_lines.append("ns 60 IN A 127.0.0.1")
    for line in sorted(set(a_records)):
        forward_lines.append(line)
        
    write_atomic(db_forward, "\n".join(forward_lines) + "\n")
    LOG.info("Wrote %d records to %s", len(a_records), db_forward)

def create_reverse_records(ptr_map, zone="pccc", db_reverse="/app/dns/db.10"):
    # Reverse zone (10.in-addr.arpa.)
    serial = int(time.time())
    reverse_lines = []
    reverse_lines.append(f"@ 60 IN SOA ns.{zone} hostmaster.{zone} {serial} 60 60 60 60")
    reverse_lines.append(f"@ 60 IN NS ns.{zone}")
    for ip, names in sorted(ptr_map.items()):
        parts = ip.split(".")
        if len(parts) != 4 or parts[0] != "10":
            continue
        _, b, c, d = parts
        owner = f"{d}.{c}.{b}"
        for target in sorted(set(names)):
            reverse_lines.append(f"{owner} 1 IN PTR {target}")
    write_atomic(db_reverse, "\n".join(reverse_lines) + "\n")
    LOG.info("Wrote %d records to %s", len(ptr_map), db_reverse)

def main() -> int:
    hosts_json = os.getenv("HOSTS_JSON")
    if not hosts_json:
        raise RuntimeError("HOSTS_JSON is required")

    zone_dir = os.getenv("COREDNS_DIR", "/app/dns")
    interval = float(os.getenv("DISCOVERY_INTERVAL_SECONDS", "5"))

    db_reverse = os.path.join(zone_dir, "db.10")
    
    os.makedirs(zone_dir, exist_ok=True)

    j = json.loads(hosts_json)
    
    # First, we need to find all of the hosts and wait for them to be up
    hostnames = []
    for zone, hosts in j.items():
        hostnames += [ f"{x["hostname"]}.{zone}" for x in hosts ]
    
    wait_for_all(hostnames)

    # Now that all of the hosts are ready, we use nmap to find ALL of their IP addresses
    nets = get_ipv4_networks()
    logging.info("Found the following subnets: %s", nets)
    results = nmap_up_hosts_xml(nets)
    
    # Next, add all of their identified IPs to the list
    for _, hosts in j.items():
        for host in hosts:
            host["ip"] = [x["ip"] for x in results if x["hostname"] is not None and x["hostname"].endswith(host["container"])]
    
    # Finally, create the "db.zone" files for them
    # There will be one file for each zone and subnet
    #   to make sure the correct IP is provided for each subnet
    for net in nets:
        for zone, hosts in j.items():
            records = {}
            for host in hosts:
                # Set default to first if all subnets should be visible
                found_ip = None
                if os.getenv("DNS_ALL_SUBNETS_VISIBLE", "true").lower() == "true":
                    found_ip = host["ip"][0]
                # Check if there is an IP in this net
                for ip in host["ip"]:
                    if ip_in_subnet(ip, net):
                        found_ip = ip
                        break
                if found_ip is not None:
                    records[host["hostname"]] = {"ip": found_ip, "aliases": host["aliases"]}
            
            # Output the file for this zone and subnet            
            create_records(records, zone, f"/app/dns/db.{zone}.{net.replace("/", "-")}")

    # Reverse records are simpler if DNS_ALL_SUBNETS_VISIBLE is true
    if os.getenv("DNS_ALL_SUBNETS_VISIBLE", "true").lower() == "true":
        records = {}
        for zone, hosts in j.items():
            for host in hosts:
                for ip in host["ip"]:
                    # Note the ending dot, since we don't want these to be relative
                    records[ip] = [f"{host["hostname"]}.{zone}."]
                    for a in host["aliases"]:
                        records[ip].append(f"{a}.{zone}.")
        zone = next(iter(j)) # Just grab the first zone for this
        create_reverse_records(records, zone)
    else:
        # If not true, we need to follow the same pattern as above and create different files for each subnet
        for net in nets:
            records = {}
            for zone, hosts in j.items():
                for host in hosts:
                    for ip in host["ip"]:
                        if not ip_in_subnet(ip, net):
                            continue
                        # Note the ending dot, since we don't want these to be relative
                        records[ip] = [f"{host["hostname"]}.{zone}."]
                        for a in host["aliases"]:
                            records[ip].append(f"{a}.{zone}.")
            zone = next(iter(j)) # Just grab the first zone for this
            create_reverse_records(records, zone, f"/app/dns/db.10.{net.replace("/", "-")}")
    
    
    # With all of the records in place, we just need to create the config for CoreDNS
    config = []
    for net in nets:
        for zone, _ in j.items():
            config.append(COREDNS_TEMPLATE.format(zone=zone, subnet=net, subnet_name=net.replace("/", "-")))
        if os.getenv("DNS_ALL_SUBNETS_VISIBLE", "true").lower() != "true":
            # Add the subnet-specific reverse lookup
            config.append(CORE_DNS_REVERSE_TEMPLATE.format(subnet=net, subnet_name=net.replace("/", "-")))
            
    if os.getenv("DNS_ALL_SUBNETS_VISIBLE", "true").lower() == "true":
        # The default, single reverse file for all subnets
        config.append(COREDNS_REVERSE)
    config.append(COREDNS_DEFAULT)
    write_atomic("/app/dns/Corefile", "\n".join(config) + "\n")

if __name__ == "__main__":
    raise SystemExit(main())
