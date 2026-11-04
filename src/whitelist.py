import ipaddress

def is_whitelisted(ip, whitelist):
    ip_obj = ipaddress.ip_address(ip)
    for cidr in whitelist:
        if ip_obj in ipaddress.ip_network(cidr):
            return True
    return False