import requests
import concurrent.futures
import socket
import json
import time
from typing import Optional, List, Dict, Any


def get_pub_ip(timeout: float = 1.0) -> Optional[str]:
    import requests, concurrent.futures, re, json

    services = [
        # 国内优先
        "http://pv.sohu.com/cityjson?ie=utf-8",   # sohu
        "http://ip.360.cn/IPShare/info",          # 360
        "http://ip.cn/api/index?ip=&type=0",      # ip.cn
        "https://api.ip.sb/ip",                   # ip.sb (国内CDN)

        # 国外 Anycast
        "https://1.1.1.1/cdn-cgi/trace",          # Cloudflare
        "https://checkip.amazonaws.com",          # AWS
        "https://whatismyip.akamai.com/",         # Akamai
        "https://api.ipify.org",                  # ipify
    ]

    def fetch_ip(url: str) -> Optional[str]:
        try:
            resp = requests.get(url, timeout=timeout)
            text = resp.text.strip()

            # 特殊解析
            if "cip" in text and "cname" in text:  # sohu
                m = re.search(r'"cip":\s*"([0-9.]+)"', text)
                return m.group(1) if m else None
            elif text.startswith("{") and "360" in url:  # 360
                return resp.json().get("ip")
            elif "ip.cn" in url and text.startswith("{"):  # ip.cn
                return resp.json().get("ip")
            elif "ip=" in text:  # Cloudflare trace
                for line in text.splitlines():
                    if line.startswith("ip="):
                        return line.split("=", 1)[1].strip()
            return text if _is_valid_ip(text) else None
        except:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(services)) as executor:
        futures = [executor.submit(fetch_ip, url) for url in services]
        for future in concurrent.futures.as_completed(futures, timeout=timeout + 0.5):
            ip = future.result()
            if ip:
                return ip
    return None



def get_pub_ip_detail(timeout: float = 0.5) -> Optional[Dict[str, Any]]:
    """使用返回JSON数据的服务，获取更详细信息"""
    json_services = [
        "https://ipapi.co/json",
        "https://ipinfo.io/json",
        "https://api.ipgeolocation.io/ipgeo?apiKey=free",
        "https://freegeoip.app/json/",
        "https://ip-api.com/json",
        "https://api.bigdatacloud.net/data/client-ip",
        "https://geolocation-db.com/json/",
        "https://api.techniknews.net/ipgeo/",
    ]

    def fetch_json_data(url: str) -> Optional[Dict]:
        try:
            response = requests.get(url, timeout=timeout)
            data = response.json()

            # 标准化不同服务的字段名
            ip_fields = ['ip', 'query', 'ipAddress', 'IPv4']
            for field in ip_fields:
                if field in data and _is_valid_ip(str(data[field])):
                    return data
            return None

        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        future_to_url = {executor.submit(fetch_json_data, url): url for url in json_services}

        try:
            for future in concurrent.futures.as_completed(future_to_url, timeout=timeout + 1):
                result = future.result()
                if result:
                    for f in future_to_url:
                        f.cancel()
                    return result
        except concurrent.futures.TimeoutError:
            pass

    return None


def get_ip_by_dns() -> Optional[str]:
    """通过DNS查询获取公网IP"""
    try:
        # 方法1: 查询OpenDNS
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['208.67.222.222', '208.67.220.220']  # OpenDNS

        result = resolver.resolve('myip.opendns.com', 'A')
        return str(result[0])
    except ImportError:
        # 如果没有安装dnspython，使用socket方法
        pass
    except Exception:
        pass

    try:
        # 方法2: 通过UDP连接获取本地对外IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]

            # 检查是否为公网IP
            if not _is_private_ip(local_ip):
                return local_ip
    except Exception:
        pass

    return None


def get_pub_ip_stun_method() -> Optional[str]:
    """使用STUN协议获取公网IP"""
    try:
        import stun
        nat_type, external_ip, external_port = stun.get_ip_info()
        return external_ip
    except ImportError:
        print("需要安装pystun: pip install pystun")
    except Exception:
        pass

    return None


def get_pub_ip_upnp_method() -> Optional[str]:
    """通过UPnP获取外网IP (需要路由器支持)"""
    try:
        import upnpclient
        devices = upnpclient.discover()

        for device in devices:
            if 'WANIPConnection' in str(device.services):
                wan_service = device['WANIPConnection']
                return wan_service.GetExternalIPAddress()['NewExternalIPAddress']
    except ImportError:
        print("需要安装upnpclient: pip install upnpclient")
    except Exception:
        pass

    return None


def _is_valid_ip(ip: str) -> bool:
    """验证IP地址格式"""
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            if not (0 <= int(part) <= 255):
                return False
        return True
    except:
        return False


def _is_private_ip(ip: str) -> bool:
    """检查是否为私有IP"""
    try:
        parts = [int(x) for x in ip.split('.')]
        # 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        return (parts[0] == 10 or
                (parts[0] == 172 and 16 <= parts[1] <= 31) or
                (parts[0] == 192 and parts[1] == 168) or
                parts[0] == 127)  # localhost
    except:
        return False


def get_public_ip_compare(timeout: float = 0.5) -> Dict[str, Any]:
    """综合多种方法获取公网IP"""
    methods = {
        'get_pub_ip': lambda: get_pub_ip(timeout),
        'get_pub_ip_detail': lambda: get_pub_ip_detail(timeout),
        'get_ip_by_dns': get_ip_by_dns,
        'get_pub_ip_stun_method': get_pub_ip_stun_method,
        'get_pub_ip_upnp_method': get_pub_ip_upnp_method,
    }

    results = {}

    for method_name, method_func in methods.items():
        try:
            start_time = time.time()
            result = method_func()
            end_time = time.time()

            if result:
                if isinstance(result, dict):
                    # JSON服务返回详细信息
                    ip_fields = ['ip', 'query', 'ipAddress', 'IPv4']
                    for field in ip_fields:
                        if field in result:
                            results[method_name] = {
                                'ip': result[field],
                                'details': result,
                                'response_time': round(end_time - start_time, 3)
                            }
                            break
                else:
                    # 纯文本IP
                    results[method_name] = {
                        'ip': result,
                        'response_time': round(end_time - start_time, 3)
                    }
        except Exception as e:
            results[method_name] = {'error': str(e)}

    return results