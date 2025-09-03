import requests
import concurrent.futures
import socket
import json
import time
from typing import Optional, List, Dict, Any


def get_pub_ip_concurrent(timeout: float = 0.5) -> Optional[str]:
    """并发请求多个服务，返回最快响应的IP"""
    services = [
        # 纯文本IP服务
        "https://api.ipify.org",
        "https://ipinfo.io/ip",
        "https://icanhazip.com",
        "https://ifconfig.me/ip",
        "https://checkip.amazonaws.com",
        "https://ip.42.pl/raw",
        "https://httpbin.org/ip",
        "https://api.my-ip.io/ip",
        "https://ipapi.co/ip",
        "https://api4.my-ip.io/ip",
        "https://ip4.seeip.org",
        "https://ipv4.icanhazip.com",
        "https://v4.ident.me",
        "https://api.ipgeolocation.io/getip",
        "https://wtfismyip.com/text",
        # 新增的服务
        "https://ipecho.net/plain",
        "https://myexternalip.com/raw",
        "https://bot.whatismyipaddress.com",
        "https://ip4only.me/api/",
    ]

    def fetch_ip(url: str) -> Optional[str]:
        try:
            response = requests.get(
                url,
                timeout=timeout,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
            )
            ip = response.text.strip()

            # 处理JSON响应的服务
            if url == "https://httpbin.org/ip":
                return json.loads(ip).get('origin', '').split(',')[0].strip()
            elif url == "https://ip4.seeip.org":
                return json.loads(ip).get('ip', '').strip() if ip.startswith('{') else ip

            # 验证IP格式
            if _is_valid_ip(ip):
                return ip
            return None

        except Exception:
            return None

    # 使用线程池并发请求
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        # 提交所有任务
        future_to_url = {executor.submit(fetch_ip, url): url for url in services}

        try:
            # 获取第一个成功的结果
            for future in concurrent.futures.as_completed(future_to_url, timeout=timeout + 1):
                result = future.result()
                if result:
                    # 取消其他未完成的任务
                    for f in future_to_url:
                        f.cancel()
                    return result
        except concurrent.futures.TimeoutError:
            pass

    return None


def get_pub_ip_json_services(timeout: float = 0.5) -> Optional[Dict[str, Any]]:
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


def get_pub_ip_dns_method() -> Optional[str]:
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


def get_public_ip_comprehensive(timeout: float = 0.5) -> Dict[str, Any]:
    """综合多种方法获取公网IP"""
    methods = {
        'http_concurrent': lambda: get_pub_ip_concurrent(timeout),
        'json_services': lambda: get_pub_ip_json_services(timeout),
        'dns_method': get_pub_ip_dns_method,
        'stun_method': get_pub_ip_stun_method,
        'upnp_method': get_pub_ip_upnp_method,
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


if __name__ == '__main__':
    print("=== 快速获取公网IP ===")
    ip = get_pub_ip_concurrent(timeout=0.5)
    print(f"公网IP: {ip}")

    print("\n=== 详细信息 ===")
    json_result = get_pub_ip_json_services(timeout=0.5)
    if json_result:
        print(f"详细信息: {json_result}")

    print("\n=== 综合方法对比 ===")
    all_results = get_public_ip_comprehensive(timeout=0.5)
    for method, result in all_results.items():
        print(f"{method}: {result}")

    print("\n=== DNS方法 ===")
    dns_ip = get_pub_ip_dns_method()
    print(f"DNS查询IP: {dns_ip}")
