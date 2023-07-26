import requests
import whois
import re
# import aiohttp
# import asyncio


def complete_url(url):
    # 检查是否包含协议，如果不包含则默认补全为https协议
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url

    # 检查是否包含子域名（如www），如果不包含则默认补全
    if '://' in url:
        protocol, domain = url.split('://', 1)
        if '.' not in domain:
            url = f'{protocol}://www.{domain}'

    return url


def capture_web_traffic(url):
    try:
        # 发送GET请求
        response = requests.get(url)

        # 输出响应状态码和内容
        print("Response Status Code:", response.status_code)
        # print("Response Content:")
        # print(response.text)

        # 获取请求头部信息
        print("Request Headers:")
        for header, value in response.request.headers.items():
            print(f"{header}: {value}")

        # 获取响应头部信息
        print("Response Headers:")
        for header, value in response.headers.items():
            print(f"{header}: {value}")

        # 检查代理头部信息
        check_proxy_headers(response.headers)

    except requests.exceptions.RequestException as e:
        print("An error occurred:", e)


def check_proxy_headers(headers):
    # Check for "X-Forwarded-For" header
    x_forwarded_for = headers.get("X-Forwarded-For")
    if x_forwarded_for:
        print(f"X-Forwarded-For: {x_forwarded_for}")

    # Check for "Via" header
    via = headers.get("Via")
    if via:
        print(f"Via: {via}")

    # You can add more checks for other proxy-related headers as needed

    if not x_forwarded_for and not via:
        print("No proxy headers found. The request might not pass through a reverse proxy.")

def get_whois(url):
    w = whois.whois(target_url)
    # Define the regular expression pattern
    pattern = {
        "dnssec": r'"dnssec": "([^"]*)"',
        "name": r'"name": ([^,]*)',
        "org": r'"org": "([^"]*)"',
        "address": r'"address": ([^,]*)',
        "city": r'"city": ([^,]*)',
        "state": r'"state": "([^"]*)"',
        "registrant_postal_code": r'"registrant_postal_code": ([^,]*)',
        "country": r'"country": "([^"]*)"',
    }

    # Extract the desired information using regular expressions
    desired_info = {}
    for key, regex in pattern.items():
        match = re.search(regex, str(w))
        if match:
            desired_info[key] = match.group(1)
    for key, value in desired_info.items():
        print(f"{key}: {value}")

# async def access_https_website(url):
#     try:
#         async with aiohttp.ClientSession() as session:
#             async with session.get(url) as response:
#                 # 检查响应状态码
#                 if response.status == 200:
#                     # 打印网页内容
#                     ssl_content = await response.text()
#                     html_content = ssl_content
#                     # 使用正则表达式提取信息
#                     pattern = re.compile(
#                         r'<div class="ssl-more-item">.*?<span class="ssl-more-label">(.*?)</span>.*?<span class="ssl-more-value">(.*?)</span>',
#                         re.DOTALL)
#                     certificate_details = pattern.findall(html_content)
#
#                     # 输出提取的信息
#                     for label, value in certificate_details:
#                         print(f"{label.strip()}: {value.strip()}")
#                     # 使用正则表达式提取信息
#                     pattern = re.compile(
#                         r'<h4 class="ssl-more-title">服务器详情：</h4><div class="ssl-more-items">.*?<div class="ssl-more-item"><span class="ssl-more-label">服务器类型：</span>\s*<span class="ssl-more-value">(.*?)</span>.*?<div class="ssl-more-item"><span class="ssl-more-label">IP地址：</span>\s*<span class="ssl-more-value">(.*?)</span>.*?<div class="ssl-more-item"><span class="ssl-more-label">端口：</span>\s*<span class="ssl-more-value">(.*?)</span>.*?<div class="ssl-more-item"><span class="ssl-more-label">主机名：</span>\s*<span class="ssl-more-value">(.*?)</span>',
#                         re.DOTALL)
#                     server_details = pattern.findall(html_content)
#
#                     # 输出提取的信息
#                     for server_type, ip_address, port, hostname in server_details:
#                         print(f"服务器类型: {server_type.strip()}")
#                         print(f"IP地址: {ip_address.strip()}")
#                         print(f"端口: {port.strip()}")
#                         print(f"主机名: {hostname.strip()}")
#                 else:
#                     print(f"Failed to access the website. Status code: {response.status}")
#
#     except aiohttp.ClientError as e:
#         print("An error occurred:", e)

if __name__ == "__main__":
    # 设置要抓包的网站URL
    user_url = input("target URL: ")
    target_url = complete_url(user_url)
    # 调用抓包函数
    print("Packet Capture Result")
    capture_web_traffic(target_url)
    print("\nWhois Result")
    get_whois(target_url)
    print("\nSSL Info")
    print(f"SSL-Checker: https://www.websiteplanet.com/zh-hans/webtools/ssl-checker/?url=" + user_url)

    print(f"\nMore Info\nnetcraft: https://sitereport.netcraft.com/?url="+target_url)
    print(f"robtex: https://www.robtex.com/dns-lookup/"+user_url)
    print(f"e-cert: https://crt.sh/?q="+user_url)
    print("ICP: https://beian.miit.gov.cn/#/Integrated/index")
    print("Ping_Test: https://www.itdog.cn")


