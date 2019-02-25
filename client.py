import requests
"""安装依赖
pip install requests[socks]
"""

socket_proxy = {"http": "socks5://username:password@127.0.0.1:9011",
                "https": "socks5://username:password@127.0.0.1:9011"}
resp = requests.get("http://www.baiducom", proxies=socket_proxy, timeout=5)
print(resp.content.decode("utf-8"))
