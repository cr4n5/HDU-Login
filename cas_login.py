from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
import base64
import requests
import lxml.etree
import json

def encrypt(key, plain):
    key=base64.b64decode(key)
    des=DES.new(key,DES.MODE_ECB)
    plain= pad(plain.encode('utf-8') , DES.block_size , style='pkcs7')
    cipher_text=des.encrypt(plain)
    cipher_text=base64.b64encode(cipher_text).decode('utf-8')
    return cipher_text

def login(session):
    with open("config.json","r") as f:
        config=json.load(f)
    session.headers.update({
        "Accept": "text/html, application/xhtml+xml, application/xml; q=0.9, */*; q=0.8",
        "Accept-Language": "zh_CN",
        "Connection": "keep-alive",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18363",
    })

    url="https://sso.hdu.edu.cn/login"
    response=session.get(url)
    tree=lxml.etree.HTML(response.text)
    execution=tree.xpath('//*[@id="login-page-flowkey"]/text()')[0]
    croypto=tree.xpath('//*[@id="login-croypto"]/text()')[0]
    password=config["login"]["password"]
    password=encrypt(croypto,password)

    data={'username': config["login"]["username"], 'type': 'UsernamePassword', '_eventId': 'submit', 'geolocation': '', 
        'execution': execution, 
        'captcha_code': '', 'croypto': croypto, 'password': password}

    response=session.post(url,data=data)
    return session

if __name__ == "__main__":
    session = requests.Session()    
    login(session)
    newjw="https://newjw.hdu.edu.cn/sso/driot4login"
    response=session.get(newjw)
    print(response.text)