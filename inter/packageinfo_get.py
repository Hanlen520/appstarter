#coding:utf-8

import re
from random import choice
import argparse, sys, os

try:
    import requests
except Exception as e:
    print('pip install requests')
    sys.exit()

try:
    from bs4 import BeautifulSoup
except Exception as e:
    print('pip install bs4 lxml')
    sys.exit()


def get_content(url):
    User_Agent = [
        "Mozilla/5.0 (Windows; U; Windows NT 6.0; cs; rv:1.9.0.13) Gecko/2009073022 Firefox/3.0.13",
        "Mozilla/5.0 (Windows; U; Windows NT 6.0; cs; rv:1.9.0.19) Gecko/2010031422 Firefox/3.0.19",
        "Opera 9.4 (Windows NT 5.3; U; en)",
        "Opera 9.4 (Windows NT 6.1; U; en)",
        "Opera/9.64 (X11; Linux i686; U; pl) Presto/2.1.1",
    ]
    headers = {
        'User-Agent' : choice(User_Agent),
        'Referer' : '',
        'Cookie' : '',
    }
    timeout = 10
    proxies = {}
    try:
        content = requests.get(url, headers = headers, timeout = timeout, proxies = proxies)
        return content.text
    except Exception as e:
        print(e)

    return ""

###########
def parse_packageinfo(content):
    soup = BeautifulSoup(content,'lxml')
    info = soup.find('div', attrs={'class': 'app-intro cf'})
    #print(info)
    if info:
        packageinfo = {}
        img = info.find('img', attrs={'class': 'yellow-flower'})
        packageinfo['img'] = img['src']

        download = info.find('a', attrs={'class': 'download'})
        packageinfo['download'] = "http://app.mi.com"+download['href']

        version = re.findall(u'版本号：</li><li>(.*?)</li>', content, re.M)
        packageinfo['version'] = version[0]

        update = re.findall(u'更新时间：</li><li>(.*?)</li>', content, re.M)
        packageinfo['update'] = update[0]

        appid = re.findall(u'appId：</li><li class=\"special-li\">(.*?)</li>', content, re.M)
        packageinfo['appid'] = appid[0]

        company = re.findall(u'intro-titles\"><p>(.*?)</p>', content, re.M)
        packageinfo['company'] = company[0]

        return packageinfo
    
    return []

def get_packageinfo(package):
    content = get_content("http://app.mi.com/details?id={}&ref=search".format(package))
    return parse_packageinfo(content)
#############

#############
def parse_samedev(content):
    import json, time
    pkgs = []
    info = json.loads(content)
    for x in info['listApp']:
        packageinfo = {}
        packageinfo['package'] = x['packageName']
        packageinfo['version'] = x['versionName']
        packageinfo['update'] = time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(float(x['updateTime']/1000)))
        packageinfo['appid'] = str(x['appId'])
        packageinfo['company'] = x['publisherName']

        pkgs.append(packageinfo)

    return pkgs

def get_samedev(appid):
    samedevpackage = []
    page = 0
    while True:
        url = "http://app.market.xiaomi.com/apm/samedev?appId={}&os=V10.2.1.0.OAACNXM&page={}&sdk=26&stamp=0".format(appid, page)
        content = get_content(url)
        pkgs = parse_samedev(content)
        if len(pkgs) == 0:
            break
        page += 1

        samedevpackage += pkgs
    return samedevpackage
############

############
def parse_search(content):
    soup = BeautifulSoup(content,'lxml')
    info = soup.find('div', attrs={'class': 'applist-wrap'}).find_all('a', href=True)
    #print(info)
    if info:
        searchres = []
        for x in info:
            #print(x['href'])
            p = re.findall(r'details\?id=(.*?)&ref', x['href'])
            if p:
                searchres.append(p[0])

        return list(set(searchres))
    
    return []

def get_search(package):
    samedevpackage = []
    page = 1
    while True:
        url = "http://app.mi.com/searchAll?keywords={}&typeall=phone&page={}".format(package, page)
        content = get_content(url)
        pkgs = parse_search(content)
        if len(pkgs) == 0:
            break
        page += 1

        samedevpackage += pkgs
    result = []
    for x in samedevpackage:
        if x.startswith(package):
            result.append(x)

    return result
 ###########

def getpkg(package, same):
    #根据包名获取下载链接、appid等
    packageinfo = get_packageinfo(package)
    if packageinfo:
        #print(package+', '+ packageinfo['appid']+', '+packageinfo['company']+ ', '+packageinfo['download']+ ', '+packageinfo['update'])
        if not same:
            #print(packageinfo['download'])
            return packageinfo.get('download')
        #根据appid查询同开发者应用
        appid = packageinfo['appid']
        if same:
            samedevpackage = get_samedev(appid)
            #print('Same dev total: '+str(len(samedevpackage)))
            pkgs = []
            for x in samedevpackage:
                pkgs.append(x['package'])
            #print(', '.join(pkgs))
            return ','.join(pkgs)

    else:
        #包名前缀情况下，进行模糊查询
        if same:
            searchpackage = get_search(package)
            #print('Search total: '+str(len(searchpackage)))
            #print(', '.join(searchpackage))
            return ', '.join(searchpackage)
        else:
            #print('error')
            return ''
            #print('检查下包名是否正确，或加上-s选项')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='输入包名或包名前缀')
    parser.add_argument("-p", "--package",type=str, help="package name")
    parser.add_argument("-s", "--same", action="store_true", help="是否获取同开发者应用")
    

    args = parser.parse_args()
    package = args.package
    same = args.same
    
    if not package:
        parser.print_help()
        sys.exit()
    getpkg(package, same)