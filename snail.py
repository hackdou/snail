# coding=utf-8
import requests
import sys
import re
import time
import threading
import os

banner='''
   _____                   _   _ 
  / ____|                 (_) | |
 | (___    _ __     __ _   _  | |
  \___ \  | '_ \   / _` | | | | |
  ____) | | | | | | (_| | | | | |
 |_____/  |_| |_|  \__,_| |_| |_|
                                 
                                 
[!]start threading snail
[!]Dection starting...
'''
lock=threading.Lock()
max_thread=200
count=0
https="https://"
http="http://"
domains=[]
dict=[]
res=[]
user_agent = 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'
headers = {'User-Agent': user_agent}
#获取域名
def getDomain(file):
    with open(file,'r',encoding='UTF-8') as f:
    	for line in f:
    		domains.append(line[:-1])
    	f.close()
            
#获取字典
def getDict(filename):
    with open(filename,'r',encoding='UTF-8') as f:
        for line in f:
            dict.append(line[:-1])
    f.close()

#生成敏感字典
def genWeak(name):
    exts=['.rar','.zip','.7z','.tar','.tar.7z','.tar.gz','.tar.bz2','.tgz']
    res=[]
    com1=name.split('.')[1]
    com2=name.split('.')[0]+name.split('.')[0]
    for ext in exts:
        res.append(name+ext)
        res.append(com1+ext)
        res.append(com2+ext)
    return res

def check(domain):
    flag=0
    for mem in res:
        if mem.find(domain)>0:
            flag+=1
            if flag>=4:
                return False
    return True

#检测黑名单
def blacklist(res):
    pattern=[]
    if len(res)==0:
        return False
    #pattern.append(re.compile(r''))
    pattern.append(re.compile('看到此页面，说明您可能输入了错误的地址，或者您使用的应用配置了错误的链接。'))
    pattern.append(re.compile('404\.png'))
    pattern.append(re.compile('<TITLE>访问禁止</TITLE>'))
    pattern.append(re.compile('<title>404</title>'))
    pattern.append(re.compile('<h1>无法加载模块.+</h1>'))
    pattern.append(re.compile('<h1>Welcome to nginx!</h1>'))
    pattern.append(re.compile('<title>网站防火墙</title>'))
    pattern.append(re.compile('<title>微校园</title>'))
    pattern.append(re.compile('您需要登录后才可访问系统'))
    pattern.append(re.compile('<title>安徽大学空调监管平台</title>'))
    pattern.append(re.compile('<title>出错了</title>'))
    pattern.append(re.compile('禁止访问'))
    pattern.append(re.compile('<H2>Error</H2>'))
    pattern.append(re.compile('Blocked'))
    pattern.append(re.compile('404</a>错误'))
    pattern.append(re.compile('<input type=hidden'))
    pattern.append(re.compile('document\.location'))
    pattern.append(re.compile('Error 404'))
    for black in pattern:
        if len(black.findall(res))>0:
            return False
    
    return True

#扫描模块
def scan(domain,dicts):
    global count
    dicts.extend(dict)
    for dictionary in dicts:
        http_req_url=http+domain+'/'+dictionary
        https_req_url=https+domain+'/'+dictionary
        try:
            resShark=requests.head(http_req_url,headers=headers,timeout=1,allow_redirects=False)
            try:
                if int(resShark.headers['content-length'])>5000000:
                    print('![*]'+http_req_url)
                    continue
            except:
                pass
            resHttp=requests.get(http_req_url,headers=headers,timeout=1,allow_redirects=False)
            resHttp.encoding = resHttp.apparent_encoding
            if int(resHttp.status_code)==200 or int(resHttp.status_code)==206:
                if blacklist(resHttp.text): 
                    if check(domain):
                        print(' [*]'+http_req_url)
                        lock.acquire()
                        count+=1
                        lock.release()
                        res.append(http_req_url+'\n')
            time.sleep(3)
            resSharks=requests.head(https_req_url,headers=headers,timeout=1,allow_redirects=False)
            try:
                if int(resSharks.headers['content-length'])>5000000:
                    print('![*]'+https_req_url)
                    continue
            except:
                pass

            resHttps=requests.get(https_req_url,headers=headers,timeout=1,allow_redirects=False)
            resHttps.encoding=resHttps.apparent_encoding
            if int(resHttps.status_code)==200 or int(resHttps.status_code)==206:
                if blacklist(resHttps.text): 
                    if check(domain):
                        print(' [*]'+https_req_url)
                        lock.acquire()
                        count+=1
                        lock.release()
                        res.append(https_req_url+'\n')
        except:
            pass
        time.sleep(6)

if __name__=="__main__":

    print(banner)
    # 获取字典
    getDict('dict_file.txt')
    #获取域名
    getDomain('domains.txt')
    thread=[]
    #多线程调用
    #daemon参数，主线程随子线程结束还是子线程随主线程结束,默认为False
    start=time.time()
    for domain in domains:
        dictionaries=genWeak(domain)
        t=threading.Thread(target=scan,args=(domain,dictionaries,),daemon=True)
        thread.append(t)
    
    #维持线程队列
    for t in thread:
        t.start()
        while True:
            if len(threading.enumerate())<=max_thread:
                #print("当前线程数: "+str(len(threading.enumerate())),end="")
                time.sleep(1)
                break
            
    
    print('Detection over in '+str(time.time()-start).split('.')[0]+' s, '+str(count)+' items found')

    #保存检测结果
    with open('result.txt','w') as f:
        for line in res:
            f.write(line+'\n')
        f.close()

