#!/usr/bin/python
#encoding=utf-8
import sys
import time
import urllib
import urllib2  
from urllib2 import *
from bs4 import BeautifulSoup
import re
import socket
import MySQLdb
import urlparse
import mechanize
import httplib
import telnetlib
import os
import cookielib
import ConfigParser

socket.setdefaulttimeout(150)
cf = ConfigParser.ConfigParser()
cf.read("info.conf")
class gettrace:
    def __init__(self,testid,url,ip):
        self.id=testid   
        self.url=url  
        self.tmpurl=url  
        self.resulturl=url
        self.server=url.split('/')[2]
        self.ip=ip  
        self.list={}   
        self.post=0   
        self.finish=0
        self.my559=0 #多源服务器中当前源服务器id
        self.mynumber=0#多源服务器中服务器总数目
        self.myspe=3#特殊多源服务器中当前ID
        self.flag=1    
        self.rstr=""
        self.unjumpa=[1784,3671]
        self.hasjump=0
        self.my5400=0
        self.function=0
        self.resultlab=0
        #不同标签的匹配
        self.attrs=['submit','hidden']
        self.radiop=re.compile(cf.get("label", "radiop"),re.I)
        self.checkboxp=re.compile(cf.get("label", "checkboxp"))
        self.formpa=re.compile(cf.get("label", "formpa"),re.I) #jump level 1
        self.formpframe=re.compile(cf.get("label", "formpframe"))
        self.formpiframe=re.compile(cf.get("label", "formpiframe"))
        self.resultiframe=re.compile(cf.get("label", "resultiframe"))
        self.buttonp=re.compile(cf.get("label", "buttonp"),re.I)
        self.bsp=re.compile(cf.get("label", "bsp"),re.I)
        self.actionp=re.compile(cf.get("label", "actionp"))
        self.srouter=re.compile(cf.get("label", "srouter"))
        self.optionp=re.compile(cf.get("label", "optionp"),re.I)
        self.selectp=re.compile(cf.get("label", "selectp"))
        self.formsp=re.compile(cf.get("label", "formsp"),re.I)
        self.fp=re.compile(cf.get("label", "fp"))


        #结果的标签中提取数据匹配
        self.textp=re.compile(cf.get("result", "textp"))
        self.p=re.compile(cf.get("result", "p"),re.I)  #traceroute result format
        self.pat=re.compile(cf.get("result", "pat"))  #input=text ip
       
        #多源服务器ASN
        self.specaillist=[]
        for j in cf.options("masn"):
            a=cf.get("masn", j).split(',')
            self.specaillist.append(a)
    def __call__(self):
        apply(self.ma,())
    def ma(self):                                      #直接爬虫         
        try:
            print "begin ma()","\n"
            br=mechanize.Browser()
            f=br.open(self.url) 
            if not (self.url==f.geturl()):   #URL发生改变
                f.close()
                self.url=f.geturl()
                self.resulturl=self.url
                request=Request(self.url)
                f=urlopen(request)     
            soup=BeautifulSoup(f)
        except HTTPError,e:
            print "HTTPError:",e.code,"\n"
            print "trying mb()","\n"
            self.mb()
        except URLError,e:         
            if 'telnet' in e.reason:
                self.mi()
            else:
                print "URLError:",e.reason,"\n"
                print "trying mb()","\n"
                self.mb()
        except socket.timeout:
            print "timeout!","\n"
            print "trying mb()","\n"
            self.mb()
        except TypeError:  
            print "TypeERROR!"
            print "trying mb()","\n"
            self.mb()
        except IOError,e:
            print "IOError"
            print "trying mb()","\n"
            self.mb()
        except Exception:
            print "the page cannot be opened correctly!"
            print "trying mb()","\n"
            self.mb()
 
        else: 
            self.function=1    
            f.close()
            flag=0             #目的URL不在当前页面
            while(1):
                flag=0
                tagas=soup.findAll('a')
                for taga in tagas:
                    if taga.has_key('href') and re.search(self.formpa,taga['href']):
                        if self.server in self.unjumpa:
                            continue
                        else:
                            str1=taga['href']
                        self.url=urlparse.urljoin(self.url,str1)
                        try:
                            f=urllib.urlopen(self.url)
                            self.url=f.geturl()
                            self.resulturl=self.url
                            soup=BeautifulSoup(f)
                        except Exception:
                            sys.exit(1)
                        f.close()
                        flag=1
                        self.hasjump=1
                        break
                if flag==0:
                    break    
            
  
            flag=0             #目的URL在frame
            while(1):
                flag=0
                tagframes=soup.findAll('frame')
                for tagframe in tagframes:
                    if tagframe.has_key('src') and re.search(self.formpframe,tagframe['src']):
                        self.url=urlparse.urljoin(self.url,tagframe['src'])
                        try:
                            f=urllib.urlopen(self.url)
                            self.url=f.geturl()
                            self.resulturl=self.url
                            soup=BeautifulSoup(f)
                        except Exception:
                            print "an unexpected error!\n"
                            sys.exit(1)
                        f.close()
                        flag=1
                        self.hasjump=1
                        break
                if flag==0:
                    break     

            flag=0             #目的URL在iframe
            while(1):
                flag=0
                tagiframes=soup.findAll('iframe')
                for tagiframe in tagiframes:
                    if tagiframe.has_key('src') and re.search(self.formpiframe,tagiframe['src']):
                        self.url=urlparse.urljoin(self.url,tagiframe['src'])
                        try:
                            f=urllib.urlopen(self.url)
                            self.url=f.geturl()
                            self.resulturl=self.url
                            soup=BeautifulSoup(f)
                        except Exception:
                            print "an unexpected error!\n"
                            sys.exit(1)
                        flag=1
                        self.hasjump=1
                        break
                if flag==0:
                    break   
        
            self.tmpurl=self.url,"\n\n"  
            
            forms=soup.findAll('form')
            for form in forms:
                if self.finish:
                    break
                if re.search(self.fp,repr(form)) and (self.server not in  self.specaillist[1]):    #找到我们需要的from表单
                    if not ( re.search(r'network_tools_iframe\.asp',self.url) or re.search(self.formsp,repr(form.contents)) ):
                        continue
                self.list={}
                self.post=0
                self.tmpurl=self.url
                if form.has_key('method'):
                    if form['method'].lower()=='post':
                        self.post=1
                if form.has_key('action'):
                    self.tmpurl=urlparse.urljoin(self.url,form['action']) #解析URL
               
                inputs=form.findAll('input',{'name':True})       

                for inp in inputs:#输入存在文本标签中
                     if (not inp.has_key('type')) or ( inp['type'].lower() in ['text','textfield'] ):
                         if inp.has_key('name') and (inp['name'] not in ["VIA"]):
                             if not ( inp.has_key('value') and inp['value'] and re.search(self.textp,inp['value']) ):
                                 self.list[inp['name']]=self.ip
                                 self.flag=1    
                             elif inp.has_key('value'):
                                 self.list[inp['name']]=inp['value']

                     elif (inp['type'].lower() in self.attrs) and inp.has_key('value'):#某些值可能存在于按钮标签中
                         if not ( inp['type'].lower()=='submit'  and ( re.search(r'QTYPE2|btt_show',inp['name']) or re.search(self.bsp,inp['value']) ) ):
                            self.list[inp['name']]=inp['value']
                      

                     elif inp['type'].lower()=='radio' and inp.has_key('value') and re.search(self.radiop,inp['value']):#radio标签中的值
                            self.list[inp['name']]=inp['value']
                        #特殊的，根据变化自己增删改
                            if (self.server in self.specaillist[3]):
                                if(inp['name']==cf.items(str(self.server))[0][0]):
                                     self.list[inp['name']]=int(cf.items(str(self.server))[0][1])
                     elif inp['type'].lower()=='checkbox' and inp.has_key('value') and re.search(self.checkboxp,inp['value']) :#取checkbox标签中的有效值
                         self.list[inp['name']]=inp['value']
                     elif inp['type'].lower()=='checkbox' and  self.server in self.specaillist[4]:
                         self.list[inp['name']]=cf.items(str(self.server))[1][1]
                     
                     elif inp['type'].lower()=='button' and inp.has_key('value') and re.search(self.buttonp,inp['value']):
                         self.list[inp['name']]=inp['value']     
                     if (self.server in self.specaillist[5]):
                                if(inp['name']==cf.items(str(self.server))[0][0]):
                                     self.list[inp['name']]=int(cf.items(str(self.server))[0][1])
                #取select标签中的有效值
                selects=form.findAll('select')
                optionflag=0
                self.number=0
                i=0
                for select in selects:
                    options=select.findAll('option')
                    for option in options:
                        if (self.server in self.specaillist[7]) and option.has_key('value'):
                            self.list[select['name']]=cf.items(str(self.server))[0][1]
                            break
                        elif option.has_key('value') and re.search(self.optionp,option['value']):
                            if select.has_key('name'):
                                self.list[select['name']]=option['value']
                                break
                        elif (not option.has_key('value') ) and (option.string!=None) and re.search(r'TraceRoute\(TW\)|^No$|\b3\b|oslo-gw\.uninett\.no|^5$',option.string):
                            self.list[select['name']]=option.string
                            break
                    if re.search(self.selectp,select['name']) and self.server in self.specaillist[8]:#多源点
                        for option in options:
                            self.list[select['name']]=option['value']
                            self.show()
                        optionflag=1
                #多源点服务器循环traceroute所有服务器,服务器选择在option标签中
                i=1
                selects=form.findAll('select')
                for select in selects:
                    options=select.findAll('option')
                    if re.search(self.selectp,select['name']) and self.server in self.specaillist[0]:
                        for option in options:
                            if option.string!=None and option.has_key('value'):
                                self.number=self.number+1 #求源点数目
                        for option in options:
                            if option.string!=None and option.has_key('value'):
                                if self.my559==i:
                                    self.list[select['name']]=option['value']
                                    self.my559=self.my559+1
                                    self.show()
                                    if self.my559<self.number:
                                        self.post=1
                                        self.finish=0
                                        self.ma()
                                i=i+1
                        optionflag=1
                
                 #多源点服务器循环traceroute所有服务器,服务器选择在checkbox标签中
                i=1
                if self.server in self.specaillist[9]:
                    self.post=0
                    inputs=form.findAll('input',{'name':True})
                    self.list['afPref']='preferV6'
                    for inp in inputs:
                        if inp['type'].lower()=='checkbox' and re.search(self.srouter,inp['name']) :
                            self.number=self.number+1
                    for inp in inputs:
                        if inp['type'].lower()=='checkbox' and  re.search(self.srouter,inp['name']) :
                            if i==self.my559:
                                self.list[inp['name']]=inp['value']
                                self.my559=self.my559+1
                                self.show()
                                if self.my559<self.number:
                                    self.finish=0
                                    self.post=0
                                    self.ma()
                            i=i+1
                    optionflag=1
                #特殊网站中标签需要固定的值
                if self.server in self.specaillist[3]:
                    self.post=int(cf.items(self.server)[0][1])
                if self.list and optionflag==0:    
                    self.show()   #if the result is matched in show(),then self.finish=1
            else:
                if self.finish==0:
                    self.mb()







    def mb(self):        # 伪装成浏览器                            
        try:
            print "begin mb()","\n"
            headers = ('User-Agent','Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11')
            opener = urllib2.build_opener()
            opener.addheaders = [headers]
            f=opener.open(self.resulturl)
            if not (self.url==f.geturl()):   
                f.close()
                self.url=f.geturl()
                self.resulturl=self.url
                request=Request(self.url)
                f=urlopen(request)       
            soup=BeautifulSoup(f)
            if self.server in  self.specaillist[21] and self.my5400==1: #特殊网站
                soup=self.soup
        except HTTPError,e:
            print "HTTPError:",self.server,"\n"
        except URLError,e:
            if 'telnet' in e.reason:
                self.mi()
            else:
                print "URLError:",self.server,"\n"
        except socket.timeout:
            print "timeout!",self.server,"\n"
            self.finish=1
        except TypeError:  
            print "TypeERROR!",self.server,"\n"
        except IOError,e:
            print "IOError",self.server,"\n"
        except Exception:
            print "the page cannot be opened correctly!",self.server,"\n"
 
        else:
            self.function=2
            f.close()
            flag=0        
            while(1):
                if self.hasjump:
                    break
                flag=0
                tagas=soup.findAll('a')
                for taga in tagas:
                    if taga.has_key('href') and re.search(self.formpa,taga['href']):
                        if self.server in self.unjumpa:
                            continue
                        else:
                            str1=taga['href']
                        self.url=urlparse.urljoin(self.url,str1)
                        try:
                            f=urllib.urlopen(self.url)
                            self.url=f.geturl()
                            self.resulturl=self.url
                            soup=BeautifulSoup(f)
                        except Exception:
                            print "an unexpected error!\n"
                            sys.exit(1)
                        f.close()
                        flag=1
                        
                        break
                if flag==0:
                    break   
            

                

            flag=0         
            while(1):
                if self.hasjump:
                    break
                flag=0
                tagframes=soup.findAll('frame')
                for tagframe in tagframes:
                    if tagframe.has_key('src') and re.search(self.formpframe,tagframe['src']):
                        self.url=urlparse.urljoin(self.url,tagframe['src'])
                        try:
                            f=urllib.urlopen(self.url)
                            self.url=f.geturl()
                            self.resulturl=self.url
                            soup=BeautifulSoup(f)
                        except Exception:
                            print "an unexpected error!\n"
                            sys.exit(1)
                        f.close()
                        flag=1
                        
                        break
                if flag==0:
                    break     

            
            flag=0          
            while(1):
                if self.hasjump:
                    break
                flag=0
                tagiframes=soup.findAll('iframe')
                for tagiframe in tagiframes:
                    if tagiframe.has_key('src') and re.search(self.formpiframe,tagiframe['src']):
                        self.url=urlparse.urljoin(self.url,tagiframe['src'])
                        try:
                            f=urllib.urlopen(self.url)
                            self.url=f.geturl()
                            self.resulturl=self.url
                            soup=BeautifulSoup(f)
                        except Exception:
                            print "an unexpected error!\n"
                            sys.exit(1)
                        flag=1
                        
                        break
                if flag==0:
                    break     ####################
            
            
            self.tmpurl=self.url  
            forms=soup.findAll('form')
            
            for form in forms:
                if self.finish:
                    break
                if re.search(self.fp,repr(form)) and  (self.server not in self.specaillist[2]):   
                        if not ( re.search(r'network_tools_iframe\.asp',self.url) or re.search(self.formsp,repr(form.contents)) ): 
                            continue 
                if self.server in self.specaillist[12]:
                    if form.has_key('action'):
                        if form['action'] =='../search/':
                             continue           
                self.list={}
                self.post=0
                self.tmpurl=self.url
                if form.has_key('method'):
                    if form['method'].lower()=='post':
                        self.post=1
                
                if form.has_key('action'):
                    self.tmpurl=urlparse.urljoin(self.url,form['action'])
                        
                    

                inputs=form.findAll('input',{'name':True})       
                for inp in inputs:
                     if (not inp.has_key('type')) or ( inp['type'].lower() in ['text','textfield'] ):
                         if inp.has_key('name') and (inp['name'] not in ["VIA"]):
                             if not ( inp.has_key('value')   and inp['value'] and re.search(self.textp,inp['value']) ):
                                 self.list[inp['name']]=self.ip
                                 self.flag=1  
                             elif inp.has_key('value'):
                                 self.list[inp['name']]=inp['value']
                                 
                     elif (inp['type'].lower() in self.attrs) and inp.has_key('value'):
                         if not ( inp['type'].lower()=='submit'  and ( re.search(r'QTYPE2',inp['name']) or re.search(self.bsp,inp['value']) ) ):
                             self.list[inp['name']]=inp['value']
                         
                     elif inp['type'].lower()=='radio' and inp.has_key('value') and re.search(self.radiop,inp['value']):
                         self.list[inp['name']]=inp['value']
                         if (self.server in  self.specaillist[10]):
                                if(inp['name']==cf.items(str(self.server))[0][0]):
                                     self.list[inp['name']]=int(cf.items(str(self.server))[0][1])
                             
                     elif inp['type'].lower()=='checkbox' and inp.has_key('value') and re.search(self.checkboxp,inp['value']) :
                         self.list[inp['name']]=inp['value']
                     elif inp['type'].lower()=='button' and inp.has_key('value') and re.search(self.buttonp,inp['value']):
                         self.list[inp['name']]=inp['value']
                     
                selects=form.findAll('select')
                flag=0
                for select in selects:
                    options=select.findAll('option')
                    for option in options:
                        if (self.server in self.specaillist[14]) and select['name']=='routers':
                            self.list[select['name']]=option.next.split('\n')[0]
                            break
                        if option.has_key('value') and re.search(self.optionp,option['value']):
                            self.list[select.get('name')]=option['value']
                            break

                     #多源服务器
                    self.number=0
                    if self.server in self.specaillist[11]: #某些网站对标签固定要求
                            self.list[cf.items(str(self.server))[0][0]]=cf.items(str(self.server))[0][1] 
                    if select.has_key('name'):     
                      if self.server in self.specaillist[0] and re.search(self.selectp,select['name']) :
                        i=0
                        for option in options:
                            self.number=self.number+1
                        for option in options:
                            if self.my559<self.number and self.my559==i:
                                if self.server in self.specaillist[13]: #需要解析字符串提取有效值
                                        self.list[select['name']]=option.next.split('\n')[0]
                                else:
                                    self.list[select['name']]=option['value']
                                self.my559=self.my559+1
                                self.show()
                                if self.my559<self.number:
                                    self.finish=0
                                    self.post=1
                                    self.mb()
                            i=i+1
                        flag=1
                if self.list and flag==0:    
                    self.show()  
            else:
                if self.finish==0:
                    self.mc()                   

    def mc(self):                                                 #第一次traceroute无效，重新一次traceroute
        try:
            print "begin mc()","\n\n"
            headers = ('User-Agent','Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11')
            opener = urllib2.build_opener()
            opener.addheaders = [headers]
            f=opener.open(self.resulturl) 
            soup=BeautifulSoup(f)

        except HTTPError,e:
            print "HTTPError:",e.code,"\n"
            print "trying md()\n"
            self.md()
        except URLError,e:
            print "URLError:",e.reason,"\n"
            print "trying md()\n"
            self.md()
        except socket.timeout:
            print "timeout!","\n"
            print "trying md()\n"
            self.md()
        except TypeError:  #if the page is empty
            print "TypeERROR!"
            print "trying md()\n"
            self.md()
        except IOError,e:
            print "IOError"
            print "trying md()\n"
            self.md()
        except Exception:
            print "the page cannot be opened correctly!"
            print "trying md()\n"
            self.md()
        else:
            self.function=3
            f.close()
            self.tmpurl=self.url
            forms=soup.findAll('form')
            for form in forms:
                if self.finish:
                    break
                if re.search(self.fp,repr(form)) and  (self.server not in self.specaillist[2]):    #form is not the form for ping 
                    if not ( re.search(r'network_tools_iframe\.asp',self.url) or re.search(self.formsp,repr(form.contents)) ):
                        continue

                    
                self.list={}
                self.post=0
                self.tmpurl=self.url
                if form.has_key('method') and form['method'].lower()=='post':
                    self.post=1
                if form.has_key('action'):
                        self.tmpurl=urlparse.urljoin(self.tmpurl,form['action'])

                        
                inputs=form.findAll('input',{'name':True})

                for inp in inputs:
                    if  (not inp.has_key('type'))  or  ( inp['type'].lower() in ['text','textfield'] ):
                        if inp.has_key('name') and (inp['name'] not in ["VIA"]):
                            if not ( inp.has_key('value')and inp['value'] and re.search(self.textp,inp['value']) ):
                                self.list[inp['name']]=self.ip
                                self.flag=1    
                            elif inp.has_key('value'):
                                self.list[inp['name']]=inp['value']
                    elif inp['type'].lower() in self.attrs and inp.has_key('value'):
                        if not ( inp['type'].lower()=='submit'  and ( re.search(r'QTYPE2',inp['name']) or re.search(r'\bmtr\b|\bping\b|\bPing\b|Do\s+NSLookup|^Reset\s+Form$|^Defaults$|^Clear\s+Form$|^Abort$',inp['value']) ) ):
                             self.list[inp['name']]=inp['value']
        
                        
                    elif inp['type'].lower()=='radio' and inp.has_key('value') and re.search(self.radiop,inp['value']):
                        self.list[inp['name']]=inp['value']
                             
                    elif inp['type'].lower()=='checkbox' and inp.has_key('value') and re.search(self.checkboxp,inp['value']) :
                        self.list[inp['name']]=inp['value']
                    elif inp['type'].lower()=='button' and inp.has_key('value') and re.search(self.buttonp,inp['value']):
                        self.list[inp['name']]=inp['value']

                selects=form.findAll('select')
                for select in selects:
                    options=select.findAll('option')
                    
                    for option in options:
                        if option.has_key('value') and re.search(self.optionp,option['value']):
                            self.list[select['name']]=option['value']
                            break
                        elif (not option.has_key('value') ) and (option.string!=None)and re.search(r'TraceRoute\(TW\)|^No$|\b3\b|oslo-gw\.uninett\.no',option.string):
                            self.list[select['name']]=option.string
                            break        
                if self.list:
                    self.show()
            else:
                if self.finish==0:
                    self.md()
    
    def md(self):         #直接打开输入目的IP mechanize
        try:
            print "begin md()","\n\n"
            br=mechanize.Browser()
            f=br.open(self.url)
        except HTTPError,e:
            print "HTTPError:",e.code,"\n"
            print "trying me()\n"
            self.me()
        except URLError,e:
            print "URLError:",e.reason,"\n"
            print "trying me()\n"
            self.me()
        except socket.timeout:
            print "timeout!","\n"
            print "trying me()\n"
            self.me()
        except TypeError:  
            print "TypeERROR!"
            print "trying me()\n"
            self.me()
        except IOError,e:
            print "IOError"
            print "trying me()\n"
            self.me()
        except Exception:
            print "the page cannot be opened correctly!"
            print "trying me()\n"
            self.me()
        else:
            try:
                self.function=4
                text=f.read()
            except socket.timeout:
                print "timeout!",self.server,"\n"
                print "trying me()\n"
                self.me()
            else:
                pattern=re.compile(r'isindex',re.I)  
                if re.search(pattern,text):
                    self.flag=1   
                    self.show()
                if self.finish==0:
                    self.me()    
      
        
    
    def me(self):         #直接打开输入目的IP urllib
        try:
            print "begin me()","\n\n"
            request=Request(self.url)
            f=urlopen(request)
        except HTTPError,e:
            print "HTTPError:",self.server,"\n"
        except URLError,e:
            print "URLError:",self.server,"\n"
        except socket.timeout:
            print "timeout!",self.server,"\n"
        except TypeError:  
            print "TypeERROR!",self.server,"\n"
        except IOError,e:
            print "IOError",self.server,"\n"
        except Exception:
            print "the page cannot be opened correctly!",self.server,"\n"
        else:
            try:
                text=f.read()
            except socket.timeout:
                print "timeout!",self.server,"\n"
            else:
                self.function=5
                pattern=re.compile(r'isindex',re.I)  
                if re.search(pattern,text):
                    self.flag=1   
                    self.show()
                if self.finish==0:
                    self.mg()            

    def mg(self):           #一部分输入不在From表单中
        try:
            print "begin mg()","\n\n"
            br=mechanize.Browser()
            f=br.open(self.url)
            soup=BeautifulSoup(f)
        except HTTPError,e:
            print "HTTPError:",e.code,"\n"
            print "trying mh()\n"
        except URLError,e:
            print "URLError:",e.reason,"\n"
            print "trying mh()\n"
        except socket.timeout:
            print "timeout!","\n"
            print "trying mh()\n"
        except TypeError:  
            print "TypeERROR!"
            print "trying mh()\n"
        except IOError,e:
            print "IOError"
            print "trying mh()\n"
        except Exception:
            print "the page cannot be opened correctly!"
            print "trying mh()\n"
        else: 
            self.function=6
            f.close()
            self.tmpurl=self.url
            forms=soup.findAll('form')
            self.list={}
            for form in forms:
                if re.search(self.fp,repr(form)) and (self.server not in self.specaillist[2]):  
                    if not ( re.search(r'network_tools_iframe\.asp',self.url) or re.search(self.fp,repr(form.contents)) ):
                        continue
                
                if form.has_key('method') and form['method'].lower()=='post':
                    self.post=1
                if form.has_key('action') and (not re.search(self.actionp,form['action'])):  
                        self.tmpurl=urlparse.urljoin(self.url,form['action'])
             
             #   取值在from表单外 
            inputs=soup.findAll('input',{'name':True})       
            for inp in inputs:
                if re.search(self.fp,repr(inp)):    
                    continue                    
                if (not inp.has_key('type')) or ( inp['type'].lower() in ['text','textfield'] ):
                    if inp.has_key('name') and (inp['name'] not in ["VIA"]):
                        if not ( inp.has_key('value')   and inp['value'] and re.search(self.textp,inp['value']) ):
                            self.list[inp['name']]=self.ip
                            self.flag=1
                        elif inp.has_key('value'):
                            self.list[inp['name']]=inp['value']
                elif (inp['type'].lower() in self.attrs) and inp.has_key('value'):
                    if not ( inp['type'].lower()=='submit'  and ( re.search(r'QTYPE2',inp['name']) or re.search(self.bsp,inp['value']) ) ):
                        self.list[inp['name']]=inp['value']
                    
                elif inp['type'].lower()=='radio' and inp.has_key('value') and re.search(self.radiop,inp['value']):
                    self.list[inp['name']]=inp['value']

                elif inp['type'].lower()=='checkbox' and inp.has_key('value') and re.search(self.checkboxp,inp['value']) and (self.server not in self.specaillist[18]):
                    self.list[inp['name']]=inp['value']
                elif inp['type'].lower()=='button' and inp.has_key('value') and re.search(self.buttonp,inp['value']):
                    self.list[inp['name']]=inp['value']

            flag=0        
            selects=soup.findAll('select')
            for select in selects:
                options=select.findAll('option')
                  
                for option in options:
                    if option.has_key('value') and re.search(self.optionp,option['value']) and select.has_key('name'):
                        self.list[select['name']]=option['value']
                        break
                    elif (not option.has_key('value') ) and re.search(r'TraceRoute\(TW\)|^No$|\b3\b|oslo-gw\.uninett\.no',option.string):
                        self.list[select['name']]=option.string
                        break
                    elif select.has_key('name'):
                        if select['name']=='router' and self.server in self.specaillist[15]:
                            self.list[select['name']]=option['value']
                            self.post=1
            #输入不全部在form表单的特殊多源服务器
            for select in selects:            
                if self.server in self.specaillist[16]:            
                 if select['name']==cf.items(self.server)[0][1] :
                    script=soup.findAll('script')
                    my = re.compile(r'Option(.*)')
                    mytxt=soup.get_text()
                    lines=re.findall(my,mytxt)
                    self.number=0
                    for line in lines:
                        self.number=self.number+1
                    if self.myspe<=self.number:
                        ops=lines[self.myspe].split('"')
                        op = ops[3].encode("utf-8") 
                        self.list[select['name']]=op
                        self.post=1
                        self.show()
                        self.myspe=self.myspe+1
                        if self.myspe<self.number:
                            self.finish=0
                            self.mg()
                    flag=1
                if self.server in self.specaillist[17]:
                 if select['name']==cf.items(self.server)[0][1]  :
                    self.number=0
                    i=0
                    for option in options:
                        self.number=self.number+1
                    for option in options:
                        if self.my559==i and self.my559<self.number:
                            self.list[select['name']]=option['value']
                            self.my559=self.my559+1
                            self.show()
                            if self.my559<self.number:
                                self.finish=0
                                self.post=1
                                self.ma()
                        i=i+1
            if self.list and flag==0 :
                self.show()
            if self.finish==0:
                self.show()





    def show(self):
        try:
            print "show()","\n"
            if self.post: #POST
                req = urllib2.Request(self.tmpurl) 
                data=urllib.urlencode(self.list)
                headers = ('User-Agent','Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11')
                opener = urllib2.build_opener()
                opener.addheaders = [headers]
                f=opener.open(req,data)
                f=urlopen(self.tmpurl,urllib.urlencode(self.list))
            else:#GET
                if self.list:
                    if self.server in self.specaillist[22]:
                        self.tmpurl=urlparse.urljoin(self.tmpurl,"?router="+self.list['router']+"&query="+self.list['query']+"&parameter="+self.list['parameter'])
                    else :
                        self.tmpurl=urlparse.urljoin(self.tmpurl,"?"+urllib.urlencode(self.list))
                    if self.server in  self.specaillist[23]:
                        self.tmpurl=self.resulturl+"tracert?host="+self.ip
                    if self.server in self.specaillist[24]:
                        self.tmpurl=urlparse.urljoin(self.tmpurl,"/ajax.php?"+urllib.urlencode(self.list))
                    f=urllib.urlopen(self.tmpurl)
                else:
                    if (self.url)[len(self.url)-1]!='?':
                        f=urllib.urlopen(self.url+"?"+self.ip)  
                    else:
                        f=urllib.urlopen(self.url+self.ip)        
            soup=BeautifulSoup(f)     
            if self.server in self.specaillist[21] and self.my5400==0:
                self.soup=soup
                self.my5400=1
                self.mb()
        except HTTPError,e:
            print "HTTPError:",e.code,"\n"
        except URLError,e:
            print "URLError:",self.server,"\n"
        except socket.timeout:
            print "timeout!",self.server,"\n"
        except TypeError:  
            print "TypeERROR!",self.server,"\n"
        except IOError,e:
            print "IOError",self.server,"\n"
        except Exception:
            print "the page cannot be opened correctly!",self.server,"\n"
        else:
            print self.id
            print self.list,"\n"  
            print self.tmpurl,"\n" 
            
            f.close()
    
            flag=0             
            while(1):
                flag=0
                tagiframes=soup.findAll('iframe')
                for tagiframe in tagiframes:
                    if tagiframe.has_key('src') and self.server in self.specaillist[19]:
                        if (self.tmpurl)[len(self.tmpurl)-1]!='/' :
                            self.tmpurl+="/"
                        try:
                            self.tmpurl=urlparse.urljoin(self.tmpurl,tagiframe['src'])
                            f=urllib.urlopen(self.tmpurl)
                            soup=BeautifulSoup(f)
                            flag=0
                        except HTTPError,e:
                            print "HTTPError:",e.code,"\n"
                        except URLError,e:
                            print "URLError:",self.server,"\n"
                        except socket.timeout:
                            print "timeout!",self.server,"\n"
                        except TypeError: 
                            print "TypeERROR!",self.server,"\n"
                        except IOError,e:
                            print "IOError",self.server,"\n"
                        except Exception:
                            print "the page cannot be opened correctly!",self.server,"\n"
                        break 
                tagiframes=soup.findAll('frame')
                for tagiframe in tagiframes:
                    if tagiframe.has_key('src') and self.server in self.specaillist[20]:
                        if (self.tmpurl)[len(self.tmpurl)-1]!='/' :
                            self.tmpurl+="/"
                        try:
                            self.tmpurl=urlparse.urljoin(self.tmpurl,tagiframe['src'])
                            f=urllib.urlopen(self.tmpurl)
                            soup=BeautifulSoup(f)
                            flag=0
                        except HTTPError,e:
                            print "HTTPError:",e.code,"\n"
                        except URLError,e:
                            print "URLError:",self.server,"\n"
                        except socket.timeout:
                            print "timeout!",self.server,"\n"
                        except TypeError:  #if the page is empty
                            print "TypeERROR!",self.server,"\n"
                        except IOError,e:
                            print "IOError",self.server,"\n"
                        except Exception:
                            print "the page cannot be opened correctly!",self.server,"\n"
                        break
                if flag==0:
                    break  
           
            #提取数据,不同标签依次尝试
            if self.finish==0:
                self.resultlab=1
                result=soup.findAll('xmp')
                if result:                                              
                    for resu in result:
                        for content in resu.contents:
                            field=repr(content)
                            if  resu.string==None :
                                    break
                            if re.search(self.p,field):
                                print "find in xmp!\n\n"
                                self.finish=1
                                self.rstr+=field


            if self.finish==0:
                self.resultlab=2
                result=soup.findAll('div')
                if result:                                            
                    for resu in result:
                        for content in resu.contents:
                            field=repr(content)
                            if  resu.string==None :
                                    break
                            if re.search(self.p,field):
                                print "find in div!\n\n"
                                self.finish=1
                                self.rstr+=field


            if self.finish==0:
                self.resultlab=3
                result=soup.findAll('textarea')
                if result:                                              
                    for resu in result:
                        for content in resu.contents:
                            field=repr(content)
                            if  resu.string==None :
                                    break
                            if re.search(self.p,field):
                                print "find in textarea!\n\n"
                                
                                self.finish=1
                                self.rstr+=field
            if self.finish==0:   
                self.resultlab=4   
                result=soup.findAll('code')
                if result:                                              
                    for resu in result:
                        for content in resu.contents:
                            field=repr(content)
                            if re.search(self.p,field):
                                self.finish=1
                                self.rstr+=field
            if self.finish==0:
                self.resultlab=5
                result=soup.findAll('span')
                if result:                                           
                    for resu in result:
                        for content in resu.contents:
                            field=repr(content)
                            if  resu.string==None :
                                    break
                            if re.search(self.p,field):
                                print "find in span!\n\n"
                                self.finish=1
                                self.rstr+=field
            if self.finish==0: 
                self.resultlab=6     
                result=soup.findAll('p')
                if result:                                               
                    for resu in result:
                        for content in resu.contents:
                            field=repr(content)
                            if re.search(self.p,field) :
                                self.finish=1
                                self.rstr+=field          
            if self.finish==0:
                self.resultlab=7    
                result=soup.findAll('pre')
                if result:                              
                    for resu in result:
                        for content in resu.contents:
                            field=repr(content)
                            if re.search(self.p,field) or len(re.findall(self.pat,field))>4:
                                self.finish=1
                                self.rstr+=field
                        if self.finish:  
                            break

            if self.finish==0:
                self.resultlab=8                  
                result=soup.findAll('pre')
                if result:                                 
                    for resu in result:
                        for content in resu.contents:
                            if  resu.string==None :
                                    break
                            field=repr(content)
                            if re.search(self.p,field) or len(re.findall(self.pat,field))>4:
                                print "find in pre!\n\n"
                                self.finish=1
                                self.rstr+=field
                        if self.finish:  
                            break
            if self.finish==0:
                self.resultlab=9                
                result=soup.findAll('div')   
                if result:                                     
                    for resu in result:
                        for content in resu.contents:
                            field=repr(content)
                            if  resu.string==None :
                                    break
                            if re.search(self.p,field):
                                    print "find in div!\n\n"
                                    self.finish=1
                                    self.rstr+=field
                        if self.finish:
                            break

            if self.finish==0:
                self.resultlab=10
                results=soup.findAll('td')
                if results:                                           
                    for result in results:
                        taga=result.a
                        if taga:
                            if  result.string==None :
                                    break
                            if re.search(self.pat,repr(taga.contents)) and self.server not in [4808]:
                                self.finish=1
                                self.rstr+=repr(taga.contents)

            if self.finish==0:
                self.resultlab=11
                result=soup.findAll('td')
                if result:                                           
                    for resu in result:
                        for content in resu.contents:
                            field=repr(content)
                            if  resu.string==None :
                                    break
                            if len(re.findall(self.p,field))>4  or  len(re.findall(self.pat,repr(result)) )>4 and self.server not in [4808,38082]:
                                print "find in td!\n\n"
                                self.finish=1
                                self.rstr+=field
   
 
            if self.finish==0:
                self.resultlab=12
                result=soup.findAll('table')
                if result:                                               
                    for resu in result:
                        for content in resu.contents:
                            field=repr(content)
                            if  resu.string==None :
                                    break
                            if re.search(self.p,field):
                                print "find in table!\n\n"
                                self.finish=1
                                self.rstr+=field          

            if self.finish==0:   
                self.resultlab=13
                scripts=soup.findAll('script')
                if scripts:
                    script=scripts[len(scripts)-1]
                    str1=repr(script.contents)
                    beijingp=re.compile(r'\d+ms')
                    if re.search(self.pat,str1) and re.search(beijingp,str1): 
                        self.finish=1
                        self.rstr+=str1
                                                         
            if self.finish==0:
                self.resultlab=14   
                bodys=soup.findAll('body')
                for body in bodys:
                    for content in body.contents:
                        if  content.string==None :
                                    break
                        if re.search(self.p,repr(content)) or len(re.findall(r'\D{0,1}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\D{0,1}&nbsp',repr(content)))>4:
                            print "find in body!\n\n"
                            self.finish=1
                            self.rstr+=repr(content)

            if self.finish==0:
                self.resultlab=15  
                result=re.findall(self.pat,repr(soup.contents))
                if result and len(result)>5 and self.server not in[4808]:
                    print "find in html!\n\n"
                    self.finish=1
                    self.rstr+=repr(soup.contents)
                            
            if self.flag==0:
                if self.rstr:
                    self.resulturl=self.tmpurl
                self.finish=0
                self.rstr=""
                self.post=0
            if self.rstr:
                self.finish=1
                timeformat="%Y-%m-%d %X"
                ltime=time.strftime(timeformat,time.localtime())
                if self.server==174 :   
                    value=(self.id,(self.myspe-3),ltime)
                    sql="select * from Ttable where id='%s' and tid='%s'"%(self.id,(self.myspe-3))
                else:
                    value=(self.id,self.my559,ltime)
                    sql="select * from Ttable where id='%s' and tid='%s'"%(self.id,self.my559)
                con=MySQLdb.connect(host=cf.get("db", "db_host"),user=cf.get("db", "db_user"),passwd=cf.get("db", "db_pass"))
                cur=con.cursor()
                con.select_db(cf.get("db", "db_name"))
                cur.execute(sql)
                result=cur.fetchall()
                if str(self.server) in cf.sections():
                    fun=int(cf.get(str(self.server),"fun"))
                    resultlable=int(cf.get(str(self.server),"resultlab"))
                    if(fun!=self.function) and fun!=10:
                        cf.set(str(self.server),'fun',self.function)
                    if(resultlable!=self.resultlab) and resultlable!=15 and resultlable!=7:
                        cf.set(str(self.server),'resultlab',self.resultlab)
                    cf.write(open("info.conf", "w")) 
                else :
                     cf.add_section(str(self.server))     
                     cf.set(str(self.server),'fun',self.function)
                     cf.set(str(self.server),'resultlab',self.resultlab)
                     cf.set(str(self.server),'resultup','1')
                     cf.write(open("info.conf", "w")) 
                if result:
                    print "INSERTed"
                else:
                    cur.execute("INSERT into Ttable values(%s,%s,%s)",value)
                    cur.execute("commit")
                    print self.server,"has been written in DB!\n","--------------------------------------------"
                sql="select * from AStable where id='%s' "%(self.id)
                cur.execute(sql)
                result=cur.fetchall()
                if(result[0][3]!=self.url):
                    br=mechanize.Browser()
                    try :
                        br.open(self.url)
                        print "url changed"
                        sql="UPDATE AStable SET link='%s' where id='%s' "%(self.url,self.id)
                        cur.execute(sql)
                        cur.execute("commit")
                    except:
                        pass
                cur.close()
                 
def main():
    if len(sys.argv)==3:     
        asn=sys.argv[1]
        ip=sys.argv[2]
        con=MySQLdb.connect(host='localhost',user='root',passwd='19941017')
        cur=con.cursor()
        con.select_db('BGP')
        count=cur.execute("select link from AStable where asn=%d"%int(asn))
        url=((cur.fetchall())[0])[0]
        
        cur.close()
        gt=gettrace(asn,url,ip)  #create a gettrace instance and init!
if __name__=='__main__':
    main()
