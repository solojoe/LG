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
import os
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
        self.mynuUrllibFormer=0#多源服务器中服务器总数目
        self.flag=1    
        self.rstr=""
        self.my5400=0
        self.function=0
        self.resultlab=0
        #不同标签的匹配
        self.attrs=['submit','hidden']
        self.buttonp=re.compile('traceroute',re.I)  #button标签正则匹配式
        self.formsp=re.compile(cf.get("label", "formsp"),re.I)
        self.fp=re.compile(cf.get("label", "fp"))


        #结果的标签中提取数据匹配
        self.textp=re.compile(cf.get("result", "textp"))
        self.p=re.compile(cf.get("result", "p"),re.I)  #traceroute result forMechanizeFormt
        self.pat=re.compile(cf.get("result", "pat"))  #input=text ip
        self.effectlable=["radio","checkbox","frame","iframe","hidden","option","select"]
        self.tags={'radio':['invalid'],"checkbox":['invalid'],'frame':['invalid'],"iframe":['invalid'],'hidden':['invalid'],'option':['invalid'],'select':['invalid']}
        self.FunName=["MechanizeForm","UrllibForm","Twicetraceroute","DirectMechanize","DirectRequest","NotInForm"]

    def __call__(self):
        apply(self.ReadingInfo,())
    def ReadingInfo(self):
        self.specaillist=[] #一些特殊的服务器
        for k in cf.sections():
            for j in cf.options(k):
                if j in self.effectlable :
                    a=cf.get(k,j).split(',')
                    for i in a :
                        if i not in self.tags[j]:
                            self.tags[j].append(i)
        for j in cf.options("SpecialServer"):
            a=cf.get("SpecialServer", j).split(',')
            self.specaillist.append(a)
        self.MechanizeForm()

    def MechanizeForm(self):                                      #直接爬虫         
        try:
            print "begin MechanizeForm()","\n"
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
            print "trying UrllibForm()","\n"
            self.UrllibForm()
        except URLError,e:         
            if 'telnet' in e.reason:
                self.mi()
            else:
                print "URLError:",e.reason,"\n"
                print "trying UrllibForm()","\n"
                self.UrllibForm()
        except socket.timeout:
            print "timeout!","\n"
            print "trying UrllibForm()","\n"
            self.UrllibForm()
        except TypeError:  
            print "TypeERROR!"
            print "trying UrllibForm()","\n"
            self.UrllibForm()
        except IOError,e:
            print "IOError"
            print "trying UrllibForm()","\n"
            self.UrllibForm()
        except Exception:
            print "the page cannot be opened correctly!"
            print "trying UrllibForm()","\n"
            self.UrllibForm()
 
        else: 
            self.function=1    
            f.close()
            flag=0             #真正的URL在frame
            while(1):
                flag=0
                tagframes=soup.findAll('frame')
                for tagframe in tagframes:
                    if tagframe.has_key('src') and re.search(self.tags['frame'],tagframe['src']):
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
            while(1): #真正的URL在iframe中
                flag=0
                tagframes=soup.findAll('iframe')
                for tagframe in tagframes:
                    if tagframe.has_key('src') and tagframe['src'] in self.tags['iframe']:
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
       
            self.tmpurl=self.url,"\n\n"  
            
            forms=soup.findAll('form')
            for form in forms:
                if self.finish:
                    break
                if len(forms)>1:
                    if re.search(self.fp,repr(form)) :    #找到我们需要的from表单
                        if not re.search(self.formsp,repr(form.contents)) :
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

                inputs=form.findAll('input',{'name':True})       
                for inp in inputs:
                     if (not inp.has_key('type')) or ( inp['type'].lower() in ['text','textfield'] ):
                         if inp.has_key('name') and (inp['name'] not in ["VIA"]):
                             if not ( inp.has_key('value') and inp['value'] and re.search(self.textp,inp['value']) ):
                                 self.list[inp['name']]=self.ip   
                             elif inp.has_key('value'):
                                 self.list[inp['name']]=inp['value']

                     elif (inp['type'].lower() in self.attrs) and inp.has_key('value'):
                         if (inp['value'] in self.tags['hidden'] ) :
                            self.list[inp['name']]=inp['value']
                      

                     elif inp['type'].lower()=='radio' and inp.has_key('value') and inp['value'] in self.tags['radio']:
                            self.list[inp['name']]=inp['value']
                     elif inp['type'].lower()=='checkbox' and inp.has_key('value') and inp['value'] in self.tags['checkbox']:
                         self.list[inp['name']]=inp['value']
                     elif inp['type'].lower()=='button' and inp.has_key('value') and re.search(self.buttonp,inp['value']):
                         self.list[inp['name']]=inp['value']    
                #取select标签中的有效值
                selects=form.findAll('select')
                optionflag=0
                self.number=0
                i=0
                for select in selects:
                    options=select.findAll('option')
                    for option in options:#option标签下几种取值
                        if option.has_key('value') and option['value'] in self.tags['option']:#直接取值
                            self.list[select['name']]=option['value']
                            break
                        elif (not option.has_key('value') ) and (option.string!=None) :  #HTML中取值
                            if option.string in self.tags['option'] :
                                self.list[select['name']]=option.string
                            break
                #多源点服务器循环traceroute所有服务器,服务器选择在option标签中
                i=1
                selects=form.findAll('select')
                for select in selects:
                    options=select.findAll('option')
                    if select['name'] in self.tags['select'] :
                        for option in options:
                            if option['value'] in self.tags['option']:
                                    break
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
                                        self.MechanizeForm()
                                i=i+1
                                optionflag=1
                
                 #多源点服务器循环traceroute所有服务器,服务器选择在checkbox标签中
                i=1
                if self.server in self.specaillist[1]:
                    inputs=form.findAll('input',{'name':True})
                    for inp in inputs:
                        if inp['type'].lower()=='checkbox' and re.search('routers',inp['name']) :
                            self.number=self.number+1
                    for inp in inputs:
                        if inp['type'].lower()=='checkbox' and  re.search('routers',inp['name']):
                            if i==self.my559:
                                self.list[inp['name']]=inp['value']
                                self.my559=self.my559+1
                                if self.server in self.specaillist[1]:
                                    self.post=0
                                self.show()
                                if self.my559<self.number:
                                    self.finish=0
                                    self.MechanizeForm()
                                optionflag=1
                            i=i+1
                if self.list and optionflag==0:    
                    self.show()   #if the result is MechanizeFormtched in show(),then self.finish=1
            else:
                if self.finish==0:
                    self.UrllibForm()







    def UrllibForm(self):        # 伪装成浏览器                            
        try:
            print "begin UrllibForm()","\n"
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
            if self.flag==0: #（二次提交）
                soup=self.soup
                self.flag = 1
        except HTTPError,e:
            print "HTTPError:",self.server,"\n"
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
            flag=0             
            while(1):
                flag=0
                tagframes=soup.findAll('frame')
                for tagframe in tagframes:
                    if tagframe.has_key('src') and re.search(self.tags['frame'],tagframe['src']):
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
            while(1): 
                flag=0
                tagframes=soup.findAll('iframe')
                for tagframe in tagframes:
                    if tagframe.has_key('src') and tagframe['src'] in self.tags['iframe']:
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
            f.close()   
            
            self.tmpurl=self.url  
            forms=soup.findAll('form')
            for form in forms:
                if self.finish:
                    break
                if len(forms)>1:
                    if re.search(self.fp,repr(form)) : 
                        if not  re.search(self.formsp,repr(form.contents)) : 
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
         
                             elif inp.has_key('value'):
                                 self.list[inp['name']]=inp['value']
                                 
                     elif (inp['type'].lower() in self.attrs) and inp.has_key('value'):
                         if (inp['value'] in self.tags['hidden'] ) :
                             self.list[inp['name']]=inp['value']
                         
                     elif inp['type'].lower()=='radio' and inp.has_key('value') and inp['value'] in self.tags['radio']:
                         self.list[inp['name']]=inp['value']
                             
                     elif inp['type'].lower()=='checkbox' and inp.has_key('value') and inp['value'] in self.tags['checkbox']:
                         self.list[inp['name']]=inp['value']
                     elif inp['type'].lower()=='button' and inp.has_key('value') and re.search(self.buttonp,inp['value']):
                         self.list[inp['name']]=inp['value']
                     
                selects=form.findAll('select')
                flag=0
                for select in selects:
                    options=select.findAll('option')
                    for option in options:
                        if (self.server in self.specaillist[2]) and (select['name'] in self.tags['select']):
                            self.list[select['name']]=option.next.split('\n')[0]
                            break
                        if option.has_key('value') and option['value'] in self.tags['option']:
                            self.list[select.get('name')]=option['value']
                            break

                     #多源服务器
                    self.number=0
                    if select.has_key('name'):     
                        if  select['name'] in self.tags['select'] :
                            i=1
                            for option in options:
                                if option.has_key('value') and option['value'] in self.tags['option']:
                                    break
                                self.number=self.number+1
                            for option in options:
                                if self.my559<self.number and self.my559==i:
                                    if self.server in self.specaillist[2]: #需要解析字符串提取有效值
                                        self.list[select['name']]=option.next.split('\n')[0]
                                    else:
                                        self.list[select['name']]=option['value']      
                                    self.my559=self.my559+1
                                    self.show()
                                    flag=1
                                    if self.my559<self.number:
                                        self.finish=0
                                        self.post=1
                                        self.UrllibForm()
                                i=i+1
                if self.list and flag==0:    
                    self.show()  
            else:
                if self.finish==0:
                    self.DirectMechanize()                   

    
    def DirectMechanize(self):         #直接打开输入目的IP mechanize
        try:
            print "begin DirectMechanize()","\n\n"
            br=mechanize.Browser()
            f=br.open(self.url)
        except HTTPError,e:
            print "HTTPError:",e.code,"\n"
            print "trying DirectRequest()\n"
            self.me()
        except URLError,e:
            print "URLError:",e.reason,"\n"
            print "trying DirectRequest()\n"
            self.me()
        except socket.timeout:
            print "timeout!","\n"
            print "trying DirectRequest()\n"
            self.me()
        except TypeError:  
            print "TypeERROR!"
            print "trying DirectRequest()\n"
            self.me()
        except IOError,e:
            print "IOError"
            print "trying DirectRequest()\n"
            self.me()
        except Exception:
            print "the page cannot be opened correctly!"
            print "trying DirectRequest()\n"
            self.me()
        else:
            try:
                self.function=4
                text=f.read()
            except socket.timeout:
                print "timeout!",self.server,"\n"
                print "trying DirectRequest()\n"
                self.me()
            else:
                pattern=re.compile(r'isindex',re.I)  
                if re.search(pattern,text): 
                    self.show()
                if self.finish==0:
                    self.DirectRequest()    
      
        
    
    def DirectRequest(self):         #直接打开输入目的IP urllib
        try:
            print "begin DirectRequest()","\n\n"
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
                    self.show()
                if self.finish==0:
                    self.NotInForm()            

    def NotInForm(self):           #一部分输入不在From表单中
        try:
            print "begin NotInForm()","\n\n"
            br=mechanize.Browser()
            f=br.open(self.url)
            soup=BeautifulSoup(f)
        except :
            print "Error"
        else: 
            self.function=6
            f.close()
            self.tmpurl=self.url
            forms=soup.findAll('form')
            self.list={}
            for form in forms:
                if len(forms)>1:
                    if re.search(self.fp,repr(form)) :  
                        if not  re.search(self.fp,repr(form.contents)) :
                            continue
                if form.has_key('method') and form['method'].lower()=='post':
                    self.post=1
                if form.has_key('action'):  
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

                        elif inp.has_key('value'):
                            self.list[inp['name']]=inp['value']
                elif (inp['type'].lower() in self.attrs) and inp.has_key('value'):
                    if inp['value'] in self.tags['hidden'] :
                        self.list[inp['name']]=inp['value']
                    
                elif inp['type'].lower()=='radio' and inp.has_key('value') and inp['value'] in self.tags['radio']:
                    self.list[inp['name']]=inp['value']

                elif inp['type'].lower()=='checkbox' and inp.has_key('value') and inp['value'] in self.tags['checkbox']:
                    self.list[inp['name']]=inp['value']
                elif inp['type'].lower()=='button' and inp.has_key('value') and re.search(self.buttonp,inp['value']):
                    self.list[inp['name']]=inp['value']

            flag=0        
            selects=soup.findAll('select')
            for select in selects:
                options=select.findAll('option')
                  
                for option in options:
                    if option.has_key('value') and option['value'] in self.tags['option'] and select.has_key('name'):
                        self.list[select['name']]=option['value']
                        break
                    elif (not option.has_key('value') ) and (option.string!=None) :  #HTML中取值
                            if option.string in self.tags['option'] :
                                self.list[select['name']]=option.string
                            break
                    elif select.has_key('name'):
                        if select['name'] in self.tags['select'] :
                            self.list[select['name']]=option['value']
            #输入不全部在form表单的特殊多源服务器
            for select in selects:
                if select['name'] in self.tags['select']:
                        self.number=0
                        i=0
                        for option in options:
                            self.number=self.number+1
                        for option in options:
                            if self.my559==i and self.my559<self.number:
                                self.list[select['name']]=option['value']
                                self.my559=self.my559+1
                                self.show()
                                flag =1     
                                if self.my559<self.number:
                                    self.finish=0
                                    self.post=1
                                    self.MechanizeForm()
                            i=i+1               
                if self.server in self.specaillist[3]:    #在script代码中        
                    if select['name'] in self.tags['select']:
                        script=soup.findAll('script')
                        my = re.compile(r'Option(.*)')
                        mytxt=soup.get_text()
                        lines=re.findall(my,mytxt)
                        self.number=0
                        for line in lines:
                            self.number=self.number+1
                        if self.my599<=self.number:
                            ops=lines[self.myspe].split('"')
                            op = ops[3].encode("utf-8") 
                            self.list[select['name']]=op
                            self.post=1
                            self.show()
                            flag=1
                            self.myspe=self.myspe+1
                            if self.my599<self.number:
                                self.finish=0
                                self.NotInForm()
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
                        if self.server in self.specaillist[7]:
                            self.tmpurl=urlparse.urljoin(self.tmpurl,"?router="+self.list['router']+"&query="+self.list['query']+"&parameter="+self.list['parameter'])
                        elif self.server in self.specaillist[8] :
                            self.tmpurl=self.resulturl+"tracert?host="+self.ip
                        elif self.server in self.specaillist[9] :
                            self.tmpurl=urlparse.urljoin(self.tmpurl,"/ajax.php?"+urllib.urlencode(self.list))
                        elif self.server in self.specaillist[10] :
                            self.tmpurl=urlparse.urljoin(self.tmpurl,"?target="+self.ip+"&function=traceroute")
                        else :
                            self.tmpurl=urlparse.urljoin(self.tmpurl,"?"+urllib.urlencode(self.list))
                        f=urllib.urlopen(self.tmpurl)
                else:
                    if (self.url)[len(self.url)-1]!='?':
                        f=urllib.urlopen(self.url+"?"+self.ip)  
                    else:
                        f=urllib.urlopen(self.url+self.ip)        
            soup=BeautifulSoup(f)     
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
                tagiframes=soup.findAll('iframe') #结果在iframe中
                for tagiframe in tagiframes:
                    if tagiframe.has_key('src') and self.server in self.specaillist[4]:
                        if (self.tmpurl)[len(self.tmpurl)-1]!='/' :
                            self.tmpurl+="/"
                        try:
                            self.tmpurl=urlparse.urljoin(self.tmpurl,tagiframe['src'])
                            f=urllib.urlopen(self.tmpurl)
                            soup=BeautifulSoup(f)
                            flag=0
                        except :
                            print "error"
                        break 
                tagiframes=soup.findAll('frame') #结果在frame中
                for tagiframe in tagiframes:
                    if tagiframe.has_key('src') and self.server in self.specaillist[5]:
                        if (self.tmpurl)[len(self.tmpurl)-1]!='/' :
                            self.tmpurl+="/"
                        try:
                            self.tmpurl=urlparse.urljoin(self.tmpurl,tagiframe['src'])
                            f=urllib.urlopen(self.tmpurl)
                            soup=BeautifulSoup(f)
                            flag=0
                        except :
                            print "error"
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
                            if re.search(self.pat,repr(taga.contents)) :
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
                            if len(re.findall(self.p,field))>4  or  len(re.findall(self.pat,repr(result)) )>4 :
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
                if result and len(result)>5 :
                    print "find in html!\n\n"
                    self.finish=1
                    self.rstr+=repr(soup.contents)
                            
            if  not self.rstr and self.server in self.specaillist[6]: #需要二次traceroute
                self.finish=0
                self.soup = soup
                self.flag = 0
                functionname= "self."+self.FunName[int(cf.get(self.server, "function"))-1]+"()"
                exec(functionname)
            if self.rstr:
                self.finish=1
                timeforMechanizeFormt="%Y-%m-%d %X"
                ltime=time.strftime(timeforMechanizeFormt,time.localtime())
                value=(self.id,self.my559,ltime)
                sql="select * from Ttable where id='%s' and tid='%s'"%(self.id,self.my559)
                con=MySQLdb.connect(host=cf.get("db", "db_host"),user=cf.get("db", "db_user"),passwd=cf.get("db", "db_pass"))
                cur=con.cursor()
                con.select_db(cf.get("db", "db_name"))
                cur.execute(sql)
                result=cur.fetchall()
                if self.server not in cf.sections():
                     cf.add_section(str(self.server))     
                     cf.set(self.server,'funtion',self.function)
                     cf.set(self.server,'resultlable',self.resultlab)
                     cf.set(self.server,'resultup','1')
                     for i in self.list:
                        if i in self.effectlable and  self.list[i] in self.tags[i] :
                            cf.set(self.server,i,self.list[i])
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
                 
def MechanizeFormin():
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
if __name__=='__MechanizeFormin__':
    MechanizeFormin()
