#!/usr/bin/python
#encoding=utf-8

import sys
import urllib
import urllib2  
from urllib2 import *
from bs4 import BeautifulSoup
import re
import socket
import urlparse
import mechanize
import httplib
import os
import ConfigParser
import datetime
import signal

socket.setdefaulttimeout(150)
cf = ConfigParser.ConfigParser()
cf.read("info.conf")
class gettrace:
    def __init__(self,url,ip,tid):
        self.id=tid     #源服务器id（即选择该网站的第几个源服务器，单源网站的id为0）
        self.url=url    #源服务器URL
        self.tmpurl=url #显示traceroute结果的URL 
        self.resulturl=url #第一次traceroute无效，需要再次测试的URL（很少用）
        self.server=url.split('/')[2]#服务器标识符
        self.ip=ip  #目的IP
        self.list={}   #参数列表
        self.post=0   #提交方式
        self.finish=0 #是否完成标识
        self.flag=1    #特殊标识（第一次traceroute无效）
        self.rstr=""   #traceroute结果
        self.my5400=0  #特殊标识（需二次提交）
        self.write=0   #是否写入文本中标识
        
        #不同标签的匹配
        self.attrs=['submit','hidden'] 
        self.buttonp=re.compile('traceroute',re.I)  #button标签正则匹配式
        self.formsp=re.compile(cf.get("label", "formsp"),re.I) #无效form标签正则匹配式
        self.fp=re.compile(cf.get("label", "fp"))  #有效form标签正则匹配式


        #结果的标签中提取数据匹配
        self.textp=re.compile(cf.get("result", "textp")) #text标签中匹配式
        self.p=re.compile(cf.get("result", "p"),re.I) #结果匹配（traceroute结果在一起，中间无html代码分割）  
        self.pat=re.compile(cf.get("result", "pat")) #结果匹配（traceroute结果不在一起，中间有html代码分割）  
        self.asq=re.compile(cf.get("result", "asq"),re.I)#结果格式统一化
        self.FunName=["MechanizeForm","UrllibForm","Twicetraceroute","DirectMechanize","DirectRequest","NotInForm"]
        self.effectlable=["radio","checkbox","frame","iframe","hidden","option","select"]
        self.tags={'radio':['invalid'],"checkbox":['invalid'],'frame':['invalid'],"iframe":['invalid'],'hidden':['invalid'],'option':['invalid'],'select':['invalid']}
    def __call__(self):
        apply(self.ReadingInfo,())
    def ReadingInfo(self):
        self.time1=time.time()#记录时间
        self.specaillist=[] #一些特殊的服务器
        for j in cf.options(self.server):
            if j in self.effectlable :
                a=cf.get(self.server, j).split(',')
                for i in a :
                    self.tags[j].append(i)
        for j in cf.options("SpecialServer"):
            a=cf.get("SpecialServer", j).split(',')
            self.specaillist.append(a)
        functionname= "self."+self.FunName[int(cf.get(self.server, "function"))-1]+"()"
        exec(functionname)#动态加载模块
    
    
    def  MechanizeForm(self):
         try:                                    #直接爬虫         
            br=mechanize.Browser()
            f=br.open(self.url) 
            if not (self.url==f.geturl()):   #URL发生改变
                f.close()
                self.url=f.geturl()
                self.resulturl=self.url
                request=Request(self.url)
                f=urlopen(request)     
            soup=BeautifulSoup(f)
         except:
                pass
         else: 
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
            f.close() 
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
                if form.has_key('method'): #参数提交方式
                    if form['method'].lower()=='post':
                        self.post=1
                if form.has_key('action'): #action标签中有结果提交的URL
                    self.tmpurl=urlparse.urljoin(self.url,form['action']) 
                
                inputs=form.findAll('input',{'name':True})       
                for inp in inputs:
                     if (not inp.has_key('type')) or ( inp['type'].lower() in ['text','textfield'] ):
                         if inp.has_key('name') and (inp['name'] not in ["VIA"]):
                             if not ( inp.has_key('value') and inp['value'] and re.search(self.textp,inp['value']) ):
                                 self.list[inp['name']]=self.ip   
                             elif inp.has_key('value'):
                                 self.list[inp['name']]=inp['value']

                     elif (inp['type'].lower() in self.attrs) and inp.has_key('value'):
                         if (inp['value'] in self.tags['hidden'] )or ('Dynamic' in self.tags['hidden']):
                            self.list[inp['name']]=inp['value']
                      

                     elif inp['type'].lower()=='radio' and inp.has_key('value') and inp['value'] in self.tags['radio']:
                            self.list[inp['name']]=inp['value']
                     elif inp['type'].lower()=='checkbox' and inp.has_key('value') and inp['value'] in self.tags['checkbox']:
                         self.list[inp['name']]=inp['value']
                     elif inp['type'].lower()=='checkbox' and  (not  inp.has_key('value')) :
                         if len(self.tags['checkbox'])>1: 
                            self.list[inp['name']]=self.tags['checkbox'][1]
                     
                     elif inp['type'].lower()=='button' and inp.has_key('value') and re.search(self.buttonp,inp['value']):
                         self.list[inp['name']]=inp['value']     
                #取select标签中的有效值
                selects=form.findAll('select')
                self.number=0
                i=0
                optionflag=0
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
                selects=form.findAll('select')
                i=1
                for select in selects:
                    options=select.findAll('option')
                    if select['name'] in self.tags['select'] and self.server in self.specaillist[0]:
                        for option in options:
                            if option['value'] in self.tags['option']:
                                    break
                            if option.string!=None and option.has_key('value'):
                                if self.id==i:
                                    self.list[select['name']]=option['value']
                                    self.show()
                                    optionflag=1
                                i=i+1
                
                 #多源点服务器循环traceroute所有服务器,服务器选择在checkbox标签中
                i=1
                if self.server in self.specaillist[1]:
                    self.post=0
                    inputs=form.findAll('input',{'name':True})
                    for inp in inputs:
                        if inp['type'].lower()=='checkbox' and re.search('routers',inp['name']) :
                            self.number=self.number+1
                    for inp in inputs:
                        if inp['type'].lower()=='checkbox' and  re.search('routers',inp['name']):
                            if i==self.id:
                                self.list[inp['name']]=inp['value']
                                self.show()
                                optionflag=1
                            i=i+1

                if self.list and optionflag==0:    
                    self.show()   






    def  UrllibForm(self):        # 伪装成浏览器                            
        try:
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
        except :
                pass
 
        else:
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
                         if (inp['value'] in self.tags['hidden'] )or ('Dynamic' in self.tags['hidden']):
                             self.list[inp['name']]=inp['value']
                         
                     elif inp['type'].lower()=='radio' and inp.has_key('value') and inp['value'] in self.tags['radio']:
                         self.list[inp['name']]=inp['value']
                             
                     elif inp['type'].lower()=='checkbox' and inp.has_key('value') and inp['value'] in self.tags['checkbox']:
                         self.list[inp['name']]=inp['value']
                     elif inp['type'].lower()=='button' and inp.has_key('value') and re.search(self.buttonp,inp['value']):
                         self.list[inp['name']]=inp['value']
		
	   #select标签取有效值
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
                        if (self.server in self.specaillist[0]) and select['name'] in self.tags['select'] :
                            i=1
                            for option in options:
                                if option.has_key('value') and option['value'] in self.tags['option']:
                                    break
                                if self.id==i:
                                    if self.server in self.specaillist[2]: #需要解析字符串提取有效值
                                        self.list[select['name']]=option.next.split('\n')[0]
                                    else:
                                        self.list[select['name']]=option['value']                  
                                    self.show()
                                    flag=1    
                                i=i+1
                if self.list and flag==0:    
                    self.show()  
            else:
                pass             

    
    def  DirectMechanize(self):         #直接打开输入目的IP mechanize
        try:
            br=mechanize.Browser()
            f=br.open(self.url)
        except :
            pass
        else:
            try:
                text=f.read()
            except socket.timeout:
                print "timeout!",self.server,"\n"
            else:
                pattern=re.compile(r'isindex',re.I)  
                if re.search(pattern,text):   
                    self.show() 
      
        
    
    def  DirectRequest(self):         #直接打开输入目的IP urllib
        try:
            request=Request(self.url)
            f=urlopen(request)
        except :
            pass
        else:
            try:
                text=f.read()
            except socket.timeout:
                print "timeout!",self.server,"\n"
            else:
                pattern=re.compile(r'isindex',re.I)  
                if re.search(pattern,text):
  
                    self.show()         

    def  NotInForm(self):           #一部分输入不在From表单中
        try:
            br=mechanize.Browser()
            f=br.open(self.url)
            soup=BeautifulSoup(f)
        except :
            pass
        else: 
            flag=0             #目的URL在iframe
            while(1):
                flag=0
                tagiframes=soup.findAll('iframe')
                for tagiframe in tagiframes:
                    if tagiframe.has_key('src') and tagiframe['src'] in self.tags['iframe']:
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
                    break   
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
            i=0
            for select in selects:
                if self.server in self.specaillist[0]:    #在script代码中        
                    if select['name'] in self.tags['select']:
                        script=soup.findAll('script')
                        my = re.compile(r'Option(.*)')
                        mytxt=soup.get_text()
                        lines=re.findall(my,mytxt)
                        for line in lines:
                            if self.id==i:
                                ops=lines[self.id+2].split('"')
                                op = ops[3].encode("utf-8") 
                                self.list[select['name']]=op
                                self.post=1
                                self.show()
                                flag=1
                            i=i+1
                if self.server in self.specaillist[3]: #在form表单外的option中
                    if select['name'] in self.tags['select']:
                        i=1
                        for option in options:
                            if self.id==i:
                                self.list[select['name']]=option['value']
                                self.show()
                                flag=1
                            i=i+1
            if self.list and flag==0 :
                self.show()




    def show(self):
        try:
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
        except :
            pass
        else:
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
            if(int(cf.get(self.server, "resultlable"))==1):             
                result=soup.findAll('xmp')
                if result:                                              
                    for resu in result:
                        for content in resu.contents:
                            field=repr(content)
                            if  resu.string==None :
                                    break
                            if re.search(self.p,field):
                                self.finish=1
                                self.rstr+=field

            if(int(cf.get(self.server, "resultlable"))==2):      
                result=soup.findAll('div')
                if result:                                              
                    for resu in result:
                        for content in resu.contents:
                            field=repr(content)
                            if  resu.string==None :
                                    break
                            if re.search(self.p,field):
                                self.finish=1
                                self.rstr+=field

            if(int(cf.get(self.server, "resultlable"))==3):      
                result=soup.findAll('textarea')
                if result:                                            
                    for resu in result:
                        for content in resu.contents:
                            field=repr(content)
                            if  resu.string==None :
                                    break
                            if re.search(self.p,field):
                                self.finish=1
                                self.rstr+=field


            if(int(cf.get(self.server, "resultlable"))==4):      
                result=soup.findAll('code')
                if result:                                              
                    for resu in result:
                        for content in resu.contents:
                            field=repr(content)
                            if re.search(self.p,field):
                                self.finish=1
                                self.rstr+=field
            if(int(cf.get(self.server, "resultlable"))==5):      
                result=soup.findAll('span')
                if result:                                        
                    for resu in result:
                        for content in resu.contents:
                            field=repr(content)
                            if  resu.string==None :
                                    break
                            if re.search(self.p,field):
                                self.finish=1
                                self.rstr+=field
            
            if(int(cf.get(self.server, "resultlable"))==6):      
                result=soup.findAll('p')
                if result:                                               
                    for resu in result:
                        for content in resu.contents:
                            field=repr(content)
                            if re.search(self.p,field) :
                                self.finish=1
                                self.rstr+=field  

            if(int(cf.get(self.server, "resultlable"))==7):          
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

            if(int(cf.get(self.server, "resultlable"))==8):                       
                result=soup.findAll('pre')
                if result:                              
                    for resu in result:
                        for content in resu.contents:
                            field=repr(content)
                            if  resu.string==None :
                                    break
                            if re.search(self.p,field) or len(re.findall(self.pat,field))>4:
                                self.finish=1
                                self.rstr+=field
                        if self.finish:  
                            break
            if(int(cf.get(self.server, "resultlable"))==9):                      
                result=soup.findAll('div')   
                if result:                                     
                    for resu in result:
                        for content in resu.contents:
                            field=repr(content)
                            if  resu.string==None :
                                    break
                            if re.search(self.p,field):
                                    self.finish=1
                                    self.rstr+=field
                        if self.finish:
                            break
            if(int(cf.get(self.server, "resultlable"))==10):          
                results=soup.findAll('td')
                if results:                                           
                    for result in results:
                        taga=result.a
                        if taga:
                            if re.search(self.pat,repr(taga.contents)) :
                                self.finish=1
                                self.rstr+=repr(taga.contents)

            if(int(cf.get(self.server, "resultlable"))==11):      
                result=soup.findAll('td')
                if result:                                           
                    for resu in result:
                        for content in resu.contents:
                            field=repr(content)
                            if  resu.string==None :
                                    break
                            if len(re.findall(self.p,field))>4  or  len(re.findall(self.pat,repr(result)) )>4 :
                                self.finish=1
                                self.rstr+=field
 
            if(int(cf.get(self.server, "resultlable"))==12):      
                result=soup.findAll('table')
                if result:                                               
                    for resu in result:
                        for content in resu.contents:
                            field=repr(content)
                            if  resu.string==None :
                                    break
                            if re.search(self.p,field):
                                self.finish=1
                                self.rstr+=field          

            if(int(cf.get(self.server, "resultlable"))==13):   
                scripts=soup.findAll('script')
                if scripts:
                    script=scripts[len(scripts)-1]
                    sstr=repr(script.contents)
                    beijingp=re.compile(r'\d+ms')
                    if re.search(self.pat,sstr) and re.search(beijingp,sstr): 
                        self.finish=1
                        self.rstr+=sstr
                                                         
            if(int(cf.get(self.server, "resultlable"))==14):       
                bodys=soup.findAll('body')
                for body in bodys:
                    for content in body.contents:
                        if  content.string==None :
                                    break
                        if re.search(self.p,repr(content)) or len(re.findall(r'\D{0,1}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\D{0,1}&nbutton',repr(content)))>4:
                            self.finish=1
                            self.rstr+=repr(content)

            if(int(cf.get(self.server, "resultlable"))==15):      
                result=re.findall(self.pat,repr(soup.contents))
                if result and len(result)>5 :
                    self.finish=1
                    self.rstr+=repr(soup.contents)
                            
            if  not self.rstr and self.server in self.specaillist[6]: #需要二次traceroute
                self.finish=0
                self.soup = soup
                self.flag = 0
                functionname= "self."+self.FunName[int(cf.get(self.server, "function"))-1]+"()"
                exec(functionname)
            if self.rstr:
                    print "from "+self.url+"to "+self.ip+""
                    today=datetime.date.today()
                    txt=str(today)+"-html.txt"
                    f=open(txt,"a")
                    time2=time.time()
                    f.write("\n"+self.url+"   "+self.ip+"    "+str(self.time1)+"    "+str(time2)+"\n")
                    f.write(self.rstr+"\n")
                    f.close()    
                    self.finish=1
                     #前面所有代码即可提取出原始数据，以下为根据自己需要数据格式统一化,如果某个ASN对应的网站数据格式发生变化，搜寻相应的ASN，改变规则或者添加新的规则
    
                    path=[]
                    lastip='0.0.0.0'
                    p=re.compile(r'\\n')
                    #数据分割
                    mylist=re.split(p,self.rstr) #对结果进行切割
                    mypath=[1]*100 #跳数最大值
                    for i in range(0,99):
                        mypath[i]=0
                    resultpath=[]
                    ms=[]
                    if socket.getaddrinfo((urlparse.urlparse(self.url)).netloc,None):#取得服务器IP
                        serverip=socket.getaddrinfo((urlparse.urlparse(self.url)).netloc,None)[0][4][0]
                    j=-1
                    flag=0
                    if len(mylist)<2: #未切割成功二次切割
                        p=re.compile(cf.get(self.server, "split"))
                        mylist=re.split(p,mylist[0])
                    k=int(cf.get(self.server, "resultup"))
                    for i in mylist: #对每一条数据进行处理
                        if re.findall(self.asq,i)!=[]:
                            dr = re.compile(r'<[^>]+>|u\'' ,re.S)#去HTML标签
                            i = dr.sub('',i)
                            it=re.findall(self.asq,i)
                            if len(it)>0:
                                asnode=it[0]
                                lastip=asnode
                                if (asnode not in [self.ip,serverip]) and (asnode not in ['0.0.0.0']):#如果不是目的IP，服务器IP，以及0.0.0.0，有效
                                        if k==-1:
                                            j=j+1
                                            flag=1
                                        else:
                                            if i[k].isdigit():
                                                j=j+1
                                                flag=1
                                        if flag==1:   
                                            it = list(set(it))
                                            for li in it :
                                                mypath[j]=mypath[j]+1
                                                if(len(it)>5):
                                                        j=j+1
                                                resultpath.append(li)
                    
                    if lastip==self.ip :
                         resultpath.append(asnode)
                    today=datetime.date.today()
                    txt=str(today)+".txt"
                    j=0
                    if self.write==0:
                        f=open(txt,"a")
                        f.write("from "+self.url+"----"+repr(self.id)+"to "+self.ip+"\n------------------------\n")
                        for i in resultpath:
                            if i[0]=='0':
                                i = i[1:]
                            f.write(str(j+1)+":"+i+"\n") 
                            mypath[j]=mypath[j ]-1
                            if mypath[j]<1 :
                                j=j+1
                                if j>99 :
                                    break
                          
                    f.close()
                    self.write=1
                 
def main():
    if len(sys.argv)==4:     
        url=sys.argv[1]
        ip=sys.argv[2]
        tid=sys.argv[3]
        gt=gettrace(url,ip,tid)
        gt()


if __name__=='__main__':
    def handler(signum, frame):
        raise AssertionError
    try:
         signal.signal(signal.SIGALRM, handler)
         signal.alarm(600)
         main()
         signal.alarm(0)
    except AssertionError:
            print " Traceroute timeout"
            os._exit(0)