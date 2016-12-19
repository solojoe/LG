#!/usr/bin/python
#encoding=utf-8

import sys
import os
import socket
import MySQLdb
from threading import Thread
import re
import socket
import ConfigParser
from testttrace import gettrace

socket.setdefaulttimeout(150)

url=re.compile(r'^http://')

def main():
    cf = ConfigParser.ConfigParser()
    cf.read("info.conf")
    con=MySQLdb.connect(host=cf.get("db", "db_host"),user= cf.get("db", "db_user"),passwd= cf.get("db", "db_pass"))
    cur1=con.cursor()
    con.select_db(cf.get("db", "db_name"))
    # 如果需要重新测试则删除表中所有元素
    #cur1.execute("truncate Ttable")  
    
    cur2=con.cursor()
    con.select_db(cf.get("db", "db_name"))
    count1=cur2.execute("select id,asn,link from AStable ")
    result=cur2.fetchall()         
                     
    tgtip="202.118.236.190"
    for i in range(0,count1,1):                
    	    threads=[]
            for j in range(1):
            	pos=i+j
		if pos>=count1:
		    break
          	p=gettrace(result[i+j][0],result[i+j][2],tgtip)
            	thread=Thread(target=p)
            	threads.append(thread)
	   	print "\n----------from ",result[i+j][1],"to","HIT[",tgtip,"]----------------------------"
            length=len(threads)    
            for a in range(length):
            	threads[a].start()
       	    for a in range(length):
            	threads[a].join()   
                
        
if __name__=='__main__':
    main()
         
