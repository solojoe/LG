#!/usr/bin/python
#encoding=utf-8

import sys
import os
import socket
import MySQLdb
from threading import Thread
import re
import socket
from DDtrace import gettrace

socket.setdefaulttimeout(60)

def main():
    con=MySQLdb.connect(host='localhost',user='root',passwd='19941017')
    cur=con.cursor()
    con.select_db('BGP')
    count1=cur.execute("select id,tid from Ttable")
    aslist=cur.fetchall()
    f=open("targetip.txt", "r")
    lines=f.readlines()
    count2=0
    for line in lines:
    	count2=count2+1
    count=count1*count2
    k=0
    m=0
    print lines[m].split('\n')[0]
    for i in range(0,count,100):                
    	    threads=[]
	    print "------",i,"--------"
            for j in range(100):
            	pos=i+j
           	if pos>=count:
               	    break
                if k>=count1:
		   k=k-count1
		   m=m+1
                   print lines[m].split('\n')[0]
                targip=lines[m].split('\n')[0]
	    	sql="select asn,link from AStable where id='%s'"%(aslist[(i+j)%count1][0])
	        cur.execute(sql)
   	        result=cur.fetchall()
          	p=gettrace(result[0][1],targip,aslist[(i+j)%count1][1])
            	thread=Thread(target=p)
            	threads.append(thread)
		k=k+1
            length=len(threads)    
            for a in range(length):
            	threads[a].start()
       	    for a in range(length):
            	threads[a].join(2)        
if __name__=='__main__':
    main()
         
        
