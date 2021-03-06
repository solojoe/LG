# !/usr/bin/env python
# -*- coding:utf-8 -*-

import Queue
import threading
import time
import MySQLdb
from DDtrace import gettrace

class WorkManager(object):
    def __init__(self, work_num,thread_num):
        self.work_queue = Queue.Queue()
        self.threads = []
        self.__init_work_queue(work_num)
        self.__init_thread_pool(thread_num)

    def __init_thread_pool(self,thread_num):
        for i in range(thread_num):
            self.threads.append(Work(self.work_queue))

    def __init_work_queue(self, jobs_num):
        for i in jobs_num:
            self.add_job(do_job, i)

    def add_job(self, func, args):
        self.work_queue.put((func, args))
 
    def wait_allcomplete(self):
        for item in self.threads:
            if item.isAlive():	
		item.join()

class Work(threading.Thread):
    def __init__(self, work_queue):
        threading.Thread.__init__(self)
        self.work_queue = work_queue
        self.start()

    def run(self):
        while True:
            try:
                do, args = self.work_queue.get(block=False)
                do(args)
                self.work_queue.task_done()
            except:
                break

def get_ip():
    con=MySQLdb.connect(host='localhost',user='root',passwd='19941017')
    cur=con.cursor()
    con.select_db('BGP')
    
    count=cur.execute("select id,tid from Ttable")
    aslist=cur.fetchall()
    Serverlist=[]
    for i in range(count):
	sql="select asn,link from AStable where id='%s'"%(aslist[i][0])
	cur.execute(sql)
   	result=cur.fetchall()
	Serverinfo=[result[0][1],aslist[i][1]]
	Serverlist.append(Serverinfo)
    f=open("targetip.txt", "r")
    lines=f.readlines()
    Allwork=[]
    for line in lines:
	target_ip=line.split('\n')[0]
	for i in Serverlist:
	    i.append(target_ip)
	    Allwork.append(i)
    return Allwork

def do_job(args):
    work=gettrace(args[0],args[2],args[1])
    work()
if __name__ == '__main__':
    start = time.time()
    work_manager =  WorkManager(get_ip(), 300) #get_ip()
    work_manager.wait_allcomplete()
    end = time.time()
    print "cost all time: %s" % (end-start)
