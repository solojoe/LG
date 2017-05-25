# !/usr/bin/env python
# -*- coding:utf-8 -*-

import Queue
import threading
import time
import MySQLdb
from DDtrace import gettrace

Result=[]
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



def do_job(args):
    work=gettrace(args[0],args[2],args[1])
    work()
    Result.append([args[3],work.dresult,work.orireuslt])
