#!/usr/bin/python
import time
import test

while True:
    current_time = time.localtime(time.time())
    if((current_time.tm_mday == 1) and (current_time.tm_hour == 1) and (current_time.tm_min == 0) and (current_time.tm_sec == 0)):
	test.main()
    time.sleep(1)

         
