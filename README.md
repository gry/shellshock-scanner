shellshock-scanner
==================

A simple Shellshock scanner in python


Test 1: uses the command sleep in different headers and check differences between delays to check the vulnerability.
Test 2: uses the command ping -cX 127.0.0.1 and check differences between delays.
Test 3: try to print a string and get it (causes a lot of False Positives)

Receives a host list and a cgi list (and the number of threads). 

It uses only 1 thread per host to avoid time differences caused by multiple requests at the same time.

It can cause some False positives (Retest the possible possitives).

I know is not the most portable code that you have ever seen but... it works ^ ^u. Anyway, any improvement is always welcome :)

TODO Tests:
1. Try to write a file in /var/www and read it? (this would be quite intrusive)
2. Send mail with info 
3. Ping IP address (then have a listener)

Output CSV file
===============
Columns:
+ WARNING : It is set to True if the delay of the request is more than the introduced with the command (sleep 9 == delay more than 9 s)
+ VULNERABLE : It is set to True if Warning is True and the difference between the delays of the normal request and the "shellshock" one is high. 
+ ERROR : It is set to True if an exception happens (usually Timeout or an invalid CGI or Host)
+ The other columns are almost self explanatory

Useful stuff
============

If a 100K lines CSV is a bit Long, you can search quickly for Vulnerable lines with the command:
$ grep '^[^,]*,[^,]*,True' <output.csv>

Or Warning = True lines with:
$ grep '^[^,]*,[^,]*,[^,]*,[^,]*,True' <output.csv>

Have fun :D
