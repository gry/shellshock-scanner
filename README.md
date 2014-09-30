shellshock-scanner
==================

A simple Shellshock scanner in python

uses the command sleep in different headers to check the vulnerability.

Receives a host list and a cgi list (and the number of threads). 

It uses only 1 thread per host to avoid time differences caused by multiple requests at the same time.

It can cause some False positives. 
