#!/usr/bin/env python3
'''
Project Creator: Tan You
'''
import subprocess
import platform
import sys
import socket
import re
import argparse
import traceback
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
numThreads=500
udpAttempts=15
udpTimeout=15
socket.setdefaulttimeout(1)
currentDatetime=None
timeTaken=None

class createPacket():
    '''
    This class takes in a hostname and port number, and upon command,
    will either make a TCP or UDP packet and send it. This is used for
    attempting to verify if a port exists.
    '''
    def __init__(self, hostname, port):
        self.hostname=hostname
        self.port=port
    def sendUDPPkt(self):
        '''
        When sending a UDP packet, if a ICMP destination unreachable
        packet is received, it means that either the udp port is closed,
        or that port does not have a UDP equivalent.
        '''
        data=None
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        try:
            s.settimeout(udpTimeout)
            s.connect_ex((self.hostname,self.port))
            s.sendto(b"ping",(self.hostname,self.port))
            data=s.recvfrom(1024)
        except KeyboardInterrupt as k:
            raise k
        except socket.timeout as t:
            data="Open"
            raise t
        except socket.error as se:
            # if this reaches here, means that the port is closed
            data=None
            raise se
        except Exception as e:
            raise e
        finally:
            s.close()
        return data
    def sendTCPPkt(self):
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        data=None
        try:
            result=s.connect_ex((self.hostname,self.port))
            if (result==0):
                data=s.recv(1024).strip()
        except KeyboardInterrupt as k:
            raise k
        except socket.timeout as t:
            data=t
        except socket.gaierror as g:
            data=None
        except socket.error as se:
            data=se
        except Exception as e:
            raise e
        finally:
            s.close()
        return data
def checkPortOpen(hostname, port, attempts, tcpudp):
    '''
    Given the hostname and port number, determine if the port
    is open.

    the attempt variable is used for UDP, to ensure that enough
    attempts at making a connection has been made on that port
    before determining if it is open or not.

    the tcpudp variable determines if the check is for TCP or
    UDP ports. True is for TCP, false is for UDP.
    '''
    currentPacket=createPacket(hostname, port)
    isPortOpen=False
    service="Unknown"
    banner="Unknown"
    data=None
    if tcpudp: #for TCP, only one attempt is necessary
        attempts=1
    for attempt in range(attempts):
        try:
            if tcpudp:
                data=currentPacket.sendTCPPkt()
            else:
                data=currentPacket.sendUDPPkt()
            if(data!= None):
                isPortOpen=True
                break
            elif(data==None and not tcpudp):
                isPortOpen=False
                break
        except KeyboardInterrupt as k:
            print("\nExiting Program...")
            sys.exit()
        except socket.timeout as t:
            data="Time Out"
            if(not tcpudp):
                isPortOpen=True
            pass
        except socket.gaierror as g:
            print(f"Hostname {ip_host} Could Not Be Resolved! Will skip this host...")
            break
        except socket.error as se:
            if (tcpudp):
                #for TCP port is probably open, but cannot get connection this way.
                data="Unknown"
                isPortOpen=True
            else:
                #for UDP port is probably closed, or protocol does not exist.
                data=None
                isPortOpen=False
                break
        except Exception as e:
            traceback.print_exc(e)
            sys.exit(1)
        finally:
            pass
            #if(s):
            #    s.close()
    if (data):
        try:
            banner=data.decode()
        except Exception as e:
            banner=data
    return (hostname,port,isPortOpen,service,banner)

def printToConsole(listOfResults, isPing):
    '''
    This method takes in a list of tuples of the results
    of the scanning, and prints them properly to the screen.
    if the scanning is a ping, each tuple are in the following format:
    (hostname, isAlive)
    else, it is a port scan, and each tuple are in the following format:
    (hostname,port,isPortOpen,service,banner)
    and for port scan, the list is sorted by hostname, then ports
    '''
    if (isPing):
        print(f'Showing results for ping scan for {currentDatetime}')
        print("HOSTNAME\tISALIVE")
        for i in range(len(listOfResults)):
            print(f"{listOfResults[i][0]}\t{listOfResults[i][1]}")
        print(f'Time taken for scan: {timeTaken} seconds')
    else:
        hostname=listOfResults[0][0]
        print(f'Showing results for port scan for {currentDatetime}')
        print(f'Showing results for host {hostname}:')
        print("PORT\tSTATE\tSERVICE\t\tBANNER")
        for i in range(0,len(listOfResults)):
            if(listOfResults[i][0]==hostname):
                #print(f"{listOfResults[i]}")
                #print(f"{socket.getservbyport(listOfResults[i][1])}")
                print(f"{listOfResults[i][1]}\t{listOfResults[i][2]}\t{socket.getservbyport(listOfResults[i][1])}\t\t{listOfResults[i][4]}")
            else:
                print("===============")
                hostname=listOfResults[i][0]
                print(f'Showing results for host {hostname}:')
                print("PORT\tSTATE\tSERVICE\tBANNER")
        print(f'Time taken for scan: {timeTaken} seconds')

def sendICMPpkt(hostname, count, timeout):
    '''
    Sends a ICMP packet using the ping command in the system
    to the host.
    count is how many packets to send before deciding if the host
    is alive or not.
    timeout is the time in seconds to wait before deciding if a
    ICMP packet is not coming back. note that timeout in windows
    is in miliseconds, so if the platform is windows, the value
    is multiplied by 1000.
    if response == 0, then it means the host is alive.
    '''
    count_arg = '-c'
    #if windows is the platform, modify the arguments accordingly.
    if platform.system().lower() == 'windows':
        count_arg = '-n'
        timeout*=1000
    command = ['ping', count_arg, str(count),'-w',str(timeout), hostname]
    command = " ".join(command)
    #runs the command in a subprocess, with capture_output=True, so that
    #the output of the ping command does not print to the console.
    response = subprocess.run(command,shell=True,capture_output=True,check=False)
    return (hostname,response.returncode == 0)

class ipRange(argparse.Action):
    '''
    This class takes in a range of ip addresses in this format:
    192.168.1.0-255.
    
    This will return a list of ip addresses in that range, inclusive
    of both ends.
    '''
    def __init__(self, option_strings, dest, nargs = None, const = None, default = None, type = None, choices = None, required = False, help = None, metavar = None, deprecated = False):
        super().__init__(option_strings, dest, nargs, const, default, type, choices, required, help, metavar, deprecated)
    def __call__(self, parser, namespace, values, option_string = None):
        pattern=re.compile(r"\b(?:(?:2(?:[0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9])\.){3}(?:(?:2([0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9]))\b-[0-9]+")
        if (not pattern.match(values[0])):
            raise argparse.ArgumentTypeError("[!] Given ip address range must be in proper format. Use '-h' for more information.")
        range=values[0].split('-')
        ip_octets=range[0].split('.')
        start_range=int(ip_octets[3])
        end_range=int(range[1])
        if (not((0<=start_range<=255) and (0<=end_range<=255))):
            raise argparse.ArgumentTypeError("[!] Octet range must be between 0-255 inclusive. Use '-h' for more information.")
        if(start_range >= end_range):
            raise argparse.ArgumentTypeError("[!] Start range of ip address must be less than end range. Use '-h' for more information.")
        temp_list=[]
        while start_range <= end_range:
            temp_list.append(ip_octets[0]+'.'+ip_octets[1]+'.'+ip_octets[2]+'.'+str(start_range))
            start_range+=1
        setattr(namespace,self.dest,temp_list)
        #return super().__call__(parser, namespace, values, option_string)

class portRange(argparse.Action):
    '''
    This class takes in a range of port numbers
    and returns a list of port numbers.

    This will return a list of port numbers,
    inclusive of both ends.
    '''
    def __init__(self, option_strings, dest, nargs = None, const = None, default = None, type = None, choices = None, required = False, help = None, metavar = None, deprecated = False):
        super().__init__(option_strings, dest, nargs, const, default, type, choices, required, help, metavar, deprecated)
    def __call__(self, parser, namespace, values, option_string = None):
        pattern=re.compile(r'[0-9]+-[0-9]+')
        if (not pattern.match(values[0])):
            raise argparse.ArgumentTypeError("[!] Given port number range must be in proper format. Use '-h' for more information.")
        range=values[0].split('-')
        start_range=int(range[0])
        end_range=int(range[1])
        if (not((1<=start_range<=65535) and (1<=end_range<=65535))):
            raise argparse.ArgumentTypeError("[!] Range of port numbers must be between 1-65535 inclusive. Use '-h' for more information.")
        if(start_range>=end_range):
            raise argparse.ArgumentTypeError("[!] Start range of port number must be less than end range. Use '-h' for more information.")
        temp_list=[]
        while start_range <= end_range:
            temp_list.append(start_range)
            start_range+=1
        setattr(namespace,self.dest,temp_list)
        #return super().__call__(parser, namespace, values, option_string)

#add a description and epilog examples to the help menu.
parser = argparse.ArgumentParser(description='''
A simple port scanner made by Tan You.
'''
,epilog='''
Examples:
python CCK2_250506.s29.py -i 192.168.1.1 -p 23
python CCK2_250506.s29.py -i 192.168.1.1 10.1.2.3 -p 23 80
python CCK2_250506.s29.py -i scanme.nmap.org 10.1.2.3 -p 23 80
python CCK2_250506.s29.py -i 10.1.1.1 -p 53 -u
python CCK2_250506.s29.py -I 192.168.1.23-123 -p 80
python CCK2_250506.s29.py -I 10.1.1.1-245 -P 23-80
python CCK2_250506.s29.py -I 10.1.1.1-245 -pi
python CCK2_250506.s29.py -I 10.1.1.1-245 -pi -o
python CCK2_250506.s29.py -I 10.1.1.1-245 -pi -o example.txt
'''
,formatter_class=argparse.RawTextHelpFormatter
)

#add ip range, port range and tcpudp arguments
parser.add_argument('-i', '--ips',nargs='+',dest='ip_list',metavar="192.168.1.1 scanme.nmap.org", help='One or more list of ip addresses and/or hostnames, space seperated.')
parser.add_argument('-I', '--ipRange',nargs=1,dest='ip_list', action=ipRange, help='A range of ip addresses in this format: 192.168.1.0-255')
parser.add_argument('-p','--ports', nargs='+', dest='port_list',type=int,choices=range(0,65536),metavar="23 80 443",help='One or more list of port numbers, space seperated.')
parser.add_argument('-P','--portRange', nargs=1, dest='port_list',action=portRange,help='A range of ports in this format: 10-12345')
parser.add_argument('-u','--udp',dest='tcpudp',default=True,action='store_false',help="Specifically check for UDP ports. By default, TCP ports are checked.")
parser.add_argument('-o','--output',nargs="?",dest='output',default=argparse.SUPPRESS,metavar="scan_output.txt",help="Results will be output into a file. If no name of the file is given,\nthe default name will be the date and time the scan took place.")
parser.add_argument('-pi','--ping',dest='ping',default=False,action='store_true',help="Do a ping scan on the given ip addresses and/or hostnames.")


try:
    args=parser.parse_args()
except argparse.ArgumentTypeError as ate:
    print(ate)
    sys.exit(0)

#check if either one is True:
#1. both args.ip_list and args.ping is True. OR
#2. both args.ip_list and args.port_list are given.
#if not true, return a respective error.
if (args.ping and not args.ip_list):
    parser.error("[!] Please give at least one ip address or hostname for a ping scan. Use '-h' for more information")
elif (not args.ping and not (args.ip_list and args.port_list)):
    parser.error("[!] Please give at least one ip address or hostname and one port number for a port scan. Use '-h' for more information")

#If the output argument was used, it will show up in args.
#Then a check will determine if a name was given or not.
#If no name is given, it will be given the default name
#of the current date and time.
currentDatetime=datetime.now().strftime("%Y-%m-%d_%H.%M.%S")
if("output" in args):
    if (args.output == None):
        args.output = f"{currentDatetime}.txt"

starttime=time.time()
#run a number of threads for a given command, and return their results
#to a list as completed.
all_results=[]
if (args.ping):
    with ThreadPoolExecutor(numThreads) as executor:
        futures=[]
        for ip_host in args.ip_list:
            futures.append(executor.submit(sendICMPpkt,ip_host,2,2))
        for future in as_completed(futures):
            try:
                all_results.append(future.result())
            except Exception as e:
                traceback.print_exception(e)
else:
    with ThreadPoolExecutor(numThreads) as executor:
        futures=[]
        for ip_host in args.ip_list:
            print(f"Port Scanning {ip_host}")
            futures=[]
            for port_num in args.port_list:
                futures.append(executor.submit(checkPortOpen,ip_host,port_num,udpAttempts,args.tcpudp))
            for future in as_completed(futures):
                try:
                    if(future.result()[2]):
                        all_results.append(future.result())
                except Exception as e:
                    traceback.print_exception(e)
timeTaken=time.time() - starttime
sorted_results=sorted(all_results,key=lambda x: (x[0], x[1]))
printToConsole(sorted_results, args.ping)

#if output is requested, write the results to the file.
if("output" in args):
    if(args.ping):
        with open(args.output,"w") as f:
            f.write(f'Showing results for ping scan for {currentDatetime}\n')
            f.write("HOSTNAME\tISALIVE\n")
            for i in range(len(sorted_results)):
                f.write(f"{sorted_results[i][0]}\t{sorted_results[i][1]}\n")
            f.write(f'Time taken for scan: {timeTaken} seconds')
    else:
        hostname=sorted_results[0][0]
        with open(args.output,"w") as f:
            f.write(f'Showing results for port scan for {currentDatetime}\n')
            f.write(f'Results of host {hostname}:\n')
            f.write("HOSTNAME\tPORT\tSTATE\tSERVICE\tBANNER\n")
            for i in range(len(sorted_results)):
                if(sorted_results[i][0]==hostname):
                    f.write(f"{hostname}\t{sorted_results[i][1]}\t{sorted_results[i][2]}\t{socket.getservbyport(sorted_results[i][1])}\t{sorted_results[i][4]}\n")            
                else:
                    f.write("===============\n")
                    hostname=sorted_results[i][0]
                    f.write(f'Results of host {hostname}:\n')
                    f.write("HOSTNAME\tPORT\tSTATE\tSERVICE\tBANNER\n")
            f.write(f'Time taken for scan: {timeTaken} seconds')