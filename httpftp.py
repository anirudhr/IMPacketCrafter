import httplib
from ftplib import FTP

def inputHTTP():
	n  = int(raw_input("Input number of packets "))
	pDst = raw_input("Enter the destination host ")
	pPort= raw_input("Enter destination port ")
	pTimeOut = int(raw_input("Enter the time out "))
	pMet = raw_input("""Enter the method :
Request:
GET
HEAD
POST
PUT
DELETE
TRACE
CONNECT
""")
	pUri = raw_input("Enter the destination uri ")
	sendHTTP(n, pDst, pPort, pTimeOut, pMet, pUri)
	
def sendHTTP(n, pDst, pPort, pTimeOut, pMet, pUri):
	http = httplib.HTTPConnection(pDst, pPort, timeout=pTimeOut)	
	for i in range(n):
		http.request(pMet, pUri)
	http.close()
	
def inputFTP():
	n  = int(raw_input("Input number of packets "))
	pDst = raw_input("Enter the destination host ")
	pPort= raw_input("Enter destination port ")
	pTimeOut = int(raw_input("Enter the time out "))
	pCmd = raw_input("""Enter command to be sent 
?  	 			to request help or information about the FTP commands
ascii 			to set the mode of file transfer to ASCII
binary 			to set the mode of file transfer to binary
bye 			to exit the FTP environment
cd 				to change directory on the remote machine
close 			to terminate a connection with another computer
close brubeck 	closes the current FTP connection with brubeck, but still leaves you within the FTP environment.
delete 			to delete (remove) a file in the current remote directory (same as rm in UNIX)
get 			to copy one file from the remote machine to the local machine
help 			to request a list of all available FTP commands
lcd 			to change directory on your local machine (same as UNIX cd)
ls 				to list the names of the files in the current remote directory
mkdir 			to make a new directory within the current remote directory
mget 			to copy multiple files from the remote machine to the local machine;
mput 			to copy multiple files from the local machine to the remote machine;
open 			to open a connection with another computer
open brubeck 	opens a new FTP connection with brubeck;
put 			to copy one file from the local machine to the remote machine
pwd 			to find out the pathname of the current directory on the remote machine
quit 			to exit the FTP environment (same as bye)
rmdir 			to to remove (delete) a directory in the current remote directory 
""")
	sendFTP(n, pDst, pPort, pTimeOut, pCmd)
	
def sendFTP(n, pDst, pPort, pTimeOut, pCmd):
	ftp = FTP(pDst, pPort, timeout=pTimeOut)	
	for i in range(n):
		ftp.sendcmd(pCmd)
	ftp.close()

	
#inputHTTP()
inputFTP()
