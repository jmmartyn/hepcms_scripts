#!/usr/bin/python
''' 
This script checks certificate expiration dates in /etc/grid-security (excluding /etc/grid-security/certificates and any .pem file with "key" in its name, however) and emails admins if any of them are going to expire within 1-30 days. NOTE: This script must be run as someone who has access to these certificates (i.e. sudo) for it to function properly. 
'''

#Import necessary modules
import smtplib
import subprocess
import os
 
#Set admins and directory containing certificates
admins = ['jabeen@umd.edu', 'kakw@umd.edu', 'youngho.shin@cern.ch','mnudelli@terpmail.umd.edu']
GRID_SECURITY_DIRS = ['/etc/grid-security/']

#Produces a list of directories in /etc/grid-security/ to search through
if str(os.path.isdir("/etc/grid-security")) == "False" : 
  quit()
os.chdir("/etc/grid-security")
o0 = subprocess.Popen("find . -type d| grep -v './certificates'", stdout=subprocess.PIPE, shell=True)
o0_text = str(o0.communicate())
dirs = o0_text.split(r"\n") 
del dirs[0]
del dirs[-1]
for dir in dirs:
  GRID_SECURITY_DIRS.append("/etc/grid-security" + dir[1:] + "/")
#Creates message string, a list of certificates that will expire soon, and a dictionary for use later
msg = ""
certs_expiring = []
day = {}
#Produces list of .pem files in directories of GRID_SECURITY_DIRS
for i in range(0, len(GRID_SECURITY_DIRS)):
  os.chdir(GRID_SECURITY_DIRS[i])
  o1 = subprocess.Popen("ls | grep .pem | grep -v .pem-old | grep -v empty.pem | grep -v key", stdout=subprocess.PIPE,   shell=True)
  o1_text = str(o1.communicate())
  files = o1_text.split(r"\n") 
  files[0] = files[0][2:]
  del files[-1]
 
  #Checks which certificates will expire in 1-30 day(s); compiles a message containing the expiring certificates and their expiration dates
  for file in files:
    for x in range(1,31):
      o_day = subprocess.Popen("openssl x509 -checkend %d -noout -in %s%s ; echo $?" % ((x*86400), GRID_SECURITY_DIRS[i], file), stdout=subprocess.PIPE, shell=True)
      day_list = str(o_day.communicate()).split(r"\n")
      day_list[0] = day_list[0][2:]
      del day_list[-1]
      day["day%d" % x] = day_list
    
    o_exp = subprocess.Popen("openssl x509 -enddate -noout -in %s%s" % (GRID_SECURITY_DIRS[i], file), stdout=subprocess.PIPE, shell=True)
    exp_date = str(o_exp.communicate()).split(r"\n")
    exp_date = exp_date[0][11:]
    if exp_date == "" :
     msg += "check_cert_expire.py does not have access to %s%s, and its expiration date cannot be determined. \n" % (GRID_SECURITY_DIRS[i], file)
     break
    for y in range(1,31):
      if day["day%d" % y] == ["1"]: 
        msg += "%s%s will expire within %d day(s). Its expiration date is: %s \n" % (GRID_SECURITY_DIRS[i], file, y, exp_date)
        certs_expiring.append(file)
        break
#Emails admins if any certificates are nearing expiration
if msg:
  ohost = subprocess.Popen("hostname", stdout=subprocess.PIPE, shell=True)
  host = str(ohost.communicate())[2:-10]
  msg = "On " + host + ": \n" + msg
  from_addr = 'root@hepcms-hn.umd.edu'
  to_addr = ", ".join(admins)
  subject = "WARNING: Certificates nearing expiration." 
  header = "From: %s\nTo: %s\nSubject: %s\n" % (from_addr, to_addr, subject)
  email = header + msg
  server = smtplib.SMTP('localhost')
  for addr in admins:
      server.sendmail(from_addr, addr, email)
  server.quit()
