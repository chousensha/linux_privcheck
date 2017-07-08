#!/usr/bin/python 

import subprocess
import sys
import glob
import os.path

# global var for the no. of lines tail will use
TAIL_LINES = '20'


# helper functions

def writeInfo(data):
    try:
        with open('privinfo.txt', 'a') as f:
            f.write(data + '\n')
        return
    except IOError, e:
        print e
        sys.exit(1)


def runCmd(cmd):
            proc = subprocess.Popen(cmd, stdout = subprocess.PIPE, \
                                    stderr = subprocess.STDOUT)
            stdout, stderr = proc.communicate()
            return stdout
            if stderr != None:
                print stderr
                return

def runCmdShell(cmd):
    """
    For the cmds that required shell=True
    """
    proc = subprocess.Popen(cmd, stdout = subprocess.PIPE, \
                                    stderr = subprocess.STDOUT, shell = True)
    stdout, stderr = proc.communicate()
    return stdout
    if stderr != None:
        print stderr
        return
    


def readFile(f):
    with open(os.path.expanduser(f), 'r') as fd:
        return fd.read()
    

def pipeCmd(cmd1, cmd2):
    """
    The args are lists of commands that will be passed to Popen
    """
    p1 = subprocess.Popen(cmd1, stdout = subprocess.PIPE)
    p2 = subprocess.Popen(cmd2, stdin = p1.stdout, stdout = subprocess.PIPE)
    p1.stdout.close()
    out = p2.communicate()[0]
    p1.wait()
    return out


def fileMsg(f):
    msg = '####### Trying to read ' + f + '... #######\n'
    print msg
    return msg



def cmdMsg(cmd):
    msg = '#######Trying to run ' + str(cmd) + ':#######\n\n'
    print msg
    return msg

def pipeCmdMsg(cmd1, cmd2):
    msg = '#######Trying to run ' + str(cmd1) + ' | ' + str(cmd2) + ':#######\n\n'
    print msg
    return msg

def glbMsg(cmd, g):
    msg = '#######Trying to run ' + str(cmd) + ' on ' + g + ' :#######\n\n'
    print msg
    return msg
    
# functions that perform different checks
    
def searchOS():
    files = ['/etc/issue',
             '/etc/os-release',
             '/proc/version',
             '/etc/lsb-release', 
             '/etc/redhat-release',
             '/etc/profile',
             '/etc/bashrc',
             '~/.bash_profile', 
             '~/.bashrc',
             '~/.bash_logout']
    for f in files: 
        try:
            fmsg = fileMsg(f)
            writeInfo(fmsg)
            out = readFile(f)
            print out
            writeInfo(out)   
        except IOError, e:
            print e
            writeInfo('FAILED: ' + str(e)+ '\n')
            continue

    
    commands = {'uname': ['uname', '-a'],
                'lpstat': ['lpstat', '-a'],
                'env': ['env']}
                                                   
    for c in commands:
        try:
            cmsg = cmdMsg(commands[c])
            writeInfo(cmsg)
            stdout = runCmd(commands[c])
            print stdout    
            writeInfo(stdout)
        except (OSError, IOError), e:
            print e, commands[c]
            writeInfo('FAILED: ' + str(e)+ ' : ' + str(commands[c]) +  '\n')
            continue



    pipecmds = {'bootimg': (['ls', '/boot'], ['grep', 'vmlinuz'])}
    for c in pipecmds:
        try:
            arg1 = pipecmds[c][0]
            arg2 = pipecmds[c][1]
            pmsg = pipeCmdMsg(arg1, arg2)
            writeInfo(pmsg)
            out = pipeCmd(arg1, arg2)
            print out     
            writeInfo(out)
        except (OSError, IOError), e:
            print e, str(pipecmds[c])
            writeInfo('FAILED: ' + str(e)+ ' : ' + str(pipecmds[c]) +  '\n')
            continue
   

        
def chkSrvc():
    commands = {'top': ['top', 'bn', '1'],
                'ps': ['ps', '-ef']}
    for c in commands:
        try:
            cmsg = cmdMsg(commands[c])
            writeInfo(cmsg)
            stdout = runCmd(commands[c])
            print stdout
            writeInfo(stdout)
        except (OSError, IOError), e:
            print e, commands[c]
            writeInfo('FAILED: ' + str(e)+ ' : ' + str(commands[c]) +  '\n')
            continue


    pipecmds = {'rootsrvc': (['ps', '-ef'], ['grep', 'root'])}
    for c in pipecmds:
        try:
            arg1 = pipecmds[c][0]
            arg2 = pipecmds[c][1]
            pmsg = pipeCmdMsg(arg1, arg2)
            writeInfo(pmsg)
            out = pipeCmd(arg1, arg2)     
            print out
            writeInfo(out)
        except (OSError, IOError), e:
            print e, str(pipecmds[c])
            writeInfo('FAILED: ' + str(e)+ ' : ' + str(pipecmds[c]) +  '\n')
            continue



def chkApps():
    commands = {'ls bin': ['ls', '-alh', '/usr/bin/'], 
                'ls sbin': ['ls', '-alh', '/sbin/'],
                'dpkg': ['dpkg', '-l'],
                'rpm': ['rpm', '-qa'],
                'ls apt': ['ls', '-alh', '/var/cache/apt/archives'],
                'ls yum': ['ls', '-alh', '/var/cache/yum/ ']}
    for c in commands:
        try:
            cmsg = cmdMsg(commands[c])
            writeInfo(cmsg)
            stdout = runCmd(commands[c])
            print stdout     
            writeInfo(stdout)
        except (OSError, IOError), e:
            print e, commands[c]
            writeInfo('FAILED: ' + str(e)+ ' : ' + str(commands[c]) +  '\n')
            continue

def chkSrvcSettings():
    files = ['/etc/syslog.conf ',
             '/etc/chttp.conf', 
             '/etc/lighttpd.conf',
             '/etc/cups/cupsd.conf',
             '/etc/inetd.conf', 
             '/etc/apache2/apache2.conf',
             '/etc/my.cnf',
             '/etc/httpd/conf/httpd.conf',
             '/opt/lampp/etc/httpd.conf']
    for f in files:
        try:
            fmsg = fileMsg(f)
            writeInfo(fmsg)
            out = readFile(f)
            print out
            writeInfo(out)   
        except IOError, e:
            print e
            writeInfo('FAILED: ' + str(e)+ '\n')
            continue


def lsJobs():
    commands = {'cron': ['crontab', '-l'],
                'ls spool': ['ls', '-alh', '/var/spool/cron']}                
    for c in commands:
        try:
            cmsg = cmdMsg(commands[c])
            writeInfo(cmsg)
            stdout = runCmd(commands[c])
            print stdout         
            writeInfo(stdout)
        except (OSError, IOError), e:
            print e, commands[c]
            writeInfo('FAILED: ' + str(e)+ ' : ' + str(commands[c]) +  '\n')
            continue
     

    files = ['/etc/at.allow',
             '/etc/at.deny',
             '/etc/cron.allow',
             '/etc/cron.deny',
             '/etc/crontab',
             '/etc/anacrontab',
             '/var/spool/cron/crontabs/root']
    for f in files:
        try:
            fmsg = fileMsg(f)
            writeInfo(fmsg)
            out = readFile(f)
            print out            
            writeInfo(out)   
        except IOError, e:
            print e
            writeInfo('FAILED: ' + str(e)+ '\n')
            continue

    globbed_cron = glob.glob('/etc/cron*')
    lscron = ['ls', '-al']
    for g in globbed_cron:
        try:          
            cmsg = glbMsg(lscron, g)
            print cmsg
            writeInfo(cmsg)
            stdout = runCmd(lscron)
            print stdout       
            writeInfo(stdout)
        except (OSError, IOError), e:
            print e, lscron
            writeInfo('FAILED: ' + str(e)+ ' : ' + str(lscron) +  '\n')
            continue
  
            
  
def netInfo():
    commands = {'ifconfig': ['ifconfig', '-a'],
                'iptables': ['iptables', '-L'],
                'hostname': ['hostname'],
                'dnsdomainname': ['dnsdomainname'],
                'arp': ['arp'],
                'route': ['route']}
    for c in commands:
        try:
            cmsg = cmdMsg(commands[c])
            writeInfo(cmsg)
            stdout = runCmd(commands[c])
            print stdout
            writeInfo(stdout)
        except (OSError, IOError), e:
            print e, commands[c]
            writeInfo('FAILED: ' + str(e)+ ' : ' + str(commands[c]) +  '\n')
            continue
 

    files = ['/etc/network/interfaces',
                 '/etc/sysconfig/network',
                 '/etc/resolv.conf',
                 '/etc/sysconfig/network',
                 '/etc/networks']
    for f in files:
        try:
            fmsg = fileMsg(f)
            writeInfo(fmsg)        
            out = readFile(f)
            print out
            writeInfo(out)   
        except IOError, e:
            print e
            writeInfo('FAILED: ' + str(e)+ '\n')
            continue
    

def currNetStats():
    commands = {'lsof': ['lsof', '-i'],
                'netstat antup': ['netstat', '-antup'],
                'netstat tulpn': ['netstat', '-tulpn'],
                'chkconfig': ['chkconfig', '--list']}

    for c in commands:
        try:
            cmsg = cmdMsg(commands[c])
            writeInfo(cmsg)
            stdout = runCmd(commands[c])
            print stdout
            writeInfo(stdout)
        except (OSError, IOError), e:
            print e, commands[c]
            writeInfo('FAILED: ' + str(e)+ ' : ' + str(commands[c]) +  '\n')
            continue
       


def chkUsers():
    commands = {'id': ['id'],
                 'w': ['w'],
                'last': ['last', '-n', TAIL_LINES],
                'ls root': ['ls', '-ahl', '/root/'],
                'ls home': ['ls', '-ahl', '/home/'],
                'ls mail': ['ls', '-alh', '/var/mail/']}
    for c in commands:
        try:
            cmsg = cmdMsg(commands[c])
            writeInfo(cmsg)
            stdout = runCmd(commands[c])
            print stdout
            writeInfo(stdout)
        except (OSError, IOError), e:
            print e, commands[c]
            writeInfo('FAILED: ' + str(e)+ ' : ' + str(commands[c]) +  '\n')
            continue
       

    files = ['/etc/sudoers',
             '/var/mail/root',
             '/var/spool/mail/root',
             '~/.bash_history',
             '~/.nano_history',
             '~/.atftp_history',
             '~/.mysql_history ',
             '~/.php_history',
			 '/etc/aliases']
    for f in files:
        try:
            fmsg = fileMsg(f)
            writeInfo(fmsg)
            out = readFile(f)
            print out
            writeInfo(out)   
        except IOError, e:
            print e
            writeInfo('FAILED: ' + str(e)+ '\n')
            continue
    
def chkIntrstFiles():
    files = ['/etc/passwd',
             '/etc/group',
             '/etc/shadow',
             '/var/apache2/config.inc',
             'cat /root/anaconda-ks.cfg',
             '~/.ssh/authorized_keys',
             '~/.ssh/identity.pub',
             '~/.ssh/identity',
             '~/.ssh/id_rsa.pub',
             '~/.ssh/id_rsa',
             '~/.ssh/id_dsa.pub',
             '~/.ssh/id_dsa',
             '/etc/ssh/ssh_config',
             '/etc/ssh/sshd_config',
             '/etc/ssh/ssh_host_dsa_key.pub',
             '/etc/ssh/ssh_host_dsa_key',
             '/etc/ssh/ssh_host_rsa_key.pub',
             '/etc/ssh/ssh_host_rsa_key',
             '/etc/ssh/ssh_host_key.pub',
             '/etc/ssh/ssh_host_key',
             '/var/lib/dhcp3/dhclient.leases']
    for f in files:
        try:
                fmsg = fileMsg(f)
                writeInfo(fmsg)
                out = readFile(f)
                print out
                writeInfo(out)   
        except IOError, e:
            print e
            writeInfo('FAILED: ' + str(e)+ '\n')
            continue
    

def chkLogs():
    commands = {'ls log': ['ls', '-alh', '/var/log'],
                'ls mail': ['ls', '-alh', '/var/mail'],
                'ls spool': ['ls', '-alh', '/var/spool'],
                'ls lpd': ['ls', '-alh', '/var/spool/lpd'],
                'ls pgsql': ['ls', '-alh', '/var/lib/pgsql'],
                'ls mysql': ['ls', '-alh', '/var/lib/mysql'],
                'ls dhcp': ['ls', '-alh', '/var/lib/dhcp3/'],
                'ls posgresql': ['ls', '-alh', '/var/log/postgresql/'],
                'ls proftpd': ['ls', '-alh', '/var/log/proftpd/'],
                'ls samba': ['ls', '-alh', '/var/log/samba/'],
                'tail msgs': ['tail', '-n', TAIL_LINES, '/var/log/messages'], #global sys msgs
                'tail dmesg': ['tail', '-n', TAIL_LINES, '/var/log/dmesg'], #kern ring buffer
                'tail auth': ['tail', '-n', TAIL_LINES, '/var/log/auth.log'], #auth info
                'tail booth': ['tail', '-n', TAIL_LINES, '/var/log/boot.log'], #boot info
                'tail daemon': ['tail', '-n', TAIL_LINES, '/var/log/daemon.log'], #daemon info
                'tail dpkg': ['tail', '-n', TAIL_LINES, '/var/log/dpkg.log'], #apt package info
                'tail kern': ['tail', '-n', TAIL_LINES, '/var/log/kern.log'], #kern info
                'tail user.log': ['tail', '-n', TAIL_LINES, '/var/log/user.log'], #user level info
                'tail alts': ['tail', '-n', TAIL_LINES, '/var/log/alternatives.log'], #update alts
                'tail cups': ['tail', '-n', TAIL_LINES, '/var/log/cups'], #print info
                'tail anaconda': ['tail', '-n', TAIL_LINES, '/var/log/anaconda.log'], #installation info
                'tail yum': ['tail', '-n', TAIL_LINES, '/var/log/yum.log'], #rpm pacakge info
                'tail cron': ['tail', '-n', TAIL_LINES, '/var/log/cron'], #cron info
                'tail secure': ['tail', '-n', TAIL_LINES, '/var/log/secure']} #auth msgs

    for c in commands:
        try:
            cmsg = cmdMsg(commands[c])
            writeInfo(cmsg)
            stdout = runCmd(commands[c])
            print stdout         
            writeInfo(stdout)
        except (OSError, IOError), e:
            print e, commands[c]
            writeInfo('FAILED: ' + str(e)+ ' : ' + str(commands[c]) +  '\n')
            continue
        

def chkWebSettings():
    commands = {'ls www': ['ls', '-alhR', '/var/www/'],
                'ls htdocs': ['ls', '-alhR', '/srv/www/htdocs/'],
                'ls lamp': ['ls', '-alhR', '/opt/lampp/htdocs/'],
                'ls html': ['ls', '-alhR', '/var/www/html/']}
    for c in commands:
        try:
            cmsg = cmdMsg(commands[c])
            writeInfo(cmsg)
            stdout = runCmd(commands[c])
            print stdout           
            writeInfo(stdout)
        except (OSError, IOError), e:
            print e, commands[c]
            writeInfo('FAILED: ' + str(e)+ ' : ' + str(commands[c]) +  '\n')
            continue
       

def chkFS():
    commands = {'mount': ['mount'],
                'df' : ['df', '-h']}
    for c in commands:
        try:
            cmsg = cmdMsg(commands[c])
            writeInfo(cmsg)
            stdout = runCmd(commands[c])
            print stdout         
            writeInfo(stdout)
        except (OSError, IOError), e:
            print e, commands[c]
            writeInfo('FAILED: ' + str(e)+ ' : ' + str(commands[c]) +  '\n')
            continue

    files = ['/etc/fstab']
    for f in files:
        try:
            fmsg = fileMsg(f)
            writeInfo(fmsg)
            out = readFile(f)
            print out            
            writeInfo(out)   
        except IOError, e:
            print e
            writeInfo('FAILED: ' + str(e)+ '\n')
            continue
    
    
def findTools():
    commands = {#'find perl': ['perl', '-v'],
                'find python': ['python --version'],
                'find wget': ['which wget'],
                'find nc': ['which nc'],
                'find ruby': ['ruby -v'],
                'find netcat': ['which netcat'],
                'find nmap': ['which nmap'],
		'find java': ['java -version']}
    for c in commands:
        try:
            cmsg = cmdMsg(commands[c])
            writeInfo(cmsg)
            stdout = runCmdShell(commands[c])
            print stdout         
            writeInfo(stdout)
        except (OSError, IOError), e:
            print e, commands[c]
            writeInfo('FAILED: ' + str(e)+ ' : ' + str(commands[c]) +  '\n')
            continue
    pipecmds = {'find gcc': (['gcc', '--version'], ['grep', '-m', '1', 'gcc']),
                'find cc': (['cc', '--version'], ['grep', '-m', '1', 'cc']),
                'find perl': (['perl', '-v'], ['grep', '-m', '1', 'This'])}
    for c in pipecmds:
        try:
            arg1 = pipecmds[c][0]
            arg2 = pipecmds[c][1]
            pmsg = pipeCmdMsg(arg1, arg2)
            writeInfo(pmsg)
            out = pipeCmd(arg1, arg2)
            print out     
            writeInfo(out)
        except (OSError, IOError), e:
            print e, str(pipecmds[c])
            writeInfo('FAILED: ' + str(e)+ ' : ' + str(pipecmds[c]) +  '\n')
            continue
               
def findPerm():
    commands = {'find suid/sgid': ['find / -type f \( -perm +4000 -o -perm +2000 \) -print 2> /dev/null'],
		'find ww dir': ['find / -perm -0002 -type d -print 2> /dev/null']}         
    for c in commands:
        try:
            cmsg = cmdMsg(commands[c])
            writeInfo(cmsg)
            stdout = runCmdShell(commands[c])
            print stdout         
            writeInfo(stdout)
        except (OSError, IOError), e:
            print e, commands[c]
            writeInfo('FAILED: ' + str(e)+ ' : ' + str(commands[c]) +  '\n')
            continue

        
searchOS()
chkSrvc()
chkApps()
chkSrvcSettings()
lsJobs()
netInfo()
currNetStats()
chkUsers()
chkIntrstFiles()
chkLogs()
chkWebSettings()
chkFS()
findTools()
findPerm()
