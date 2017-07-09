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
            if stderr != None:
                print stderr
                return
            return stdout


def runCmdShell(cmd):
    """
    For the cmds that required shell=True
    """
    proc = subprocess.Popen(cmd, stdout = subprocess.PIPE, \
                                    stderr = subprocess.STDOUT, shell = True)
    stdout, stderr = proc.communicate()
    if stderr != None:
        print stderr
        return
    return stdout

    


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

def foundMsg(name, cve, src):
    print '###########################################'
    print 'POTENTIALLY VULNERABLE TO'
    print 'Name: ' + name
    print 'CVE: ' + cve
    print 'Source code: ' + src
    print '###########################################'
    
# functions that perform different checks
    
def searchOS():
    """
    Gathers information about the OS
    """
    files = ['/etc/issue',
             '/etc/os-release',
             '/proc/version',
             '/etc/lsb-release', 
             '/etc/redhat-release',
             '/etc/profile',
             '/etc/bashrc',
             '~/.bash_profile', 
             '~/.bashrc',
             '~/.bash_logout',
             '/etc/timezone']
    for f in files: 
        try:
            fmsg = fileMsg(f)
            writeInfo(fmsg)
            out = readFile(f)
            print out
            writeInfo(out)   
        except IOError, e:
            # print e
            writeInfo('FAILED: ' + str(e)+ '\n')
            continue

    
    commands = {'uname': ['uname', '-a'],
                'lpstat': ['lpstat', '-a'],
                'env': ['env'],
                'uptime': ['uptime'],
                'getenforce': ['getenforce']} # check SELinux status
                                                   
    for c in commands:
        try:
            cmsg = cmdMsg(commands[c])
            writeInfo(cmsg)
            stdout = runCmd(commands[c])
            print stdout    
            writeInfo(stdout)
        except (OSError, IOError), e:
            # print e, commands[c]
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
            # print e, str(pipecmds[c])
            writeInfo('FAILED: ' + str(e)+ ' : ' + str(pipecmds[c]) +  '\n')
            continue


def chkSrvc():
    """
    Lists running processes
    """
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
            # print e, commands[c]
            # writeInfo('FAILED: ' + str(e)+ ' : ' + str(commands[c]) +  '\n')
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
            # print e, str(pipecmds[c])
            # writeInfo('FAILED: ' + str(e)+ ' : ' + str(pipecmds[c]) +  '\n')
            continue



def chkApps():
    """
    Looks at installed applications
    """
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
    """
    Reads configuration files for various services
    """
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
    """
    Checks scheduled jobs
    """
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
    """
    Looks at network configuration
    """
    commands = {'ifconfig': ['ifconfig', '-a'],
                'iptables': ['iptables', '-L'],
                'ip6tables': ['ip6tables', '-L'],
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
            '/etc/networks',
            '/etc/hosts',
            '/etc/nsswitch.conf']
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
    """
    Checks current network activity
    """
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
    """
    Looks at user accounts
    """
    commands = {'id': ['id'],
                 'w': ['w'],
                'last': ['last', '-n', TAIL_LINES],
                'ls root': ['ls', '-ahl', '/root/'],
                'ls home': ['ls', '-ahl', '/home/'],
                'ls mail': ['ls', '-alh', '/var/mail/'],
                'sudo': ['sudo', '-l']}
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
    """
    Reads files with potentially sensitive information
    """
    files = ['/etc/passwd',
             '/etc/group',
             '/etc/shadow',
             '/var/apache2/config.inc',
             '/root/anaconda-ks.cfg',
             '~/.ssh/authorized_keys',
             '~/.ssh/identity.pub',
             '~/.ssh/identity',
             '~/.ssh/id_rsa.pub',
             '~/.ssh/id_rsa',
             '~/.ssh/id_dsa.pub',
             '~/.ssh/id_dsa',
             '/etc/ssh/ssh_config',
             '/etc/ssh/sshd_config', # also look for AllowTcpForwarding
             '/etc/ssh/ssh_host_dsa_key.pub',
             '/etc/ssh/ssh_host_dsa_key',
             '/etc/ssh/ssh_host_rsa_key.pub',
             '/etc/ssh/ssh_host_rsa_key',
             '/etc/ssh/ssh_host_key.pub',
             '/etc/ssh/ssh_host_key',
             '/var/lib/dhcp3/dhclient.leases',
             '/etc/mysql/my.cnf',
             '/etc/mysql/debian.cnf']
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

    commands = {'strings': ['strings', '/var/lib/mysql/mysql/user.MYD']}
    for c in commands:
        try:
            cmsg = cmdMsg(commands[c])
            writeInfo(cmsg)
            stdout = runCmd(commands[c])
            print stdout
            writeInfo(stdout)
        except (OSError, IOError), e:
            print e, commands[c]
            writeInfo('FAILED: ' + str(e) + ' : ' + str(commands[c]) + '\n')
            continue
    

def chkLogs():
    """
    Checks logs for various categories
    """
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
    """
    Looks at web configuration
    """
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
    """
    Gathers info about the filesystem
    """
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
    # check if noatime is present, which prevents update of inode access time
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
    """
    Looks for useful tools preinstalled on the system
    """
    commands = {'find perl': ['perl', '-v'],
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
    """
    Finds loose permissions
    """
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


def findExploits():
    """
    The title says it all :)
    """
    kernel = runCmd(['uname', '-r'])
    # kernel = '4.2.0'
    print 'Kernel version is ' + str(kernel)
    startno = 119

    exploits_2_0 = {
        'Segment Limit Privilege Escalation': {'min': '2.0.37', 'max': '2.0.38', 'cve': ' CVE-1999-1166', 'src': 'https://www.exploit-db.com/exploits/19419/'}
    }

    exploits_2_2 = {
        'ptrace kmod Privilege Escalation': {'min': '2.2.0', 'max': '2.2.25', 'cve': 'CVE-2003-0127', 'src': 'https://www.exploit-db.com/exploits/3/'},
        'mremap Privilege Escalation': {'min': '2.2.0', 'max': '2.2.26', 'cve': 'CVE-2004-0077', 'src': 'https://www.exploit-db.com/exploits/160/'},
        'ptrace setuid Privilege Escalation': {'min': '2.2.0', 'max': '2.2.20', 'cve': 'CVE-2001-1384', 'src': 'https://www.exploit-db.com/exploits/21124/'},
        'procfs Stream redirection to Process Memory Privilege Escalation': {'min': '2.2.0', 'max': '2.2.20', 'cve': 'N/A', 'src': 'https://www.exploit-db.com/exploits/20979/'},
        'Privileged Process Hijacking Privilege Escalation': {'min': '2.2.0', 'max': '2.2.25', 'cve': 'CVE-2003-0127', 'src': 'https://www.exploit-db.com/exploits/22362/'},
        'Sendmail Capabilities Privilege Escalation':  {'min': '2.2.0', 'max': '2.2.16', 'cve': 'CVE-2000-0506', 'src': 'https://www.exploit-db.com/exploits/20001/'}
    }

    exploits_2_4 = {
        'ptrace kmod Privilege Escalation': {'min': '2.4.0', 'max': '2.4.21', 'cve': 'CVE-2003-0127', 'src': 'https://www.exploit-db.com/exploits/3/'},
        'do_brk Privilege Escalation': {'min': '2.4.0', 'max': '2.4.23', 'cve': 'CVE-2003-0961', 'src': 'https://www.exploit-db.com/exploits/131/'},
        'do_mremap Privilege Escalation': {'min': '2.4.0', 'max': '2.4.24', 'cve': ' CVE-2003-0985', 'src': 'https://www.exploit-db.com/exploits/145/'},
        'mremap Privilege Escalation': {'min': '2.4.0', 'max': '2.4.25', 'cve': 'CVE-2004-0077', 'src': 'https://www.exploit-db.com/exploits/160/'},
        'uselib Privilege Escalation': {'min': '2.4.0', 'max': '2.4.29-rc2', 'cve': 'CVE-2004-1235', 'src': 'https://www.exploit-db.com/exploits/895/'},
        'bluez Privilege Escalation': {'min': '2.4.6', 'max': '2.4.30-rc2', 'cve': 'CVE-2005-0750', 'src': 'https://www.exploit-db.com/exploits/926/'},
        'System Call Emulation Privilege Escalation': {'min': '2.4.0', 'max': '2.4.37.10', 'cve': 'CVE-2007-4573', 'src': 'https://www.exploit-db.com/exploits/4460/'},
        'ptrace setuid Privilege Escalation': {'min': '2.4.0', 'max': '2.4.10', 'cve': 'CVE-2001-1384', 'src': 'https://www.exploit-db.com/exploits/21124/'},
        'procfs Stream redirection to Process Memory Privilege Escalation': {'min': '2.4.0', 'max': '2.4.4', 'cve': 'N/A', 'src': 'https://www.exploit-db.com/exploits/20979/'},
        'Privileged Process Hijacking Privilege Escalation': {'min': '2.4.0', 'max': '2.4.21', 'cve': 'CVE-2003-0127', 'src': 'https://www.exploit-db.com/exploits/22362/'},
        'sock_sendpage Privilege Escalation': {'min': '2.4.4', 'max': '2.4.37.4', 'cve': ' CVE-2009-2692', 'src': 'https://www.exploit-db.com/exploits/9641/'},
        'pipe.c Privilege Escalation': {'min': '2.4.1', 'max': '2.4.37', 'cve': 'CVE-2009-3547', 'src': 'https://www.exploit-db.com/exploits/9844/'},
        'Ptrace Privilege Escalation': {'min': '2.4.0', 'max': '2.4.35.3', 'cve': 'CVE-2007-4573', 'src': 'https://www.exploit-db.com/exploits/30604/'}

    }

    exploits_2_6 = {
        'mremap Privilege Escalation': {'min': '2.6.0', 'max': '2.6.2', 'cve': 'CVE-2004-0077', 'src': 'https://www.exploit-db.com/exploits/160/'},
        'uselib Privilege Escalation': {'min': '2.6.0', 'max': '2.6.11', 'cve': 'CVE-2004-1235', 'src': 'https://www.exploit-db.com/exploits/895/'},
        'bluez Privilege Escalation': {'min': '2.6.0', 'max': '2.6.11.5', 'cve': 'CVE-2005-0750', 'src': 'https://www.exploit-db.com/exploits/926/'},
        'SYS_EPoll_Wait Privilege Escalation': {'min': '2.6.0', 'max': '2.6.12', 'cve': 'CVE-2005-0736', 'src': 'https://www.exploit-db.com/exploits/1397/'},
        'logrotate prctl Privilege Escalation': {'min': '2.6.13', 'max': '2.6.17.4', 'cve': ' CVE-2006-2451', 'src': 'https://www.exploit-db.com/exploits/2031/'},
        'proc Privilege Escalation': {'min': '2.6.13', 'max': '2.6.17.4', 'cve': ' CVE-2006-2451', 'src': 'https://www.exploit-db.com/exploits/2013/'},
        'System Call Emulation Privilege Escalation': {'min': '2.6.0', 'max': '2.6.22.7', 'cve': 'CVE-2007-4573', 'src': 'https://www.exploit-db.com/exploits/4460/'},
        'BlueTooth Stack Privilege Escalation': {'min': '2.6.0', 'max': '2.6.11.5', 'cve': 'N/A', 'src': 'https://www.exploit-db.com/exploits/4756/'},
        'vmsplice Privilege Escalation': {'min': '2.6.17', 'max': '2.6.24.1', 'cve': 'CVE-2008-0600', 'src': 'https://www.exploit-db.com/exploits/5092/'},
        'ftruncate()/open() Privilege Escalation': {'min': '2.6.0', 'max': '2.6.22', 'cve': 'CVE-2008-4210', 'src': 'https://www.exploit-db.com/exploits/6851/'},
        'exit_notify() Privilege Escalation': {'min': '2.6.0', 'max': '2.6.30-rc1', 'cve': 'CVE-2009-1337', 'src': 'https://www.exploit-db.com/exploits/8369/'},
        'UDEV Privilege Escalation': {'min': '2.6.0', 'max': '2.6.40', 'cve': 'CVE-2009-1185', 'src': 'https://www.exploit-db.com/exploits/8478/'},
        'ptrace_attach() Race Condition': {'min': '2.6.0', 'max': '2.6.30-rc4', 'cve': 'CVE-2009-1527', 'src': 'https://www.exploit-db.com/exploits/8673/'},
        'Samba Share Privilege Escalation': {'min': '2.6.0', 'max': '2.6.39', 'cve': 'CVE-2004-0186', 'src': 'https://www.exploit-db.com/exploits/23674/'},
        'ReiserFS xattr Privilege Escalation': {'min': '2.6.0', 'max': '2.6.35', 'cve': 'CVE-2010-1146', 'src': 'https://www.exploit-db.com/exploits/12130/'},
        'sock_sendpage Privilege Escalation': {'min': '2.6.6', 'max': '2.6.30.5', 'cve': ' CVE-2009-2692', 'src': 'https://www.exploit-db.com/exploits/9641/'},
        'pipe.c Privilege Escalation': {'min': '2.6.0', 'max': '2.6.32-rc6', 'cve': 'CVE-2009-3547', 'src': 'https://www.exploit-db.com/exploits/33322/'},
        'Sys_Tee Privilege Escalation': {'min': '2.6.0', 'max': '2.6.17.6', 'cve': 'N/A', 'src': 'https://www.exploit-db.com/exploits/29714/'},
        'Linux Kernel Privilege Escalation': {'min': '2.6.18', 'max': '2.6.18-20', 'cve': 'N/A', 'src': 'https://www.exploit-db.com/exploits/10613/'},
        'Dirty COW': {'min': '2.6.22', 'max': '4.8.3', 'cve': 'CVE-2016-5195', 'src': 'https://www.exploit-db.com/exploits/40616/'},
        'compat Privilege Escalation': {'min': '2.6.0', 'max': '2.6.36', 'cve': 'CVE-2010-3081', 'src': 'https://www.exploit-db.com/exploits/15024/'},
        'DEC Alpha Linux - Privilege Escalation': {'min': '2.6.28', 'max': '3.0', 'cve': 'N/A', 'src': 'https://www.exploit-db.com/exploits/17391/'},
        'SELinux (RHEL 5) - Privilege Escalation': {'min': '2.6.30', 'max': '2.6.31', 'cve': 'CVE-2009-1897', 'src': 'https://www.exploit-db.com/exploits/9191/'},
        'proc Handling SUID Privilege Escalation': {'min': '2.6.0', 'max': '2.6.38', 'cve': 'CVE-2011-1020', 'src': 'https://www.exploit-db.com/exploits/41770/'},
        'PERF_EVENTS Privilege Escalation': {'min': '2.6.32', 'max': '3.8.9', 'cve': 'CVE-2013-2094', 'src': 'https://www.exploit-db.com/exploits/25444/'},
        'RDS Protocol Privilege Escalation': {'min': '2.6.0', 'max': '2.6.36-rc8', 'cve': 'CVE-2010-3904', 'src': 'https://www.exploit-db.com/exploits/15285/'},
        'Full-Nelson.c Privilege Escalation': {'min': '2.6.0', 'max': '2.6.37', 'cve': 'CVE-2010-4258', 'src': 'https://www.exploit-db.com/exploits/15704/'},
        'Mempodipper Privilege Escalation': {'min': '2.6.39', 'max': '3.2.2', 'cve': 'CVE-2012-0056', 'src': 'https://www.exploit-db.com/exploits/35161/'},
        'Ext4 move extents ioctl Privilege Escalation': {'min': '2.6.0', 'max': '2.6.32-git6', 'cve': 'CVE-2009-4131', 'src': 'https://www.exploit-db.com/exploits/33395/'},
        'Ptrace Privilege Escalation': {'min': '2.6.0', 'max': '2.6.22.7', 'cve': 'CVE-2007-4573', 'src': 'https://www.exploit-db.com/exploits/30604/'},
        'udp_sendmsg Privilege Escalation': {'min': '2.6.0', 'max': '2.6.19', 'cve': 'CVE-2009-2698', 'src': 'https://www.exploit-db.com/exploits/9575/'},
        'fasync_helper() Privilege Escalation': {'min': '2.6.28', 'max': '2.6.33-rc4-git1', 'cve': 'CVE-2009-4141', 'src': 'https://www.exploit-db.com/exploits/33523/'},
        'CAP_SYS_ADMIN Privilege Escalation': {'min': '2.6.34', 'max': '2.6.40', 'cve': 'N/A', 'src': 'https://www.exploit-db.com/exploits/15916/'},
        'CAN BCM Privilege Escalation': {'min': '2.6.0', 'max': '2.6.36-rc1', 'cve': 'CVE-2010-2959', 'src': 'https://www.exploit-db.com/exploits/14814/'},
        'ia32syscall Emulation Privilege Escalation': {'min': '2.6.0', 'max': '2.6.36-rc4-git2', 'cve': 'CVE-2010-3301', 'src': 'https://www.exploit-db.com/exploits/15023/'},
        'Half-Nelson.c Econet Privilege Escalation': {'min': '2.6.0', 'max': '2.6.36.2', 'cve': 'CVE-2010-3848', 'src': 'https://www.exploit-db.com/exploits/17787/'},
        'ACPI custom_method Privilege Escalation': {'min': '2.6.0', 'max': '2.6.37-rc2', 'cve': 'CVE-2010-4347', 'src': 'https://www.exploit-db.com/exploits/15774/'},
        'SGID Privilege Escalation': {'min': '2.6.32.62', 'max': '3.14.8', 'cve': 'CVE-2014-4014', 'src': 'https://www.exploit-db.com/exploits/33824/'},
        'libfutex Privilege Escalation': {'min': '2.6.4', 'max': '3.14.6', 'cve': 'CVE-2014-3153', 'src': 'https://www.exploit-db.com/exploits/35370/'},
        'perf_swevent_init Privilege Escalation': {'min': '2.6.37', 'max': '3.8.9', 'cve': 'CVE-2013-2094', 'src': 'https://www.exploit-db.com/exploits/26131/'},
        'MSR Driver Privilege Escalation': {'min': '2.6', 'max': '3.7.6', 'cve': 'CVE-2013-0268', 'src': 'https://www.exploit-db.com/exploits/27297/'}
    }

    exploits_3 = {
        'overlayfs Privilege Escalation': {'min': '3.0.0', 'max': '3.19.0', 'cve': 'CVE-2015-1328', 'src': 'https://www.exploit-db.com/exploits/37292/'},
        'CLONE_NEWUSER|CLONE_FS Privilege Escalation': {'min': '3.0', 'max': '3.3.6', 'cve': 'N/A', 'src': 'https://www.exploit-db.com/exploits/38390/'},
        'SO_SNDBUFFORCE & SO_RCVBUFFORCE Local Privilege Escalation': {'min': '3.5', 'max': '4.8.14', 'cve': 'CVE-2016-9793', 'src': 'https://www.exploit-db.com/exploits/41995/'},
        'Raw Mode PTY Echo Race Condition Privilege Escalation': {'min': '3.14-rc1', 'max': '3.16', 'cve': 'CVE-2014-0196', 'src': 'https://www.exploit-db.com/exploits/33516/'},
        'sock_diag_handlers() Privilege Escalation': {'min': '3.3.0', 'max': '3.7.10', 'cve': 'CVE-2013-1763', 'src': 'https://www.exploit-db.com/exploits/24555/'},
        'b43 Wireless Driver Privilege Escalation': {'min': '3.0', 'max': '3.9.4', 'cve': 'CVE-2013-2852', 'src': 'https://www.exploit-db.com/exploits/38559/'},
        'CONFIG_X86_X32=y Privilege Escalation': {'min': '3.4', 'max': '3.13.2', 'cve': 'CVE-2014-0038', 'src': 'https://www.exploit-db.com/exploits/31347/'},
        'Double-free usb-midi SMEP Local Privilege Escalation': {'min': '3.0', 'max': '4.5', 'cve': 'CVE-2016-2384', 'src': 'https://www.exploit-db.com/exploits/41999/'},
        'Remount FUSE Privilege Escalation': {'min': '3.2', 'max': '3.16.1', 'cve': 'CVE-2014-5207', 'src': 'https://www.exploit-db.com/exploits/34923/'},
        'ptrace/sysret Privilege Escalation': {'min': '3.0', 'max': '3.15.4', 'cve': 'CVE-2014-4699', 'src': 'https://www.exploit-db.com/exploits/34134/'},
        'open-time Capability file_ns_capable() Privilege Escalation': {'min': '3.0', 'max': '3.8.9', 'cve': 'CVE-2013-1959', 'src': 'https://www.exploit-db.com/exploits/25450/'},
        'REFCOUNT Overflow/Use-After-Free in Keyrings Privilege Escalation': {'min': '3.8.0', 'max': '4.4.1', 'cve': 'CVE-2016-0728', 'src': 'https://www.exploit-db.com/exploits/39277/'}

    }

    exploits_4 = {
        'overlayfs Privilege Escalation': {'min': '4.0', 'max': '4.3.3', 'cve': 'CVE-2015-8660', 'src': 'https://www.exploit-db.com/exploits/39166/'},
        'BPF Privilege Escalation': {'min': '4.4.0', 'max': '4.5.5', 'cve': 'CVE-2016-4557', 'src': 'https://www.exploit-db.com/exploits/39772/'},
        'AF_PACKET Race Condition Privilege Escalation': {'min': '4.2.0', 'max': '4.9.0-2', 'cve': 'CVE-2016-8655', 'src': 'https://www.exploit-db.com/exploits/40871/'},
        'DCCP Double-Free Privilege Escalation': {'min': '4.4.0', 'max': '4.9.11', 'cve': 'CVE-2017-6074', 'src': 'https://www.exploit-db.com/exploits/41458/'},
        'Netfilter target_offset Out-of-Bounds Privilege Escalation': {'min': '4.4.0-21-generic', 'max': '4.4.0-31-generic', 'cve': 'N/A', 'src': 'https://www.exploit-db.com/exploits/40049/'},
        'IP6T_SO_SET_REPLACE Privilege Escalation': {'min': '4.6.2', 'max': '4.6.3', 'cve': 'CVE-2016-4997', 'src': 'https://www.exploit-db.com/exploits/40489/'},
        'Packet Socket Local Privilege Escalation': {'min': '4.8.0', 'max': '4.10.6', 'cve': 'CVE-2017-7308', 'src': 'https://www.exploit-db.com/exploits/41994/'},
        'UDEV < 232 - Privilege Escalation': {'min': '4.8.0', 'max': '4.9.0', 'cve': 'N/A', 'src': 'https://www.exploit-db.com/exploits/41886/'}
    }

    if kernel.startswith('2.2'):
        for name, exploit in exploits_2_2.iteritems(): # iterate over exploits dict
            if kernel >= exploit['min'] and kernel < exploit['max']:
                foundMsg(name, exploit['cve'], exploit['src'])
            else:
                continue
    elif kernel.startswith('2.4'):
        for name, exploit in exploits_2_4.iteritems():
            if kernel >= exploit['min'] and kernel < exploit['max']:
                foundMsg(name, exploit['cve'], exploit['src'])
            else:
                continue
    elif kernel.startswith('2.6'):
        for name, exploit in exploits_2_6.iteritems():
            if kernel >= exploit['min'] and kernel < exploit['max']:
                foundMsg(name, exploit['cve'], exploit['src'])
            else:
                continue

    elif kernel.startswith('2.0'):
        for name, exploit in exploits_2_0.iteritems():
            if kernel >= exploit['min'] and kernel < exploit['max']:
                foundMsg(name, exploit['cve'], exploit['src'])
            else:
                continue

    elif kernel.startswith('3'):
            for name, exploit in exploits_3.iteritems():
                if kernel >= exploit['min'] and kernel < exploit['max']:
                    foundMsg(name, exploit['cve'], exploit['src'])
                else:
                    continue

    elif kernel.startswith('4'):
            for name, exploit in exploits_4.iteritems():
                if kernel >= exploit['min'] and kernel < exploit['max']:
                    foundMsg(name, exploit['cve'], exploit['src'])
                else:
                    continue
    else:
        print 'No exploits found for this kernel version'

########### comment / uncomment below for desired output

        
# searchOS()
# chkSrvc()
# chkApps()
# chkSrvcSettings()
# lsJobs()
# netInfo()
# currNetStats()
# chkUsers()
# chkIntrstFiles()
# chkLogs()
# chkWebSettings()
# chkFS()
# findTools()
# findPerm()
findExploits()
