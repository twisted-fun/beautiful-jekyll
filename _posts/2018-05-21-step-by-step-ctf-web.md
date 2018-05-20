---
layout: post
title: Step-By-Step CTF-Web  
tags: [ctf, web, tut]
---


<p>The following are the steps to follow, when encountered by a web application in a Capture The Flag event. These steps are compiled from my experience in CTF and will be an ongoing project.</p>
<br/>
<h4><b>Spider:</b></h4>
<p>One can use BurpSuite or Owasp-Zap for spidering web application. In burp, intercepted packet can be passed to the spider for automated spidering. For web applications integrated with login facility though, manual spidering through burp is adviced to avoid spider from stepping on logout link.</p>
<br/>
<h4><b>Files Of Interest:</b></h4>
<p>The following files are often seen in CTF, to be very useful to look into.</p>
<ul>
<li>robot.txt</li>
<li>.htaccess</li>
<li>sitemap.xml</li>
<li>config.php</li>
<li>readme</li>
<li>Backup files</li>
</ul>
<br/>
<h4><b>Page Source:</b></h4>
<p>Analyze the source of whole web application (at least what you find relevent for the challenge). Look for comments, hidden tag or disabled tag, javascript obfuscations etc.</p>
<br/>
<h4><b>Stegnography:</b></h4>
<p>If any images, videos or files are found on web app. Download them and check for interesting stegnos. We can use the following tools to help us find hidden content in files.</p>
<p>Images (binwalk, exiftool, stegsolve)</p>
<p>videos (TrueCrypt)</p>
<br/>
<h4><b>Directory Busting:</b></h4>
<p>CTF challenges do not endorse brute-forcing the server but sometimes you may need to do some common directory lookups. For this you can use <b>dirb</b>, <b>wfuzz</b> or just <b>burpsuite</b>. In some challenges, you will have to make your own dictionary from challenge website content to bruteforce its directories, in this case <b>cewl</b> is your best friend.</p>
<br/>
<h4><b>Vulnerability Scanning:</b></h4>
<p>Run a scan using nikto or nessus, you never know when you find something interesting.</p>
<br/>
<h4><b>WebDAV Methods:</b></h4>
<p>WebDAV gives us numerous facilities that can be used to manipulate files on the web server. Given the nature of the functionality, if these are accessible by low-privileged users, they may provide an effective avenue for attacking an
application. Here are some methods to look for:
<br/>
- <b>PUT</b> uploads the attached file to the specified location.
<br/>
- <b>DELETE</b> deletes the specified resource.
<br/>
- <b>COPY</b> copies the specified resource to the location given in the Destination header.
<br/>
- <b>MOVE</b> moves the specified resource to the location given in the Destination header.
<br/>
- <b>SEARCH</b> searches a directory path for resources.
<br/>
- <b>PROPFIND</b> retrieves information about the specifi ed resource, such as author, size, and content type.
<br/>
You can use the OPTIONS method to list the HTTP methods that are permitted in a particular directory or just use <b>devtest</b> tool to make things easier.</p>
<br/>
<h4><b>Request & Response:</b></h4>
<p>Intercept all requests to the server. Try to change the relevent http header tags or request params and see how web app responds.</p>
<br/>
<h4><b>LFI/RFI:</b></h4>
<p>Look for query string or post params (ie page=,url=,lang= etc), which might be including other files into the webpage.
If LFI exists and PHP version >= 5.0.0 then try to use php resource to disclose the server side code.</p>
<pre><code>php://filter/convert.base64-encode/resource="argument"
</code></pre>
If LFI/RFI exists and PHP version >= 5.2.0 with allow_url_include ON. Try data stream method to execute shell on the server
<br/>
- create php shell payload
<br/>
- base64 encode 
<br/>
- url encode
<br/>

<pre><code>index.php?file=data://text/plain;base64,"encoded shell"
</code></pre>

Bypassing added suffix <b>.php</b> for RFI
- <b>To be added</b>
<br/>

Bypassing added suffix <b>.php</b> for RFI
- make web server on your machine
<br/>
- create two php script first to download webshell when executed and second the webshell itself
<br/>
- To make apache treat php code as plain text (so when doing RFI from target, code doesn't get executed on your host) do as described below
<br/>
- goto "/etc/apache2/mods-enabled/php5.conf"
<br/>
- comment the following lines
<br/>

<pre><code>#<FilesMatch ".+\.ph(p[345]?|t|tml)$">
#    setHandler application/x-httpd-php
#</FilesMatch>
</code></pre>

<br/>
<h4><b>File Upload:</b></h4>
<p>When file uploads are given always check the following</p>
<p>Find if server is using a black-list or white-list. On both protection try</p>
- "file.php<space>" or "file.php."
<br/>
- "file.php.jpg"
<br/>
- "file.php%00.jpg"
<br/>
<p>In case of content-type filter use intercepting proxy.</p>
<p>In case of file-type recogniser try to use</p>
- Magic Number of accepted files
<br/>
- Insert your code in comment section of the metadata
<br/>
- use file modifier (ie image resizer) to produce malicious code itself when receiving special input
<br/>
<br/>
<h4><b>Vulnerable Framework:</b></h4>
<p>Check if web application is using a framework then if it has any existing vulnerabilities.</p>
- use searchsploit or exploit-db
<br/>
<br/>
<h4><b>SQL Injection:</b></h4>
<p>When it seems like a sql injection, one can use <b>sqlmap</b> to make things easier but without proper use it may not detect even an existing sql injection.</p>

<pre><code>sqlmap --url=http://192.168.0.100:1337/index.php --method POST --data 'username=test&password=test&Submit=Login' --not-string='Username or Password is invalid' --dbms=MySQL --batch --dbs
</code></pre>

<p>Never forget to do user enumeration, may find interesting things.</p>
<br/>

