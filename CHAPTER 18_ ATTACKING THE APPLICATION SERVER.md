CHAPTER 18: ATTACKING THE APPLICATION SERVER

# Vulnerable Server Configuration

## **DEFAULT CREDENTIALS**
1. Review the results of your application mapping exercises to identify the web server and other technologies in use that may contain accessible administrative interfaces.
2. Perform a port scan of the web server to identify any administrative interfaces running on a different port to the main taget application.
3. FOr any identified interfaces, consult the manufacturer's documentation and the listings of common passwords to obtain default credentials. Use Metasploit's built-in database to scan the server.
4. If the default credentials do not work, use the techniques descrived in Chapter 6 to attempt to guess valid credentials.
5. If you gain access to an administrative interface, review the available functionality, and determine whether this can be used to further compromise the host and attack the main application.
## **DIRECTORY LISTINGS**
1. For each directory discovered on the web server during application mapping, make a request for just this directory, and identify any cases where a directory listing is returned.
## **WebDAV METHODS**
To test the server's handling of different HTTP methods, you will need to use a tool such as Burp Repeater, which allows you to send an arbitrary request with full control over the message headers and body.
1. Use the `OPTIONS` method to list the HTTP methods that the server states are available. Note that different methods may be enabled in different directories.
2. In many cases, methods may be advertised as available that you cannot in fact use. Sometimes, a method may be usable even though it is not listed in the response to the `OPTIONS` request. Try each method manually to confirm whether it can in fact be used.
3. If you find that some WebDAV methods are enabled, it is often easiest to use a WebDAV-enabled client for further investigation, such as Microsoft FrontPage or the Open as Web Folder option within IE.
	- Attempt to use the `PUT` method to upload a benign file, such as a text file.
	- If this is successful, try uploading a backdoor script using `PUT`
	- If the necessary extension for the backdoor to operate is being blocked, try uploading the file with a `.txt` extension and using the `MOVE` method to move it to a file with a new extension.
	- If any of the preceding methods fails, try uploading a JAR file, or a file with contents that a browser will render as HTML.
	- Recursively step through all directories using a tool such as davtest.pl
## **THE APPLICATION SERVER AS A PROXY**
1. Using bothe `GET` and `CONNECT` requests, try to use the web server as a proxy to connect to other servers on the internet and retrieve content from them.
2. Using both techniques, attempt to connect to different IP addresses and ports within the hosting infrastructure.
3. Using both techniques, attempt to connect to common port numbers on the web server itself by specifying 127.0.0.1 as the target host in the request.
## **MISCONFIGURED VIRTUAL HOSTING**
1. Submit `GET` requests to the root directory using the following:
	- The correct `Host` header
	- An arbitary `Host` header
	- The servers IP address in the `Host` header
	- No `Host` header.
2. Compare the responses to these requests. For example, when an IP address is used in the `Host` header, the server may simply respons with a directory listing. You may also find that different default content is accessible.
3. If you observe different behavior, repeat your application mapping exercises using the `Host` header that generated different results. Be sure to perform a Nikto scan using the `-vhost` option to identify any default content that may have been overlooked during intial application mapping.
## **WEB APPLICATION FIREWALLS**
The presence of a web application firewall can be deduced using the following steps:
1. Submit an arbitrary parameter name to the application with a clear attack payload in the value, ideally somewhere the application includes the name and/or value in the response. If the application blocks the attack, this is probably due to an external defense.
2. If a variable can be submitted that is returned in a server response, submit a range of fuzz strings and encoded variants to identify the behavior of the application defense to user input.
3. Confirm this behavior by performing the same attacks on variables within the application.

## **BYPASS WAF**
You can try the following strings to attempt to bypass a web app firewall:
1. For all fuzzing strings and request, use benign strings for payloads that are unlikely to exist in a standard signature database. Giving examples of these is, by definition, not possible. But you should avoid using `/etc/passwd` or `/windows/system32/config/sam` as payloads for file retrieval. Also avoid using terms such as `<script>` in an XSS attak and using `alert()` or `xss` as XSS payloads.
2. If a particular request is blocked, try submitting the same parameter in a different location or context. For instance, submit the same parameter in the URL in a `GET` request, within the body of a `POST` request, and within the URL in a `POST` request.
3. On ASP.NET also try submitting the parameter as a cookie. The API `Request.Params["foo"]` retrieves the valuse of a cookie named `foo` if the parameter `foo` is not found in the query string or message body.
4. Review all the other methods of introducing user input provided in Chapter 4, choosing any that are unprotected.
5. Determine locations where user inpout is (or can be) submitted in a nonstandard format such as serialization or encoding. If none are available, build the attack string by concatenation and/or by spanning it across multiple variables. (Note that if the target is ASP.NET, you may be able to use HPP to concatenate the attack using multiple specifications of the same variable)






































