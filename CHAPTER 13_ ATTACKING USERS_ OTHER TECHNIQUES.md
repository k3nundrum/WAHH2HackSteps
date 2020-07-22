CHAPTER 13: ATTACKING USERS: OTHER TECHNIQUES

# Inducing User Actions
## **OSRF REQUEST FORGERY**
1. In every location where data submitted by one user is displayed to other users but you cannot perform a stored XSS attack, review whether the app's behavior leaves it vulnerable to On-Site Request Forgery(OSRF)
2. The vulnerability typically arises where user-supplied data is inserted into the target of a hyperlink or other URL within the returned page. Unless the application specifically blocks any characters you require (typically dots, slashes, and the delimiters used in the query string), it is almost certainly vulnerable.
3. If you discover and OSRF vulnerability, look for a suitable request to target in your exploit, as discrived in the next section for CSRF
## **CSRF**
1. Review the key functionality within the app, as identified in your application mapping exercises (see Chapter 4).
2. Find an application function that can be used to perform some sensitive action on behalf of an unwitting user, that relies solely on cookies for tracking user session, and that employs request parameters that an attacker can fully determine in advance -- that is, that do not contain any other tokens or unpredictable items.
3. Create an HTML page that issues the desired request without any user interaction. For `GET` requests, you can place an `<img>` tag with the `src` attribute set to the vulnerable URL. For `POST` requests, you can create a form that contains hidden fields for all the relevant parameters required for the attack and that has its target set to the vulnerable URL. You can use JavaScript to autosubmit the form as soon as the page loads.
4. While logged in to the application, use the same browser to load your crafted HTML page. Verify that the desired action is carried out within the app.
# The Same-Origin Policy Revisted
You should always check for the `/crossdomain.xml` file on any web app you are testing. Even if the application itself does not use Flash, if permission is granted to another domain, Flash objects issued by that domain are permitted to interact with the domain that publishes the policy.
	- If the application allows unrestricted access (by specifying `<allow-access-from domain="*" />`), any other site can perform two-way interaction, riding on the sessions of application users. This would allow all data to be retrieved, and any user actions to be performed, by any other domain.
	- If the application allows access to subdomains or other domains used by the same organization, two-way interaction, is of course, possible from those domains. This means that vulnerabilites such as XSS on those domains may be exploitable to compromise the domain that grants permission. Furthermore, if an attacker can purchase Flash-based advertising on any allowed domain, the Flash objects he deploys can be used to compromise the domain that grants permission.
	- Some policy files disclose intranet hostnames or other sensitive information that may be of use to an attacker.
## **Same-Origin Policy and HTML5**
1. To test an app's handling of cross-domain request using `XMLHttpRequest`, you should try adding an `Origin` header specifying a different domain, and examin any `Access-Control` headers that are returned. The security implications of allowing two-way access from any domain, or from specified other domains, are the same as those described in the Flash cross-domain policy.
2. If any cross-domain access is supported, you should also use `OPTIONS` requests to understand exactly what headers and other request details are permitted.
# Other Client-Side Injection Attacks
## **HTTP HEADER INJECTION**
1. For each potentially vulnerable instance in which user-controllable input is copied into an HTTP header, verify whether the app accepts data containing URL-encoded carriage-return (`%0d`) and line-feed (`%0a`) characters, and whether these are returned unsanitized in its response.
2. Note that you are looking ofr the actual newline characters themselves to appear in the server's response, not their URL-encoded equivalents. If you view the response in an intercepting proxy, you should see and additional line in the HTTP headers if the attack was successful.
3. If only one of the two newline characters is returned in the server's responses, it may still be possible to craft a working exploit, depending on the context.
4. If you find that the application is blocking or sanitizing newline characters, attempt the following bypasses:
```
foo%00%0d%0abar
foo%250d%250abar
foo%%0d0d%%0a0abar
```
## **COOKIE INJECTION**
1. Obtain a valid token by whatever means the application enables you to obtain one.
2. Access the login form, and perform a login using this token
3. If the login is successful and the application does not issue a new token, it is vulnerable to session fixation.
*HACK STEPS without Auths*
1. Obtain a session token as a completely anonymous user, and then walk through the process of submitting sensitive data, up until any page at which the sensitive data is displayed back.
2. If the same token originally obtained can now be used to retrieve the sensitive data, the app is vulnerable to session fixation.
3. If any type of session fixation is identified, verify whether the server accepts arbitrary tokens it has not previously issued. If it does, the vulnerability is considerably easier to exploit over an extended period.
## **OPEN REDIRECTION**
1. Identify every instance within the app where a redirect occurs.
2. An effective way to do this is to walk through the application using an intercepting proxy and monitor the requests made for actual pages (as opposed to other resources, such as images, stylesheets, and script files).
3. If a single navigation action results in more than one request in succession, investigate what means of performing the redirect is being used.

If data is supplied by user in some way to set the target of the redirect, (for example, when an app forces users whose sessions have expired back to a login page), follow these steps:
1. If the user data being processed in a redirect conatins an absolute URL, modify the domain name within the URL, and test whether the application redirects you to the different domain.
2. If the user data being processed contains a relative URL, modify this into an absolute URL for a different domain, and test whether the app redirects you to this domain.
3. In both cases, if you see behavior like the following, the application is certainly vulnerable to an arbitrary redirection attack:
```
GET /updates/8/?redir=http://mdattacker.net HTTP/1.1
HOST: mdsec.net

HTTP/1.1 302 Object moved
Location: http://mdattacker.net/
```
# LOCAL PRIVACY ATTACKS
## **PERSISTENT COOKIES**
1. Review all the cookies identified during your application mapping exercises (see Chapter 4). If any `Set-cookie` instruction contains an `expires` attribute with a date that is in the future, this will cause the browser to persist that cookie until that date. For example:
```
UID=d475dfc6eccca72d0e expires=Fri, 10-Aug018 16:08:29 GMT;
```
2. If a persistent cookie is set that contains any sensitive data, a local attacker may be able to capture this data. Even if a persistent cookie contains an encrypted value, if this plays a critical role such as reauthenticating the user without entering credentials, an attack who captures it can resubmit it to the application without actually deciphering its contents, (see Chapter 6).
## **CACHED WEB CONTENT**
1. For any application pages that are accessed over HTTP and that contain sensitive data, review the details of the server's response to identify any cache directives.
2. The following directives prevent browsers from caching a page. Note that these may be specified within the HTTP response headers or within HTML metatags:
```
Expires: 0
Cache-control: no-cache
Pragma: no-cache
```
3. If these directives are not found, the page concerned may be vulnerable to caching by one or more browsers. Note that cache directives are processed on a per-page basis, so every sensitive HTTP-based page needs to be checked.
4. To verify that sensitive information is being cached, use a default instalation of a standard browser, such as IE or Firefox. In the browser's config, completely clean its cache and all cookies, and then access the application pages that contain sensitive data. Review the files that appear in the cache to see if any contain sensitive dat. If a large number of files are being generated, you can take a specific string from a page's source and search for the cache for that string. Here are the default cache locations for common browsers:

	- Internet Explorer--Subdirectories of C:\Documents and Settings\username\Local Settings\Temporary Internet Files\Content.IE5

	- Firefox (on Windows)--C:\Documents and Settings\username\Local Settings\Application Data\Mozilla\Firefox\Profiles\profile name\Cache
	- Firefox (on Linux)--/.mozilla/firefox/profile name/Cache
## **Browsing History**
1. Identify any instances within the application in which sensitive data is being transmitted via a URL parameter.
2. If any cases exist, examine the browser history to verify that this data has been stored there.
## **Autocomplete**
1. Review the HTML source code for any forms that contain text fields in which sensitive data is captured.
2. If the attribute `autocomplete=off` is not set, within either the form tag or the tag for the individual input field, data entered is stored within browsers where autocomplete is enabled.
## **Flash Local Shared Objects**
1. Several plug-ins are available for Firefox, such as BetterPrivacy, which can be used to brows the LSO data created by individual applications.
2. You can review the contest of the raw LSO data directly on disk. The location of this data depends on the browser and OS. For example on Internet Explorer, the LSO data resides within the following folder structure:
```
C:\Users\{username}\AppData\Roaming\Macromedia\Flash Player\#SharedObjects\{random}\{domain name}\{store name}\{name of SWF file}
```
## **Silverlight Isolated Storage**
You can review the contents of the raw Silverlight Isolated Storage data directly on disk. For IE this data resides in a series of deeply nested randomly named folders at the following location:
```
C:\Users\{username}\AppData\LocationLow\Microsoft\Silverlight\
```
## **Internet Explorer userData**
You can review the contents of the raw data stored in IE's userData directly on disk.
```
C:\Users\user\AppData\Roaming\Microsoft\Internet Explorer\UserData\Low\{random}
```
# Attacking ActiveX Controls
## **Finding ActiveX Vulnerabilites**
A simple way to prove for ActiveX vulnerabilities is to modify the HTML that invokes the control, pass your own parameters to it, and monitor the results:
1. VUlnerabilities such as buffer overflows can be probed for using the same kind of attack payloads described in Chapter 16. Triggering bugs of this kind in an uncontrolled manner is likely to result in a crash of the browser process that is hosting the control.
2. Inherently dangerous methods such as `LaunchEXE` can often be identified simply by their name. In other cases, the name may be innocuous or obfuscated, but it may be clear that interesting items such as filenames, URLs, or system commands are being passed as parameters. You should try modifying these parameters to arbitrary values and determine whether the control processes your input as expected.





















































