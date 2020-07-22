CHAPTER 12: ATTACKING USERS: XSS

# FINDING and EXPLOITING XSS VULNERABILITES
## **Reflected XSS**
1. Choose a unique arbitrary string that does not appear anywhere within the application and that contains only alphabetical characters and therefore is unlikely to be affected by any XSS-specific filters. For example:
```
myxsstestdmq1wp
```
2. Monitor the app's resonses for any appearance of this same string. Make a note of every parameter whose value is being copied into the app's response. These are not necessarily vulnerable, but each instance identified is a candidate for further investigation, as described in the next section.
3. Not that both `GET` and `POST` requests need to be tested. You should include every parameter within both the URL query string and the message body. Although a smaller range of delivery mechanisms exists for XSS vulnerabilities that can be triggered only by a `POST` request, exploitation is is still possible, as previously described.
4. In any cases where XSS was found in a `POST` reques, use the "change request method" option in Burp toi determine whether the same attack could be performed as a `GET` request.
5. In addition to the standard request parameters, you should test every instance in which the application processes the contents of an HTTP request header. A common XSS vulnerability arises in error messages, where items such as the `Refefer` and `User-Agent` headers are copied into the message's contents. These headers are valid vehicles for delivering a reflected XSS attack, because an attacker can use a Flash object to induce a victim to issue a request containing arbitrary HTTP headers.
## **Testing Reflections to Introduce Script**
Do the following for each reflected input identified in the previous steps:
1. Review the HTML source to identify the location(s) where your unique string is being reflected.
2. If the string appears more that once, each occurrence needs to be treated as a separate potential vulnerability and investigated individually.
3. Determine, from the location within the HTML of the user-controllable string, how you need to modify it to cause execution of arbitrary script. Typically, numerous different methods will be potential vehicles for an attack, as described later in this chapter.
4. Test your exploit by submitting it to the application. If your crafted string is still returned unmodified, the application is vulnerable. Double-check that your syntax is correct by using a proof-of-concept script to display an alert dialog, and confirm that this actually appears in your browser when the response is rendered.
## **STORED XSS**
1. Having submitted a unique string to every possible location within the application, you must review all of the app's content and functionality once more to identify any instances where this string is displayed back to the browser. User-controllable data entered in one location (for example, a name field on a personal information page) may be displayed in numerous places throughout the app. (for example, it could be on the user's home page, in a listing of registered users, in work flow items such as tasks, on other users' contact lists, in messages or questions posted by the user, or in application logs). Each appearance of the string may be subject to different protective filters and therefore needs to be investigated separately.
2. If possible, all areas of the app accessible by administrators should be reviewed to identify the appearance of any data controllable by non-admin users. For example, the app may allow admins to review log files in-browser. It is extremely common for this type of functionality to contain XSS vulnerabilities that an attacker can exploit by generating log entries containing malicious HTML.
3. When submitting a test string to each location within the app, it is sometimes insufficient simply to post it as each parameter to each page. Many application functions need to be followed through several stages before the submitted data is actually stored. For example, actions such as registering a new user, placing a shopping order, and making a funds transfer often involve submitting several different requests in a defined sequence. To avoid missing any vulnerabilities, it is necessary to see each test case through completion.
4. When probing for reflected XSS, you are interested in every aspect of a victim's request that you can control. This includes all parameters to the request, every HTTP header etc... For stored XSS, you should also investigate any out-of-band channels through which the app receives and processes input you can control. Any such channels are suitable attack vectors for introducing stored XSS attacks. Review the results of your application mapping exercises (see Chapter 4) to identify every possible area of attack surface.
5. If the app allows files to be uploaded and downloaded, always probe this functionality for stored XSS attacks. Detailed techniques for testing this type of functionality are discussed later in this chapter.
6. Think imaginatively about any other possible means by which data you control may be stored by the application and displayed to other users. For example, if the app search function shows a list of popular search items, you may be able to introduce a stored XSS payload by searching for it numerous times, even though the primary search functionality itself handles your input safely.
## **DOM-Based XSS**
Using the results of your application mapping exercises from Chapter 4, review every piece of client-side JavaScript for the following APIs, which may be used to access DOM data that can be controlled via a crafted URL:
```
document.location
document.URL
document.URLUnencoded
document.referrer
window.location
```
Be sure to include scripts that appear in static HTML pages as well as dynamically generated pages. DOM-based XSS bugs may exist in any location where client-side scripts are used, regardless of the type of page or whether you see parameters being submitted to the page.
In every instance where one of the preceding APIs is being used, closely review the code to identify what is being done with the user-controllable data, and whether crafted input could be used to cause execution of arbitrary JavaScript. In particular, review and test any instance where your data is being passed to any of the following APIs:
```
document.write()
document.writeIn()
document.body.innerHtml
eval()
window.execScript()
window.setInterval()
window.setTimeout()
```













































