CHAPTER 8: ATTACKING ACCESS CONTROLS

# Attacking Access Controls:
Here are some questions to consider when examining an application's access controls:
1. Do application functions give individual users access to a particular subset of data that belongs to them?
2. Are there different levels of user, such as managers, supervisors, guests etc..., who are granted access to different functions?
3. Do administrators use functionality that is built into the same application to configure and monitor it?
4. What functions or data resources within the application have you identified that would most likely enable you to escalate your current privileges?
5. Are there any identifiers (by way of URL parameters of `POST` body message) that signal a paremeter is being used to track access levels?
## Testing with Different User Accounts:
1. If the application segregates user access to different levels of functionality, first use a powerful account to locate all the available functionality. Then atempt to access this using a lower-privileged account to test for vertical privilege escalation.
2. If the application segregates user access to different resources(such as documents), use two different user-level accounts to test whether access controls are effective or whether horizontal privilege escalation is possible. For example, find a document that can be legitmately accessed by one user but not by another, and attempt to access it using the second user's account -- either by requesting the relevant URL or by submitting the same `POST` parameters from within the second user's session.
3. Use BURP:
	- With Burp configured as your proxy and interception disabled, browse all the application's content within one user context. If you are testing vertical access controls, use the higher privileged account for this.
	- Review all contents of Burp's site map to ensure that you have identified all the functionality you want to test. Then use the context menu to select the "compare site maps" feature.
	- To select the second site map to be compared, you can either load this from a Burp state file or have Burp dynamically rerequest the first stie map in a new session context. To test horizontal access controls between users of the same type, you can simply load a state file you saved earlier, having mapped the application as a different user. For testing vertical access controls, it is preferable to re-request the high-privilege site map as a low-privilege user, because this ensures complete coverage of the relevant functionality.
	- To re-request the first site map in a different session, you need to configure Burp's session-handling functionality with the details of the low-privilege user session (for example, by recording a login macro or providing a specific cookie to be used in requests). This feature is described in detail in Chapter 14. You may also need to define suitable scope rules to prevent Burp from requesting any logout function.
## Testing Multistage Processes:
1. When an action is carried out in a multistep way, involving several different requests from client to server, test each request individually to determine whether access controls have been applied to it. Be sure to include every request, including form submission, the following of redirections, and any unparameterized requests.
2. Try to find any locations where the application effectively assumes that if you have reached a particular point, you must have arrived via legitmate means. Try to reach that point in other ways using a lower-privileged account to detect if any privilege escalation attacks are possible.
3. One way to perform this testing manually is to walk through a protected multistage process several times in your browser and use your proxy to switch the session token supplied in different requests to that of a less-privileged user.
4. You can often dramatically speed up this process by using the "request in browser" feature of Burp:
	- Use the higher-privileged account to walk through the entire multistage process.
	- Log in to the application using the lower-privileged account (or none at all).
	- In the Burp Proxy History, find the sequence of requests that were made when the multistage process was performed as a more privileged user. For each request in the sequence, select the context menu item "request in browser in current browser session," Paste the provided URL into your browser that is logged in as the lower-privileged user.
	- If the application lets you, follow through the remained of the multi-stage process in the normal way, using your browser.
	- View the result within both the browser and the proxy history to determine whether it successfully performed the privileged action.
## Testing With Limited Access:
1. Use the content discovery techniques from Chapter 4 to identify as much of the application's functionality as possible. Performing this exercise as a low-privileged user is often sufficient to both enumerate and gain direct access to sensitive functionality.
2. Where application pages are identified that are likely to present different functionality or links to ordinary and administrative users (for example, Control Panel or My Home Page), try adding parameters such as `admin=true` to the URL query string and the body of `POST` requests. This will help you determine whether this uncovers or gives access to any additional functionality that your user context has normal access to.
3. Test whether the application uses the `Referer` header as the basid for making access control decision. For key application functions that you are authorized to access, try removing or modifying the `Referer` header, and determine whether your request is still successful. If not, the application may be trusting the `Referer` header in an unsafe way. If you scan requests using Burp Active Scanner, Burp tries to remove the `Referer` header from each request and informs you if this appears to make a sytematic and relevant difference to the application's respons.
4. Review all client-side HTML and scripts to find references to hidden functionality or functionality that can be manipulated on the client side, such as script-based user interfaces. Also, decompile all browser extension components as described in Chapter 5 to discover any references to server-side functionality.
- Hack Steps:
	1. Where the application uses identifiers of any kind (document IDs,, account numbers,order references) to specify which resource a user is requesting, attempt to discover the identifiers for resources to which you do not have authorized access.
	2. If it is possible to generate a series of such identifiers in quick succession (for example, by creating multiple new documents or orders), use the techniques described in Chapter 7 for session tokens to try to discover any predictable sequences in the identifiers the application produces.
	3. If it is not possible to generate any new identifiers, you are restricted to analyzing the identifiers you have already discovered, or even using plain gueeswork. If the identifier has the form of a GUID, it is unlikely that any attempts based on guessing will be successful. However, if it is a relatively small number, try other numbers in close range, or random numbers with the same number of digits.
	4. If access controls are found to be broken, and resource identifiers are found to be predictable, you can mount an automated attack to harvest sensitive resources and information from the application. Use the techniques from Chapter 14 to design a bespoke automated attack to retrieve the data you require.
	- A catastrophic vulnerability of this kind occurs where an Account Information page displays a users's personal details together with his username and password. Although the password typically is masked on-screen, it is nevertheless transmitted in full to the browser. Here, you can often quickly iterate through the full range of account identifiers to harvest the login credentials of all users, including administrators.
## Testing Direct Access to Methods:
1. Identify any parameters that follow Java naming conventions (for example, `get,set,add,update,is,has` followed by a capitalized word), or explicitly specify a package structure (for example, `com.companyname.xxx.yyy.ClassName). Make a note of all referenced methods you can find.
2. Look out for a method that lists the available interfaces or methods. Check through your proxy history to see if it has been called as part of the application's normal communication. If not, try to guess it using the observed naming conventions.
3. Consult public resources such as search engines and forum sites to determine any other methods that might be accessible.
4. Use the techniques described in Chapter 4 to guess other method names.
5. Attept to access all methods gathered using a variety of user account types, including unauthenticated users.
6. If you do not know the number or types of arguments expected by some methods, look for methods that are less likely to take arguments, such as `listInterfaces` and `getAllUsersInRoles`.
## Testing Over Static Resources:
1. Step through the normal process for gaining access to a protected static resource to obtain an example of the URL by which it is ultimately retrieved.
2. Using a different user context (for example, a less-privileged user or an account that has not made a required purchase), attempt to access the resource directly using the URL you have identified.
3. If this attack succeeds, try to understand the naming scheme being used for protected static files. If possible, construct an automated attack to crawl for content that may be useful or that may contain sensitive data (see Chapter 14).
## Testing Restrictions on HTTP Methods:
1. Using a high-privileged account, identify some privileged requests that perform sensitive actions, such as adding a new user or changing a user's security role.
2. If these requests are not protected by any anti-CSRF tokens or similar features (see Chapter 13), use the high-privileged account to determine whether the application still carries out the requested action if the HTTP method is modified. Test the following HTTP methods:
	- POST
	- GET
	- HEAD
	- An arbitrary invalid HTTP method
3. If the application honors any requests using different HTTP methods than the original method, test the access controls over those requests using the standard methodology already described, using accounts with lower privileges.











































