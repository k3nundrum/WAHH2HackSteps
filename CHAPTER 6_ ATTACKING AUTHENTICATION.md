CHAPTER 6: ATTACKING AUTHENTICATION

CHAPTER 6: ATTACKING AUTHENTICATION
## Brute Forceable Logins:
1. Manually submit several bad login attempts for an account you control, monitoring the error messages you recieve.
2. After about 10 failed logins, if the application has not returneda message about account lockout, attempt to log in correctly. If this succeeds, there is probably no account lockout policy.
3. If the account is locked out, try repeating the exercise using a different account. This time, if the application issues any cookies, use each cookie for only a single login attempt, and obtain a new cookie for each subsequent login attempt.
4. Also, if the account is locked out, see whether submitting the valid password causes any difference in the application's behavior compared to an invalid password. If so, you can continue a password-guessing attack even if the account is locked out.
5. If you do not control any accounts, attempt to enumerate a valid username (see next section) and make several bad logins using this. Monitor for any error messages about an account lockout.
6. To mount a brute-force attack, first identify a difference in the application's behavior in response to successful and failed logins. You can use this fact to discriminate between a success and failure during the course of the automated attack.
7. Obtain a list of enumerated or common usernames and a list of common passwords. Use any information obtained about password quality rules to tailor the password list so as to avoid superfluous test cases.
8. Use a suitable tool or custom script to quickly generate login requests using all permutations of these usernames and passwords. Monitor the server's responses to identify successful login attempts. Chapter 14 describes in detail various techniques and tools for performing customized attacks using automation.
9. If you are targeting several usernames at once, it is usually preferable to perform this kind of brute-force attack in a breadth-first rather than depth-first manner. This involves iterating through a list of passwords (starting with the most common) and attempting each password in turn on every username. This approach has two benefits. First, you discover accounts with common passwords more quicky. Secondly, you are less likely to trigger any account lockout defenses, because there is a time delay between successive attempts on each account.
## Verbose Failure Messages:
1. If you already know one valid username(for example, an account you control), submit one login using this username and an incorrect password, and another login usinga random username.
2. Record every detail of the server's responses to each login attempt, including the status code, any redirects, information displayed onscreen, and any differences hidden in the HTML page source. Use your intercepting proxy to maintain a full history of all traffic to and from the server.
3. Attempt to discover any obvious or subtle differences in the server's responses to the two login attempts.
4. If this fails, repeat the exercise everywhere within the application where a username can be submitted(for example, self-registration, password change, and forgotten password.)
5. If a difference is detected in the server's response to valid and invalid usernames, obtain a list of common usernames. Use a custom script or automated tool to quickly submit each username, and filter the responses that signify that the username is valid(Chapter 14)
6. Before commencing your enumeration exercise, verify whether the application performs any account lockout after a certain numbers of failed login attempts.(see preceeding section). If so, it is desirable to design your enumeration attack with this fact in mind. Try a weak or common password and password spray.  To set the password field to be the same as the username, you can use the "Battering Ram" Intruder attack in Burp to insert the same payload at multiple positions in your login request.
## Vulnerable Transmission of Credentials:
1. Carry out a successful login while monitoring all traffic in both directions between the client and server.
2. Identify every case in which the credentials are transmitted in either direction. You can set interception rules in your intercepting proxy to flag messages containing certain strings.(see Chapter 20)
3. If any instances are found in which credentials are submitted in a URL query string or as a cookie, or are transmitted back from the server to the client, understand what is happening, and try to ascertain what purpose the application developers were attempting to achieve. Try to find every means by which an attacker might interfere with the application's logic to compromise other user's credentials.
4. If any sensitive information is transmitted over an unencrypted channel, this is, of course, vulnerable to interception.
5. If no cases of actual credentials being transmitted insecurely are identified, pay close attention to any data that appears to be encoded or obfuscated. If this includes sensitive data, it may be possible to reverse engineer the obfuscation algorithm.
6. If credentials are submitted using HTTPS but the login form is loaded using HTTP, the application is vulnerable to a mitm attack which could be used to capture credentials.
## Password Change Functionality:
1. Identify any password change functionality within the application. If this is not explicitly linked from published content, it may still be implemented. Chapter 4 describes various techniques for discovering hidden content within an application.
2. Make various requests to the password change function using invalid usernames, invalid existing passwords, and missmatched "new password" and "confirm new password" values.
3. Try to identify any behavior that can be used for username enumeration or brute-force attacks(as described in the "Brute-Force Login" and "Verbose Failure Messages" sections)
## Forgotten Password Functionality:
1. Identify any forgotten password functionality within the application. If this is not explicitly linked from published content, it may still be implemented(see Chapter 4)
2. Understand how the forgotten password function works by doing a complete walk-through using an account you control.
3. If the mechanism uses a challenge, determine whether users can set or select their own challenge and response. If so, use a list of enumerated or common usernames to harvest a list of challenges, and review this for any that appear easily guessable.
4. If the mechanism uses a password "hint", do the same exercise to harvest a list of password hints, and target any that are easily guessable.
5. Try to identify any behavior in the forgotten password mechanism that can be exploited as the basis for username enumeration or brute-force attacks (see the previous section)
6. If the application generates an e-mail containing patterns that may enable you to predict the URLs issued to other users. Employ the same techniques as are relevant to analyzing session tokens for predictability.(see Chapter 7)
## "Remember Me" Functionality:
1. Activate any "remember me" functionality and determine whether the functionality indeed does fully "remember" the user or whether it remembers only his username and still requires him to enter a password on subsequent visits. If the latter is the case, the functionality is much less likely to expose any security flaw.
2. Closely inspect all persistant cookies that are set, and also any data that is persisted in other local storage mechanisms, such as IE's **userData**, Silverlight's **isolated storage**, or Flash local shared objects. Look for any saved data that identifies the user explicitly or appears to contain some predictable identifier of the user.
3. Even where stored data appears to be heavily encoded or obfuscated, review this closely. Compare the results of "remembering" several very similiar usernames and/or passwords to identify any opportunites to reverse-engineer the original data. Here, use the same techniques that are described in Chapter 7 to detect meaning and patterns in session tokens.
4. Attempt to modify the contents of the persistant cookie to try to convince the application that another user has saved his details on your computer.
## User Impersonation Functionality:
1. Identify any impersonation functionality within the application. If this is not explicitly linked from published content, it may still be implemented(see Chapter 4)
2. Attempt to use the impersonation functionality directly to impersonate other users.
3. Attempt to manipulate any user-supplied data that is processed by the impersonation function in an attempt to impersonate other users. Pay particular attention to any cases where userame is being submitted other than during normal login.
4. If you succeed in making use of the functionality, attempt to impersonate any known or guessed administrative users to elevate privilege.
5. When carrying out password-guessing attacks (see the "Brute-Forcible Login" section), review whether any users appear to have more than one valid password, or whether a specific password has been matched against several usernames. Also, log in as many different users with the credentials captured in a brute-force attack, and review whether everything appears normal. Pay close attention to any "logged in as X" status message.
## Incomplete Validation of Credentials:
1. Using an account you control, attempt to log in with variations on your own password: removing the last character, changing the case of a character, and removing any special typographical characters. If any of these attempts is successful, continue experimenting to try and understand what valididation is actually occurring.
2. Feed any results back into your automated password-guessing attacks to remove superfluous test cases and improve the chances of success.
## Nonunique Usernames:
1. If self-registration is possible, attempt to register the same username twice with different passwords.
2. IF the application blocks the second registration attempt, you can exploit this behavior to enumerate existing usernames even if this is not possible on the main login page or elsewhere. Make multiple registration attempts with a list of common usernames to identify the already registered names that the application blocks.
3. If the registration of duplicate usernames succeeds, attempt to register the same username twice with the same password and determine the application's behavior:
	1. If an error message results, you can exploit this behavior to carry out a brute-force attack, even if this is not possible on the main login page. Target an enumerated or guessed username, and attempt to register this username multiple times with a list of common passwords. When the application rejects a specific password, you have probably found the existing password for the targeted account.
	2. If no error message results, log in using the credentials you specified, and see what happens. You may need to register several users, and modify different data held within each account, to understand whether this behavior can be used to gain unauthorized access to other user's accounts
## Predictable Usernames:
1. If the application generates usernames, try to obtain several in quick succession, and determine whether any sequence or pattern can be discerned
2. If it can, extrapolate backwards to obtain a list of possible valid usernames. This can be used as the basis for a brute-force attack against the login and other attacks where valid usernames are required, such as exploitation of access control flaws(see Chapter 6)
## Predicatable Initial Passwords:
1. If the application generates passwords, try to obtain several in quick succession,, and determine whether any sequence or pattern can be discerned.
2. If it can, extrapolate the pattern to obtain a list of passwords for other application users.
3. If passwords demonstrate a pattern that can be correlated with usernames, you can try to log in using known or guessed usernames and the corresponding inferred passwords.
4. Otherwise, you can use the list of inferred passwords as the basis for a brute-force attack with a list of enumerated or common usernames.
## Insecure Distribution of Credentials:
1. Obtain a new account. If you are not required to set all credentials during registration, determine the means by which the application distributes credentials to new users.
2. If an account activation URL is used, try to register several new accounts in close succession, and identify any sequence in the URLs you recieve. If a pattern can be determined, try to predict the activation URLs sent to recent and forthcomin users, and attempt to use these URLs to take ownership of their accounts.
3. Try to reuse a single activation URL multiple times, and see if the application allows this. If not, try locking out the target account before reusing the URL, and see if it now works.
## Fail-Open Login Mechanisms:
1. Perform a complete, valid login using an account you control. Record every piece of data submitted to the application, and every response recieved, using your intercepting proxy.
2. Repeat the login process numerous times, modifying pieces of the data submitted in unexpected ways. For example, for each request parameter or cookie sent by the client, do the following:
	- Submit an emopty string as the value.
	- Remove the name/value pair entirely
	- Submit very long and very short values.
	- Submit strings instead of numbers and vice versa.
	- Submit the same item multiple times, with the same and different values.
3. For each malformed request submitted, review closely the application's response to identify any divergences from the base case.
4. Feed these observations back into framing your test cases. When one modification causes a change in behavior, try to combine this with other changes to push the application's logic to its limits.
## Defects in Multistage Login Mechanisms:
1. Perform a complete, valid login using an account you control. Record every piece of data submitted to the application using your proxy.
2. Identify each distinct stage of the login and the data that is collected at each stage. Determine whether any single piece of information is collected more than once or is ever transmitted back to the client and resubmitted via a hidden form field, cookie or preset URL parameter (see Chapter 5)
3. Repeat the login process numerous times with various malformed requests:
	- Try performing the login steps in a different sequence.
	- Try proceeding directly to any given stage and continuing from there.
	- Try skipping each stage and continuing with the next.
	- Use  your imagination to think of other ways to access the different stages that the developers may not have anticipated.
4. If any data is submitted more than once, try submitting a different value at different stages, and see whether the login is still successful. It may be that some of the submissions are superfluous and are not actually processed by the application. It might be that the data is validated at one stage and then trusted subsequently. In this instance, try to provide the credentials of one user at one stage, and then switch at the next to acutally authenticate as a different user. It might be that the same piece of data is validated at more than one stage, but against different checks. In this instance, try to provide (for example) the username and password of one user at the first stage, and the username and PIN of a different user at the second stage.
5. Pay close attention to any data being transmitted via the client that was not directly entered by the user. The application may use this data to store information about the state of the login progress, ad the application may trust it when it is submitted back to the server. For example, if the request for stage three includes the parameter `stage2completion=true` it may be possible to advance straight to stage three by setting this value. Try to modify the values being submitted and determine wheter this enables you to advance or skip stages.
6. If one of the login stages uses a randomly varying question, verify whether the details of the question are being submitted together with the answer. If so, change the question, submit the corect answer associated with that question and verify whether the login is still successful.
7. If the application does not enable an attacker to submit an arbitrary question and answer, perform a partial login several times with a single account, proceeding each time as far as the varying question. If the question changes on each occasion, an attacker can still effectivly choose which question to answer.
## Insecure Storage of Credentials:
1. Review all of the application's authentication-related functionality, as well as any functions relating to user maintenance. If you find any instances in which a user's password is transmitted back to the client, this indicates that passwords are being stored insecurely, either in cleartext or using reversible encryption.
2. If any kind of arbitrary command or query execution vulnerability is identified within the application, attempt to find the location within the application's database or filesystem where user credentials are stored:
	- Query these to determine whether passwords are being stored in unencrypted form
	- If passwords are stored in hashed form, check for nonunique values, indicating that an account has a common or default password assigned, and that the hashes are being salted.
	- If the password is hashed with a standard algorithm in unsalted form, query online hash databases to determine the corresponding cleartext password value.




























































































