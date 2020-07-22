CHAPTER 11: ATTACKING APPLICATION LOGIC:

# REAL-WORLD LOGIC FLAWS:
## **Asking the Oracle**
Manifiestation of this type of vulnerability can be found in diverse locations. Examples include account recovery tokens, token-based access to authenticated resources, and any other value being sent to the client side that needs to be either tamper-proof or unreadable to the user.
1. Look for locations where encryption (not hashing) is used in the app. Determine any locations where the app encrypts or decrypts values supplied by a user, and attempt to substitute any other encrypted values encountered withing the application. Try to cause an error within the application that reveals the decrypted value or where the decrypted value is purposely displayed on-screen.
2. Look for an "oracle reveal" vulnerability by determining where an encrypted value can be supplied that results in the corresponding decrypted value's being displayed in the app's response. Determine whether this leads to the disclosure of sensitive info such as a password or credit card.
3. Look for an "oracle encrypt" vulnerability by determining where supplying cleartext values cause the app to return a corresponding encrypted value. Determine where this can be abused by specifying arbitrary values, or malicious payloads that the application will process.
## **Fooling a Password Change Function**
1. When probing key functionality for logic flaws, try removing in turn each parameter submitted in requests, including cookies, query string fields. and items of `POST` data.
2. Be sure to delete the acutal name of the parameter as well as its value. Do not just submit an empty string, because typically the server handles this differently.
3. Attack only one parameter at a time to ensure that all relevant code paths within the app are reached.
4. If the request you are manipulating is part of a multistage process, follow the process through to completion, because some later logic may process data that was supplied in earlier steps and stored within the session.
## **Proceeding to Checkout**
The technique for finding and exploiting flaws of this kind is known as *forced browsing*. It involves cirumventing any controls imposed by in-browser navigation on the sequence in which application functions may be accessed:
1. When a multistage process involves a defined sequence of request, attempt to submit these requests out of the expected sequence. Try skipping certain stages, accessing a single stage more than once, and accessing earlier stages after later ones.
2. The sequence of stages may be accesssed via a series of `GET` or `POST` requests for distinct URLs, or they may invilve submitting different sets of parameters to the same URL. The stage being requested may be specified by submitting a function name or index within a request parameter. Be sure to understand fully the mechanisms that the app is employing to deliver access to these distinct stages.
3. From the context of the functionality that is implemented, try to understand what assumptions the developers may have made and where the key attack surface lies. Try to identify ways of violating those assumptions to cause undesirable behavior within the app.
4. When multistage functions are accessed out of sequence, it is common to encounter a variety of anomalous conditions within the application, such as variables with null or uninitialized values, a partially defined or inconsistant state, and other unpredictable behavior. In this situation, the app may return an interesting error message and debug output, which you can use to better understand its internal workings and thereby fine-tune the current or a different attack (se Chapter 15). Sometimes, the app may get into a state entirely unanticipated by developers, which may lead to series security flaws.
## **Rolling Your Own Insurance**
The flaws in this application were fundamental to its security, but none of them would have been identified by an attacker who simply intercepted browser requests and modified the parameter values being submitted.
1. Whenever an app implements a key action across multiple stages, you should take parameters that are submitted at one stage of the process and try submitting these to a different stage. If the relevant items of data are updated within the app's state, you should explore the ramifications of this behavior to determine whether you can leverage it to carry out any malicious action, as in the preceding three examples.
2. If the app implements functionality whereby different catagories of user can update or perform other actions on a common collection of data,  you should walk through the process using each type of user and observe the parameters submitted. Where different parameters are ordinarily submitted by different users, take each parameter submitted by one user and try to submit it as the other user. If the parameter is accepted and processed as that user, explore the implications of this behavior as previously described.
## **Breaking the Bank**
1. In a complext application involving either horizontal or vertical privilege segregation, try to locate any instances where an individual user can accumulate an amount of state within his session that relates in some way to his identity.
2. Try to step through one area of functionality, and then switch to an unrelated area, to determine whether any accumulated state infromation has an effect on the app's behavior.
## **Beating a Business Limit**
The first step in attempting to beat a business limit is to understand what characters are accepted within the relevant input that you control.
1. Try entering negative values, and see if the app accepts them and processes them in the way you would expect.
2. You may need to perform several steps to engineer a change in the application's state that can be exploited for a useful purpose. For example, several transfers between accounts may be required until a suitable balance has been accrued that can actually be extracted.
## **Cheating on Bulk Discounts**
1. In any situation where prices or other sensitive values are adjusted based on criteria that are determined by user-controllable data or actions, first understand the algorithms that the application uses and the point within its logic where adjustments are made. Identify whether these adjustments are made on a one-time basis or whether they are revised in response to further actions performed by the user.
2. Think imaginatively. Try to find a way of manipulating the app's behavior to cause it to get into a state where the adjustments it has applied do not correspond to the original criteria intended by its designers. In the most obvious case, as just described, this may simply involve removing items from a shopping card after a discount has been applied!
## **Escaping from Escaping**
Whenever you probe an application for command injection and other flaws, having attempted to inser the relevant metacharacters into the data you control, always try placing a `backslash` immediately before each such character to test for the logic flaw just described. This same flaw can be found in some defenses against XSS you can submit `\'` to escape the filter.
## **Invalidating Input Validation**
Make a note of any instances in which the application modifies user input, in particular by truncating it, stripping out data, encoding, or decoding. For any observed instances, determine whether a malicious string can be contrived:
1. If data is stripped once (nonrecursively), determine whether you can submit a string that compensates for this. For example, if the application filters SQL keywords such as `SELECT`, submit `SELECTSELECT` and see if the resulting filtering removes the inner `SELECT` substring, leaving just the word `SELECT`.
2. If data validation takes place in a set order and one or more validation processes modifies the data, determine whether this can be used to beat one of the prior validation steps. For example, if the app performs URL decoding and then strips malicious data such as the `<script>` tag, it may be possible to overcome this with strings such as :
```
%<script>3cscript%<script>3ealert(1)%<script>3c/script%<script>3e
```
## **Snarfing Debug Messages**
1. To detect a flaw of this kind, first catalog all the anomolous events and conditions that can be generated and that involve interesting user-specific information being returned to the browser in an unsusal way, such as a debugging error message.
2. Using the app as two users in parallel, systematically engineer each condition using one or both users, and determine whether the other user is affected in each case.
## **Racing Against the Login**
Performing remote black-box testing for subtle thread safety issues of this kind is not straightforward. It should be regarded as a specialized undertaking, probably nexessary only in the most security-critical of applications.
1. Target selected items of key functionality, such as login mechanisms, password change functions, and funds transfer processes.
2. For each function tested, identify a single request, or a small number of requests, that a given user can use to perform a single action. Also find the simplest means of confirming the result of the action, such as verifying that a given user's login has resulted in access to that person's account information.
3. Using several high-spec machines, accessing the application from different network locations, script an attack to perform the same action repeatedly on behalf of several different users. Confirm whether each action has the expected result.
4. Be prepared for a large volume of false positives. Depending on the scale of the app's supporting infrastructure, this activity may well amount to a load test of the installation. Anomalies may be experienced for reasons that have nothing to do with security.










































