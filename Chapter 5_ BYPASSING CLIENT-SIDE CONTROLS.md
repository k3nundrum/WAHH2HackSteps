Chapter 5: BYPASSING CLIENT-SIDE CONTROLS

# Transmitting Data Via the Client:
1. Locate all instances within the application where hidden form fields, cookies and URL parameters are apparently being used to transmit data via the client.
2. Attempt to determin or guess the role that the item plays in the application's logic, based on the context in which it appears and on clues such as the parameter's name.
3. Modify the item's value in ways that are relevant to its purpose in the application. Ascertain whether the application processes arbitrary values submitted in the parameter, and whether this exposes the application to any vulnerabilites.
## Faced with Opaque Data:
1. If you know the value of the plaintext behind the opaque string, you can attempt to decipher the obfuscation algorithm being employed.
2. As described in Chapter 4, the application may contain functions elsewhere that you can leverage to return the opaque string resulting from a piece of plaintext you control. In this situation, you may be able to directly obtain the required string to deliver an arbitary payload to the function you are targeting.
3. Even if the opaque string is impenetrable, it may be possible to replay its value in other contexts to achieve a maliciou effect. For example, the **pricing_token** parameter in the previously shown form may contain an encrypted version of the product's price. Although it is not possible to produced the encrypted equivalent for an arbitrary price of your choosing, you may be able to copy the encrypted price from a different, cheaper product and submit this in its place.
4. If all else fails, you can attempt to attack the server-side logic that will decrypt or deobfuscate the opaque string by submitting malformed variation of it. For example, containing overlong values, different character sets etc...

## ASP.NET ViewState:
1. If you are attacking an ASP.NET application, verify whether MAC protection is enabled for the **ViewState**. This is indicated by the presence of a 20-byte hash at the end of the **ViewState** structure, and you can use the **ViewState** parser in Burp to confirm whether this is present.
2. Even if the **ViewState** is protected, use Burp to decode the **ViewState** on various application pages to discover whether the application is using the **ViewState** to transmit any sensitive data via the client.
3. Try to modify the value of a specific parameter within the **ViewState** without interfering with its structure,and see whether an error message results.
4. If you can modify the **ViewState** without causing errors, you should review the function of each parameter within the **ViewState** and see whether the application uses it to store any custom data. Try to submit crafted values as each parameter to probe for common vulnerabilites, as you would for any other item of data being transmitted via the client.
5. Note that MAC protection may be enabled or disabled on a per-page basis, so it may be necessary to test each significant page of the application for **ViewState** hacking vulnerabilites. If you are using Burp Scanner with passive scanning enabled, Burp automatically reports any pages that use the **ViewState** without MAC protection enabled.

# Capturing User Data: HTML Forms:
## Length Limits:
1. Look for form elements containing a **maxlength** attribute. Submit data that is longer than this length but that is formatted correctly in other respects.(For example, it is numeric if the application expects a number)
2. If the application accepts the overlong data, you may infer that the client-side validation is not replicated on the server.
3. Depending on the subsequent processing that the application performs on the parameter, you may be able to leverage the defects in validation to exploit other vulnerabilites, such as SQL injection, Cross-Site Scripting or buffer Overflows.
## Script-Based Validation:
1. Identify any cases where client-side JavaScript is used to perform input validation prior to form submission.
2. Submit data to the server that the validation ordinarily would have blocked, either by modifying the submission request to inject invalid data or by modifying the form validation code to neutralize it.
3. As with length restrictions, determine whether the client-side controls are replicated on the server and, if not, whether this can be exploited for malicious purpose.
4. Note that if multiple input fields are subjected to client-side validation prior to form submission, you need to test each field individually with invalid data while leaving valid values in all other fields. If you submit invalid data in multiple fields simultaneously, the server might stop processing the form when it identifies the first invalid field. Therefore, your testing won't reach all possible code paths within the application.
## Disabled Elements:
1. Look for disabled elements within each form of the application. Whenever you find one, try submiting it to the server along with form's other parameters to determine whether it has any effect.
2. Often submit elements are flagged as disabled so that buttons appear as greyed out in contexts when the relevant action is unavailable. You should always try to submit the names of these elements to determine whether the application perfoms a server-side check before attempting to carry out the requested action.
3. Note that browsers do not include disabled form elements when forms are submitted. Therefore, you will not identify these if you simply walk through the application's functionality, monitoring the requests issued by the browser. To identify disabled elements, you need to monitor the server's responses or view the page source in your browser.
4. You can use the HTML modification feature in Burp to automatically re-enable any disabled fields used within the application.

## Obstacles to Intercepting Traffic from Browser Extensions:
1. Ensure that your proxy is correctly intercepting all traffic from the browser extension. If necessary, use a sniffer to identify any traffic that is not being proxied correctly.
2. If the client component uses a standard serialization scheme, ensure that you have the tools necessary to unpack and modify it. If the component is using a proprietary encoding or encryption mechanism, you need to decompile or debug the component to fully test it.
3. Review responses from the server that trigger key client-side logic. Often, timely interception and modification of a server response may allow you to "unlock" the client GUI, making it easy to reveal and then perform complex or multistaged privileged systems.
4. If the application performs any critical logic or events that the client component should not be trusted to perform (such as drawing a card or rolling a dice in a gambling application), look for any correlation between execution of critical logic and communication with with the server. If the client does not communicate with the server to determine the outcome of the event, the application is definitely vulnerable.
## Manipulating the Original Component Using JavaScript
1. Use the techniques described to download the component's bytecode, unpack it, and decompile it into source code.
2. Review the relevant source code to understand what processing is being performed.
3. If the component contains any public methods that can be manipulated to achieve your objective, intercept an HTML response that interacts with the component, and add some JavaScript to invoke the appropriate methods using your input.
4. If not, modify the component's source code to achieve your objective, and then recompile it execute it, either in your browser or as a standalone program.
5. If the component is being used to submit obfuscated or encrypted data to the server, use your modified version of the component to submit various suitable obfuscated attack strings to the server to probe for vulnerabilites as you would for any other parameter.
6. 











































