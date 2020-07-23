CHAPTER 16: ATTACKING NATIVE COMPILED APPLICATIONS

# Buffer Overflow Vulnerabilites
## **DETECTING BOF**
1. For each item of data being targeted, submit a range of long strings with lengths somewhat longer that common buffer sizes. For example:
```
1100
4200
33000
```
2. Target one item of data at a time to maximize the coverage of code paths within the app.
3. YOu can use the character blocks payload source in Burp Intruder to automatically generate payloads of various sizes.
4. Monitor the app's response to identify any anomalies. An uncontrolled overflow is almost certain to cause an exception in the application. Detecting when this has occured in a remote process is difficult, but here are some anomalous events to look for:
- An HTTP 500 status code or error message, where other malformed (but not overlong) input does not have the same effect.
- An informative message, indicating that a failure occured in some native code component.
- A partial or malformed response is received from the server.
- The TCP connection to the server closes abruptly without returning a response.
- The entire web application stops responding.
5. Note that when a heap-based overflow is triggered, this may result in a crash at some future point, rather than immediately. You may need to experiment to identify one or more test cases that are causing heap corruption.
6. An off-by-one vulnerability may not cause a crash, but it may result in anomalous behavior such as unexpected data being returned by the application.
# Integer Vulnerabilites
1. Having identified targets for testing, you need to send suitable payloads designed to trigger any vulnerabilities. For each item of data being targeted, send a series of different values in turn, representing boundary cases for the signed and unsigned versions of different sizes of integer. For example:
```
0x7f and 0x80 (127 and 128)
0xff and 0x100 (255 and 256)
0x7ffff and 0x80000 (32767 and 32768)
0xffff and 0x10000 (2147483647 and 2147483648)
0xffffffff and 0x0 (4294967295 and 0)
```
2. When the data being modified is represented in hexadecimal form, you should send little-endian as well as big-endian versions of each test case -- foir example, ff7f as well as 7fff. If the hexadecimal numbers are submitted in ASCII form, you should use the same case that the application itself uses for alphabetical characters to ensure that these are decoded correctly.
3. You should monitor the application's responses for anomalous events in the same way as described for buffer overflow vulnerabilites.
# Format String Vulnerabilities
1. Targeting each parameter in turn, submit strings containing large numbers of the format specifiers `%n` and `%s`:
```
%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n
%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s
```
Note that some format string operations may ignore the `%n` specifier for security reasons. Supplying the `%s` specifier instead causes the function to dereference each parameter on the stack, probably resulting in an access violation if the application is vulnerable.
2. The Windows `FormatMessage` function uses specifiers in a different way that the `printf` family. To test for vulnerable calls to this function you should use the following strings:
```
%1!n!%2!n!%3!n!%4!n!%5!n! ...etc
%1!s!%2!s!%3!s!%4!s!%5!s! ...etc
```
3. Remember to URL-encode the `%` character as `%25`.
4. You should monitor the app's responses for anomalous events in the same way as described for buffer overflow vulnerabilities.










































