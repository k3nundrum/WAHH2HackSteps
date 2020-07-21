CHAPTER 9: ATTACKING DATA STORES:

# Injecting Into Interpreted Contexts:
## Bypassing a Login:
Injection into interpreted languages is a broad topic, encompassing many different kinds of vulnerabilites and potentially affecting every component of a web application's supporting infrastructure. The detailed steps for detecting and exploiting code injection flaws depends on the language that is being targeted and the programming techniques employed by the application's developers. In every instance, however, the generic approach is as follows:
1. Supply unexpected syntax that may cause problems within the context of the particular interpreted language.
2. Identify any anomalies in the application's response that may indivate the presence of a code injection vulnerability.
3. If any error messages are received, examine these to obtain evidence about the problem that occurred on the server.
4. If necessary, systematically modify your initial input to relevant ways in an attempt to confirm or disprove your tentative diagnosis of a vulnerability.
5. Construct a proof-of-concept test that causes a safe command to be executed in a verifiable way, to conclusively prove that an exploitable code injection flaw exists.
6. Exploit the vulnerability by leveraging the functionality of the target language and component to achieve your objectives.
# Injecting into SQL:
## Injecting into String Data:
1. Submit a single quotation mark as the item of data you are targeting. Observe whether an error occurs, or whether the result differs from the original in any other way. If a detailed database error message is received, consult the "SQL Syntax and Error Reference" section of this chapter to understand the meaning of the error.
2. If an error or other divergent behavior was observed, submit two single quotation marks together. Databases use two single quotation marks as an escape sequence to represent a literal single quote, so the sequence is interpreted as data within the quoted string rather than the closing string terminator. If this input causes the error or anomalous behavior to disappear, the application is probably vulnerable to SQLi.
3. As a further verification that a bug is present, you can use SQL concatenator characters to construct a string that is equivalent to some benign input. If the application handles your crafted input in the same way as it does the corresponding benign input, it is likely to be vulnerable. Each type of database uses different methods for string concatenation. The following examples can be injected to construct input that is equivalent to `FOO` in a vulnerable application:
	``` 
		Oracle: '||'FOO
		MS-SQL: '+'FOO
		MySQL: ' 'FOO(note the space between the two quotes)
	```
## Injecting into Numerical Data:
1. Try supplying a simple mathematical expression that is equivalent to the original numeric value. For example, if the original value is 2, try submitting 1+1 or 3-1. If the application responds in the same way, it *may* be vulnerable.
2. The preceeding test is most reliable in cases where you have confirmed that the item being modified has a noticable effect on the application's behavior. For example, if the application uses a numeric `PageID` parameter to specify which content should be returned, substituting 1+1 for 2 with equivalent results is a good sign that SQL injection is present. However, if you can place arbitrary input into a numeric parameter without changing the application's behavior, the preceeding test provides no evidence of a vulnerability.
3. If the first test is successful, you can obtain further evidence of the vulnerability by using more complicated expressions that use SQL-specific keywords and syntax. A good example of this is the `ASCII` command, which returns the numeric ASCII code of the supplied character. For example, because the ASCII value of A is 65, the following expression is equivalent to 2 in SQL:
```
67-ASCII('A')
```
4. The preceeding test will not work if single quotes are being filtered. However, in this situation you can exploit the fact that databases implicitly convert numeric data to string data where required. Hence, because the ASCII value of the character 1 is 49, the following expression is equivalent to 2 in SQL:
```
51-ASCII(1)
```
TIPS:
- & and = are used to join name/value pairs to create the query sting and the block of `POST` data. You should encode them using `%26` and `%3d`
- Literal spaces are not allowed in the query string. If they are submitted, they will effectively terminate the entire string. Encode spaces using `+` or `%20`
- Because + is used to encode spaces, if you want to include an actual + in your string you must encode it using `%2b`. In the previous numeric example, therefore `1+1` should be sumitted as `1%2b1`
- The semicolon is used to separate cookie fields and should be encoded using `%3b`
## Injecting Into Query Structure:
1. Make note of any parameters that appear to control the order or field types within the results that the application returns.
2. Make a series of requests supplying a numeric value in the parameter value, starting with the number 1 and incrementing it with each subsequent request:
	- If changing the number in the input field affects the ordering of the results, the input is probably being inserted into an `ORDER BY` clause. In SQL, `ORDER BY 1` orders by the first column. Increasing this number to 2 should then change the display order of data to order by the second column. If the number supplied is greater than the number of columns in the result set, the query should fail. In this situation, you can confirm that further SQL can be injected by checking whether the results order can be reversed, using the following:
	```
	1 ASC --
	1 DESC --
	```
	If supplying the number 1 causes a set of results with a column containing a 1 in every row, the input is probably being inserted into the name of a column being returned by the query. For example:
	```
	SELECT 1,title,year FROM books WHERE publisher='Wiley'
	```
## The UNION Operator:
Your first task is to discover the number of columns returned by the original query being executed by the appliation. You can do this in two ways:
1. You can exploit the fact that `NULL` can be converted to any data type to systematically inject queries with different numbers of columns until your injected query is executed. For example:
```
' UNION SELECT NULL--
' UNION SELECT NULL, NULL--
' UNION SELECT NULL, NULL, NULL--
```
When your query is executed you have determined the number of columns required. If the application doesn't return database error messages, you can still tell when you injected query was successful. An additional row of data will be returned, containing either the word `NULL` or an empty string. Note that the injected row may contain only empty table cells and so may be hard to see when rendered as HTML. For this reason, it is preferable to look at the raw response when performing this attack.
2. Having identified the required number of columns, your next task is to discover a column that has a string data type so that you can use this to extract arbitrary data from the database. You can do this by injecting a query containing NULLS, as you did perviously, and sytematically replacing each `NULL` with `a`. For example, if you know that the query must return three columns, you can inject the following:
```
' UNION SELECT 'a', NULL, NULL--
' UNION SELECT NULL, 'a', NULL--
' UNION SELECT NULL, NULL, 'a'--
```
When your query is executed, you see an additional row of data containing the value `a`. You can then use the relevant column to extrat data from the database.
## MS-SQL Blind SQLi Test:
```
'; waitfor delay '0:30:0'--
1; waitfor delaty '0:30:0'--
```
## USing SQL Exploitation Tools:
When you have identified a SQL injection vulnerability, using the techniques described earlier in this chapter, you can consider using a SQL injection tool to exploit the vulnerability and retrieve interesting data from the database. This option is particularly useful in cases wher you need to use blind techniques to retrieve a small amount of data at a time.
1. Run the SQL exploitation tool using an intercepting proxy. Analyze the request made by the tool as well as the application's responses. Turn on any verbose output options on the tool, and correlate its progress with the observed queries and responses.
2. Because these kinds of tools rely on preset tests and specific response syntax, it may be necessary to append or prepend data to the string injected by the tool to ensure that the tool gets the expected response. Typical requirements are adding a comment character, balancing the single quotes within the server's SQL query, and appending or prepending closing brackets to the string to match the original query.
3. If the syntax appears to be fainling regardless of the methods described here, it is often easiest to create a nested subquery that is fully under your control, and allow the tool to inject into that. This allows the tool to use inference to extract data. Nested queries work well when you inject into standard `SELECT` and `UPDATE` queries. Under Oracle they work within an `INSERT` statement. In each of the following cases, prepend the text occuring before `[input]`, and append the closing bracket occuring after that point:
- Oracle:
	```
	' ||(select 1 from dual where 1=[input])
	```
- MS-SQL:
	```
	(select 1 where 1=[input])
	```
# Injecting into XPath:
## Finding XPATH Injection Flaws:
1. Try submitting the following values, and determine whether these result in different application behavior, without causing an error:
```
' or count(parent::*[position()=1])=0 or 'a'='b
' or count(parent::*[position()=1])>0 or 'a'='b
```
If the parameter is numeric, also try the following test strings:
```
1 or count(parent::*[position()=1])=0
1 or count(parent::*[position()=1])>0
```
2. If any of the preceding strings causes differential behavior within the application without causing an error, it is likely that you can extract arbitrary data by crafting test conditions to extract one byte of information at a time. Use a series of conditions with the following form to determine the name of the current node's parent:
```
substring(name(parent::*[position()=1]),1,1)='a'
```
3. Having extracted the name of the parent node, use a series of conditions with the following form to extract all the data within the XML tree:
```
substring(//parentnodename[position()=1]/child::node()
[position()=1]/text(),1,1)='a'
```
# Injecting into LDAP:
## Finding LDAP Injection Flaws:
1. Try entering just the `*` character as a search term. This character functions as a wildcard in LDAP, but not in SQL. If a large number of results are returned, this is a good indicator that you are dealing with an LDAP query.
2. Try entering a number of closing brackets:
```
))))))))
```
This input closes any brackets enclosing your input, as well as those that encapsulate the main search filter itself. This results in unmatched closing brackets, thus invalidating the query syntax. If an error results, the application may be vulnerable to LDAP injection. (Note that this inpout may also break many other kinds of application logic, so this provides a strong indicator only if you are already confident that you are dealing with an LDAP query.)
3. Try entering various expressions designed to interfere with different types of queries, and see if these allow you to influence the results being returned. The `cn` attribute is supported by all LDAP implementations and is useful to use if you do not know any details about the directory you are querying. For example:
```
)(cn=*
*))(|(cn=*
*))%00
```














































