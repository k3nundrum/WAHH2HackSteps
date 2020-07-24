CHAPTER 17: ATTACKING APPLICATION ARCHITECTURE

# Tiered Architectures
## **Using Local File Inclusion to Execute Commands**
 1. As described throughout this book, for any vulnerability you identify within the app, think imaginatively about how this can be exploited to achieve your objectives. Countless successful hacks against web apps begin from a vulnerability that is intrinsically limited in its impact. By exploiting trust relationships and undercutting controls implemented elsewhere within the application, it may be possible to leverage a seemingly minor defect to carry out a serious breach.
 2. If you succeed in performing arbitrary command execution on any component of the app, and you can initiate network connections to other host, consider ways of directly attacking other elements of the application's infrastructure at the network and operating system layers to expand the scope of your compromise.
 ## **Attacks Against ASP Application Components**
 1. Examine the access mechanism provided for customers of the shared environment to update and manage their content and functionality. Consider questions such as the following:
 - Does the remote access facility use a secure protocol and suitably hardened infrastructure?
 - Can customers access files, data, and other resources that they do not legitimately need to access?
 - Can customers gain an interactive shell within the hosting environment and perform arbitrary commands?
2. If a proprietary application is used to allow customers to configure and customize a shared environment, consider targeting this applicaiton as a means of compromising the environment itself and individual applications running within it.
3. If yoiu can achieve command execution, SQL Injection, or arbitrary file access within one application, investigate carefully whether this provides any means of escalating your attack to target other applications.
4. If you are attacking an ASP-hosted application that is made up of both shared and customized components, identify any shared components such as loggin mechanisms, administrative functions, and database code components. Attempt to leverage these to compromise the shared portion of the application and thereby attack other individual applications.
5. If a common database is used within any kind of shared environment, perform a comprehensive audid of the database configuration, patch level, table structure, and permissions, perhaps using a database scanning tool such as NGSSquirrel. Any defects within the database security model may provide a means of escalating and attack from within one application to another.