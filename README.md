# PowerShell-School-IDM
A demonstration IDM system written in PowerShell for K-12 school districts. Part of an Active Directory class put on by the [Sacramento County Office of Education (SCOE)](https://www.scoe.net).

## PowerShell is pretty… Powerful
You used to have to do a lot of custom programming in C# / .NET to pull off even the simplest of IDM systems. Now PowerShell is robust enough to power a small scale IDM system that can adequately service most school districts.

Our minimum viable IDM system will use the PowerShell AD command-lets that we learned in the AD PowerShell Basics section to perform the logic necessary to manage accounts in Active Directory. We'll be using text files in CSV format to mimic the databases for the HR database and System of Record in our system. PowerShell has pretty good support for SQL Server so you could extend this system to use a SQL database but this is beyond the scope of the course.

## Limitations to our demonstration system
In most IDM systems you'll want the idea of Roles. A role defines the accounts, properties, group memberships, file shares, etc. that a person receives when assigned to it. For our purposes here, there are few hard-coded roles, the user's department, office, and job title. We'll use these to assign the corresponding AD account properties and assign them group membership.
Also, since the course focuses on AD, our only target system will be AD. We won't be provisioning users with home directories and additional application accounts as would be typical for most IDM systems.

## How to customize the system
Our test AD domain is *scoe.info*. You'll want to find and replace it with the FQDN of your test domain. This demonstration system is MIT Licensed and as such is free to customize or use for any purpose.

**Have Fun!**

*Trevor Vass*  
*Systems Engineer*  
*Sacramento Office of Education (SCOE)*  
*tvass@scoe.net*
