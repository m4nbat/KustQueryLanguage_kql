# M365 post account compromise discovery using SnaffPoint or similar tooling

## Source: https://github.com/nheiniger/SnaffPoint


## MDE KQL Queries

### Look for suspicious search activity based on discovery / sharepoint enumeration tools and create counts that could indicate suspicious / malicious activity

`//add sensitive keywords or search strings to fit your individual business needs. 
let keywords = datatable (keyword:string)["password","passwords","filename:logins.json","NVRAM config last updated","simple-bind authenticated encrypt",
"pac key","snmp-server community","SqlStudio.bin",".mysql_history",".psql_history",".pgpass",".dbeaver-data-sources.xml","credentials-config.json",
"dbvis.xml","robomongo.json","recentservers.xml","sftp-config.json","filename:proftpdpasswd","filename:filezilla.xml","MEMORY.DMP","hiberfil.sys","lsass.dmp","lsass.exe.dmp", "connectionstring",".bash_history",".zsh_history",".sh_history","zhistory",".irb_history","ConsoleHost_History.txt","id_rsa","id_dsa","id_ecdsa","id_ed25519","database.yml",".secret_token.rb","knife.rb","carrerwave.rb","omiauth.rb",".git-credentials","filename:customsettings.ini",
"X-Amz-Credential","aws_key","awskey","aws.key","aws-key","*aws*",@'NEAR("getConnection*", "jdbc:", n=2)',"*validationkey* OR *decryptionkey*","validationkey","decryptionkey",
@'NEAR(OR("user","username","login"), OR("password","pass","passw","passwd","secret","key","credential"), n=4)',@'AND(NEAR("create", OR("user", "login"), n=1), OR("identified by", "with password"))',
@'OR(mysql_connect,mysql_pconnect,mysql_change_user,pg_connect,pg_pconnect)',
@'*validationkey* OR *decryptionkey*',
@'NEAR("getConnection*", "jdbc:", n=2)',
@'AND(NOT("*SENSITIVE*DATA*DELETED*"),OR(filename:Autounattend.xml,filename:unattend.xml))',
@'OR("mysql.connector.connect","psycopg2.connect")',
@'OR("-SecureString","-AsPlainText","Net.NetworkCredential")',
@'filename:OR("running-config.cfg","startup-config.cfg","running-config","startup-config")',
@'OR("NVRAM config last updated","simple-bind authenticated encrypt","pac key","snmp-server community")',
@'filename:OR(".git-credentials")',
@'OR(filename:proftpdpasswd,filename:filezilla.xml)',
@'filename:OR("recentservers.xml","sftp-config.json")',
@'filename:customsettings.ini',
@'NEAR(OR("user","username","login"), OR("password","pass","passw","passwd","secret","key","credential"), n=4)',
@'OR(NEAR("schtasks", "p", n=10),NEAR("schtasks", "rp", n=10), NEAR("psexec*", "-p", n=10), "passw*", "net user ", "cmdkey ", NEAR("net use ", "/user:", n=10))',
@'OR(filename:credentials.xml,filename:jenkins.plugins.publish_over_ssh.BapSshPublisherPlugin.xml)',
@'filename:OR("SqlStudio.bin",".mysql_history",".psql_history",".pgpass",".dbeaver-data-sources.xml","credentials-config.json","dbvis.xml","robomongo.json")',
@'filename:OR("mobaxterm.ini","mobaxterm backup.zip","confCons.xml")',
@'filename:OR("id_rsa","id_dsa","id_ecdsa","id_ed25519")',
@'OR("database.yml",".secret_token.rb","knife.rb","carrerwave.rb","omiauth.rb")',
@'filename:or(MEMORY.DMP,hiberfil.sys,lsass.dmp,lsass.exe.dmp)',
@'OR(NEAR(OR("X-Amz-Credential", "aws_key", "awskey", "aws.key", "aws-key", "*aws*"), OR("AKIA*", "AGPA*", "AIPA*", "AROA*", "ANPA*", "ANVA*", "ASIA*"), n=10), "CF-Access-Client-Secret")',
@'filename:OR(".bash_history",".zsh_history",".sh_history","zhistory",".irb_history","ConsoleHost_History.txt")',
@'password',
@'NEAR(BEGIN, OR(RSA, OPENSSH, DSA, EC, PGP), PRIVATE, KEY, n=1)',
@'filename:logins.json',
@'NEAR("data source", "password", n=30)',
@'NEAR("connectionstring*", "passw*", n=30)',
@'"DBI.connect"'];
let excludedKeywords = datatable(keyword:string)["reset","policy","change","hrms","existing","update","three words","changing","forgottten","lost","forgot"];
CloudAppEvents
|where ActionType == "SearchQueryPerformed"
| extend SearchQueryStrings = tostring(RawEventData["SearchQueryText"])
| where SearchQueryStrings has_any (keywords) and not (SearchQueryStrings has_any (excludedKeywords) and SearchQueryStrings has "password")
| project Timestamp, Application, ActionType, SearchQueryStrings, AccountId, AccountType, AccountDisplayName, UserAgent, OSPlatform, IPAddress, IsAnonymousProxy, CountryCode, City, ISP, RawEventData
//remove the below lines to see raw events
| summarize count() by bin(Timestamp,1h), AccountId, AccountDisplayName
//look for results where more than two search queries were performed
| where count_ > 1
| order by count_ desc`

