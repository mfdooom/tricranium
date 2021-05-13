# Tricranium

![hercules](https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Fs-media-cache-ak0.pinimg.com%2Foriginals%2F17%2F00%2F8f%2F17008fc0619dd41beb267cbdf613b987.jpg&f=1&nofb=1)

Tricranium is my attempt at better understanding kerberos and golang. Right now Tricranium is essentially a golang implementation of [GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py). End goal is much  more kerberos abuse functionality.

### Installation

- ```git clone https://github.com/mfdooom/tricranium && cd tricranium```
- ```go get github.com/go-ldap/ldap/v3```
- ```go get github.com/jedib0t/go-pretty/table```
- ```go get github.com/mfdooom/gokrb5/v8/```
- ```go build tricranium.go```

### Usage

~~~
Usage: tricranium [-dc-ip ip address] [-request] [-rc4] [-request-user domain/username] [-hash NT:LM] [-delay seconds] target

arguments:

  target domain/username[:password]

optional arguments:

  -dc-ip string
         domain controller ip addreess
  -delay int
        number of seconds delayed between TGS requests
  -hash string
        NTLM Hash in the format LMHASH:NTHASH
  -rc4
        Only request TGS for accounts with RC4 specefied
  -request
        Requests TGS for users
  -request-user string
        Requests TGS of the specified user
~~~
