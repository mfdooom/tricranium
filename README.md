# Tricranium

Tricranium is my attempt at betteer understanding kerberos and golang. Right now Tricranium is essentially a golang implementation of [GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py). End goal is much  more kerberos abuse functionality.

### Installation

- ```git clone https://github.com/mfdooom/tricranium && cd tricranium```
- ```get github.com/go-ldap/ldap/v3```
- ```go get github.com/jedib0t/go-pretty/table```
- ```go get github.com/mfdooom/gokrb5/v8/```
- ```go build tricranium.go```
