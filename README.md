#Introduction
VirusTotal-ICAP is a simple ICAP service that will look for various file types, then look up those files in VirusTotal to determine if they are malicious or not. If the files are marked as malicious by VT then they are not allowed to pass-through to the client.

#Requirements
* https://github.com/sooshie/pyicap
* Your own VirusTotal API key
* And

```
pip install -r requirements.txt
```

Sample squid.conf

```
icap_enable on
icap_preview_enable on
icap_preview_size 1024
icap_service service_resp respmod_precache bypass=1 icap://127.0.0.1:13440/vt
adaptation_access service_resp allow all
```

#References
Based on sample code from: https://github.com/netom/pyicap

#Issues
A very non-user-friendly error message is returned from Squid in the event a file is blocked.
