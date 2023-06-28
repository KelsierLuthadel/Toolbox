# port-scan
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=KelsierLuthadel_port-scan&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=KelsierLuthadel_port-scan)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=KelsierLuthadel_port-scan&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=KelsierLuthadel_port-scan)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=KelsierLuthadel_port-scan&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=KelsierLuthadel_port-scan)

[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=KelsierLuthadel_port-scan&metric=bugs)](https://sonarcloud.io/summary/new_code?id=KelsierLuthadel_port-scan)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=KelsierLuthadel_port-scan&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=KelsierLuthadel_port-scan)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=KelsierLuthadel_port-scan&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=KelsierLuthadel_port-scan)

[![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=KelsierLuthadel_port-scan&metric=sqale_index)](https://sonarcloud.io/summary/new_code?id=KelsierLuthadel_port-scan)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=KelsierLuthadel_port-scan&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=KelsierLuthadel_port-scan)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=KelsierLuthadel_port-scan&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=KelsierLuthadel_port-scan)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=KelsierLuthadel_port-scan&metric=coverage)](https://sonarcloud.io/summary/new_code?id=KelsierLuthadel_port-scan)

[![SonarCloud](https://sonarcloud.io/images/project_badges/sonarcloud-white.svg)](https://sonarcloud.io/summary/new_code?id=KelsierLuthadel_port-scan)

## usage
```
usage: scanner.py [-h] [-p PORT] [-t MAX_THREADS] [-e] [-b] [-w WAIT_TIME] [-r RESOLVE] [target]

Port scanner

positional arguments:
  target                
                        Target IP to scan, if this is not provided it will default to the local IP address. Can be one of: 
                        Single IP: 192.168.0.1 
                        Multiple IPs as a comma separated list and enclosed in []: [192.168.0.1,192.168.0.55] 
                        CIDR range: 192.168.0/24

options:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  
                        A range of ports, if this is not provided it will default to 22,23,80,443. Can be one of: 
                        Single port: 80 
                        Multiple ports: 80,443 
                        Range of ports: 8080-8010 
                        Combination of ports: 22,80-90,8080 
  -t MAX_THREADS, --threads MAX_THREADS
                        maximum number of threads, default is 500, with a maximum of 4096.
  -e, --show_refused    Show connection failures.
  -b, --show_banner     Show connection banner.
  -w WAIT_TIME, --wait WAIT_TIME
                        Maximum time in fractional seconds to wait for a response.
  -r RESOLVE, --resolve RESOLVE
                        Attempt to resolve hostnames

```

## example output
``scanner.py 192.168.0.1 -p 22,80``

```
Scanned 2 ports

[+] 192.168.0.1:22 is open
[+] 192.168.0.1:80 is open

Resolving hosts:
   [+] 192.168.0.1 resolves to Gateway
```
