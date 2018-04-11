# probemon
A simple command line tool for monitoring and logging 802.11 probe frames

I decided to build this simple python script using scapy so that I could record 802.11 probe frames over a long period of time. This was specifically useful in my use case: proving that a person or device was present at a given location at a given time.

## Usage

```
usage: probemon.py [-h] [-i INTERFACE] [-t {iso,unix}] [-o OUTPUT] [-b MAX_BYTES]
                   [-c MAX_BACKUPS] [-d DELIMITER] [-f] [-s]
                   [-r] [-D] [-l]
                   
a command line tool for logging 802.11 probe request frames

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        capture interface
  -t {iso,unix}  output time format (default: iso)
  -o OUTPUT, --output OUTPUT
                        logging output location (default: probemon.log)
  -b MAX_BYTES, --max-bytes MAX_BYTES
                        maximum log size in bytes before rotating (default: 5242880 (5MB))
  -c MAX_BACKUPS, --max-backups MAX_BACKUPS
                        maximum number of log files to keep (default: 99999)
  -d DELIMITER, --delimiter DELIMITER
                        output field delimiter (default: ;)
  -f, --mac-info        include MAC address manufacturer
  -s, --ssid            include probe SSID in output
  -r, --rssi            include rssi in ouput
  -l, --log             enable live scrolling view of the logfile
  -D                    enable debug output
  -e, --exclude         file containing MAC addresses to exclude (default: exclude.conf)
  -z, --daemon          fork process and run in background
```

