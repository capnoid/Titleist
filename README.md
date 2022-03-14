# Titleist
Watching sketchy domains as they are registered. 

This repo uses the CertStream python library to look at the names of domains being registered for DNS. It then looks at the levenshtein distance between this name
and each of many "top domains" looking for mispellings/bitflips. The threshold for triggering a messagae can be tweaked (currently low so it misses many but has 
fewer false positives). 

Example:
```bash
03/14/22 06:44:22 arttj.net was registered [similar to att.net? IP:23.108.179.149]
```
## Usage:
`python3 spotasquat.py`

## Logging 
Suspicious domains will be logged to a file called  `squatters.txt` by default in the directory you run the python script from. 
