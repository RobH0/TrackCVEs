# TrackCVEs

A python script that helps keep you up to date with the most recent CVEs for specific vendors that are relevant to you or your organisation.

The script filters CVEs by vendor names and organises them into HIGH, MEDIUM, and LOW severity HTML reports.

![](https://github.com/RobH0/project-gifs/blob/main/TrackCVEs-preview.gif)

## Usage
Running the script:
```

Usage (Windows): python track_cves.py [-h] [-f FILE] [-d DAYS]
Usage (Linux): python3 track_cves.py [-h] [-f FILE] [-d DAYS]

Options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  text file from which vendor names are read.
  -d DAYS, --days DAYS  used to only display CVEs that were
  released x number of days in the past (default: 7).

Examples:
  python track_cves.py -f vendors.txt -d 5
  python3 track_cves.py -d 4
  python3 track_cves.py
  python track_cves.py -f C:\path\to\vendors\file.txt
  ```
