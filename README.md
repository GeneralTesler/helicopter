# Helicopter 

Helicopter is a small Python script that is meant to run on a payload server. Once running, it will periodically check VirusTotal for the hashes of your payloads. If the payload was submitted to VirusTotal, Helicopter will send a notification to a webhook URL. Helicopter uses the public VirusTotal search, not the API.

*Note: this is still a somewhat beta release and requires some additional testing. If you have any feedback, please open an issue.*

## Setup

```
pip install -r requirements.txt
sudo python setup.py install
```

## Usage

```
sudo helicopter [config]
```

Config is the path to the JSON config file. If no path is provided, Helicopter will use the path specified in the HELICOPTER_CONFIG environment variable. Barring that, it will fallback to the config located at /etc/helicopter/config.json, which is created during installation (make sure to change the default values).

## Config Structure

```
{
  "webhook":{
    "url":"http://127.0.0.1:8081/webhook",
    "type":"teams",
    "id":"server01"
  },
  "time":{  
    "delay":5,
    "throttle":5
  },
  "directories":[
    {
      "root":"/var/www/html/documents",
      "glob":""
    },
    {
      "root":"/var/www/html/payloads",
      "glob":"*.exe"
    },
    ...
  ],
  "files":[
    "/var/www/html/images/thumbnail.png"
  ] 
}
```

[ Webhook ]

- Type: the webhook type
    - currently supported types: Microsoft Teams (teams) and Slack (slack)
- ID: an arbitrary identifier

[ Time ]

- Throttle: the time (in seconds) between individual requests
- Delay: the time (in minutes) between periods

[ Directories ]

- Root: the root of the directory to monitor
- Glob: the globbing pattern for files to monitor (e.g. *.exe)
    - If no glob pattern is specified, the pattern '**' is applied

[ Files ]

- list of individual files to monitor

## On Exit

When helicopter closes, it will send a webhook message. The main reason for this is to alert the operator if the program fails unexpectedly. Additionally, Helicopter creates a lock file at '/etc/helicopter/lock' on exit. If this file is present on startup, Helicopter won't start.

## To-dos

- 

## Changelog

- 8/19/2018 - Initial release
