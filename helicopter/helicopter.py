import requests #when will this become part of the standard library =\
import sys, os, fnmatch, time
import json
import hashlib
import logging
import atexit

__author__ = '@2xxeformyshirt'
__version__ = '1.0.0'

'''logger'''
lf = '/etc/helicopter/logs/helicopter.log'
if not os.path.isfile(lf):
    os.mknod(lf)
logging.basicConfig(filename=lf,format='%(levelname)s | %(asctime)s | %(message)s',datefmt='%m/%d/%Y %I:%M:%S %p',level=logging.DEBUG) #using debug level will emit request data to log
helicopterlogger = logging.getLogger('helicopter')
helicopterlogger.info('Started')

class TargetFile():
    def __init__(self,fpath,fhash):
        self.fpath = fpath
        self.fhash = fhash
        self.malicious = None
        self.suspicious = None
        self.burned = False

    def checkvthash(self):
        '''get the results for all watched files

           This uses the same URL as your browser for searching instead of the API
           because the public API limits are extrememly limited. However, it would
           not be infeasible to use the public API, you would just need to be more
           diligent about timing your requests properly and making sure each payload
           is checked in each round'''

        url = 'https://www.virustotal.com/ui/search?query=%s' % self.fhash 
        ua = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        r = requests.get(url,headers=ua)
        rj = r.json()

        '''if the hash is for a file that hasnt been scanned, data will be empty, 
           so no further actions are required'''
        if len(rj['data']) > 0:
            self.malicious = rj['data'][0]['attributes']['last_analysis_stats']['malicious']
            self.suspicious = rj['data'][0]['attributes']['last_analysis_stats']['suspicious']
            self.burned = True
            helicopterlogger.info('Payload %s (%s) burned' % (self.fpath, self.fhash))

class Helicopter():
    def __init__(self,cfg):
        '''
        Config file structure:
            {
                "webhook":{
                    "url":"<urls>",
                    "type":"<type (e.g. teams)>",
                    "id":"<id (e.g. server01)>"
                },
                "time":{  
                    "delay":<int (seconds)>,
                    "throttle":<int (minutes)>
                },
                "directories":[
                    {
                        "root":"<path>",
                        "glob":"<string (e.g. *.exe)"
                    },
                    {
                        "root":"<path>",
                        "glob":"<string (e.g. *.exe)"
                    },
                    ...
                ],
                "files":[
                    "<path>"
                ] 
            }
        '''
        try:
            with open(cfg,'r') as f:
                jc = json.loads(f.read())
            self.webhooktype = jc['webhook']['type']
            self.webhookurl = jc['webhook']['url']
            self.webhookid = jc['webhook']['id']
            self.timedelay = jc['time']['delay']        #in minutes
            self.timethrottle = jc['time']['throttle']  #in seconds - you should probably increase this as you increase the number of payloads
            self.directories = jc['directories']
            self.files = jc['files']
        except:
            helicopterlogger.error('Could not read configuration file')
            sys.exit()
        self.allfiles = []

    def launch(self):
        '''launch timed requestor'''
        if os.path.isfile('/etc/helicopter/lock'):
            helicopterlogger.error('Lock file exists')
            sys.exit()
        while(True):
            helicopterlogger.info('Checking payloads against VirusTotal')
            self.routine()
            time.sleep(self.timedelay*60)
        
    def routine(self):
        '''routine to run every period'''
        self.getfiles()
        helicopterlogger.info('Total payloads to check: %i' % len(self.allfiles))
        hashes = []
        for f in self.allfiles:
            hashes.append(TargetFile(f,self.getfilehash(f)))
        for o in hashes:
            o.checkvthash()
            if o.burned:
                self.webhookalert('payload',o)
            time.sleep(self.timethrottle)

    def getfilehash(self,file):
        '''return SHA1 of supplied file'''
        sha1sum = hashlib.sha1()
        with open(file, 'rb') as f:
            block = f.read(2**16)
            while len(block) != 0:
                sha1sum.update(block)
                block = f.read(2**16)
        return sha1sum.hexdigest()

    def getfiles(self):
        '''get list of files specified in config
           checks directories recursively'''
        self.allfiles = []
        inclfiles = []
        for pair in self.directories:
            for root,dirs,files in os.walk(pair['root']):
                glob = pair['glob'] if pair['glob'] != '' else '**'
                for file in fnmatch.filter(files,glob):
                    inclfiles.append(os.path.join(root,file))
        inclfiles.extend(self.files)
        '''covers cases where the config contains nonexistent directories/files'''
        for f in inclfiles:
            if os.path.isfile(f):
                self.allfiles.append(f)
        self.allfiles = set(self.allfiles)     

    def webhookalert(self,atype,obj):
        '''send payload details to webhook'''

        ct = {'Content-Type': 'application/json'}
        title = ''
        text = ''
        
        if atype == 'payload':
            '''payload for normal burn alerts'''
            title = '[Helicopter] Payload Burned'
            text = '[ID: %s] [File: %s] [Hash:%s] [Malicious:%i] [Suspicious:%i]' % (self.webhookid ,obj.fpath,obj.fhash,obj.malicious,obj.suspicious)
        elif atype == 'error':
            '''alert for when the service stops unexpectedly'''
            title = '[Helicopter] Service Stopped'
            text = 'The Helicopter service has stopped'
        if self.webhooktype == 'teams':
            payload = {
                '@context': 'http://schema.org/extensions',
                '@type': 'MessageCard',
                'title': title,
                'text': text
            }
        elif self.webhooktype == 'slack':
            payload = {
                'text': title,
                'attachments':[
                    {
                        "text": text
                    }
                ]
            }

        r = requests.post(self.webhookurl,headers=ct,data=json.dumps(payload))

def exithandler(helicopter):
    '''create a lockfile on exit to prevent inadvertently spamming VirusTotal'''
    try:
        os.mknod('/etc/helicopter/lock')
    except:
        pass
    o = None
    helicopterlogger.error('Quitting!')
    helicopter.webhookalert('error',o)
    sys.exit()
    
def main(cfg=None):
    if len(sys.argv) == 2:
        cfg = sys.argv[1]
    else:
        cfg = os.getenv('HELICOPTER_CONFIG','/etc/helicopter/config.json')

    if not os.path.isfile(cfg):
        helicopterlogger.error('Could not find configuration file')
        sys.exit()
    helicopter = Helicopter(cfg)
    atexit.register(exithandler,helicopter)
    helicopter.launch()

if __name__ == '__main__':
    sys.exit(main())
    '''credit to Elastalert, which I used as a reference'''