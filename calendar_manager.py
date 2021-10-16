# common libs
import sys
import logging
import json
from copy import deepcopy

# google api libs
from apiclient import discovery
from oauth2client.service_account import ServiceAccountCredentials

# webhook server libs
import http.server
import socketserver
import socket
import ssl

# threading libs
from threading import Thread, Event, current_thread
from queue import Queue

# imports for dropping root privs
import os
import pwd
import grp

# signal handling
import signal

# default configuration dict
DEFAULT_CONFIG = {
    'logLevel': 'INFO',
    'timezone': 'Etc/UTC',
    'gitlabApi': {
        'enable': False
    },
    'ssl': {
        'enable': False
    },
    'dropPrivileges': {
        'enable': False
    },
    'listenPort': 8080,
    'repoMap': {}
}

class thread_terminator (object):
    """ Dummy object to pass to queue to signal interrupt
    """
    pass
    
def stop_thread(thread, queue):
    """ Helper method to terminate thread waiting on queue
    """
    queue.put(thread_terminator())
    thread.join()
    queue.join()

def handle_event(data, service, gitlab, calIdMap, config):
    """
    Processes an incoming event "data", maps it to a calendar through "config"
    and "calIdMap", and creates/updates/deletes a calendar entry through
    "service" if necessary.
    """
    
    logger = logging.getLogger('calmgr')

    # double check that this is an issue event
    if data['object_kind'] != 'issue':
        return

    # if the repo isn't in the map, discard
    if not data['project']['name'] in config['repoMap']:
        return
    
    logger.debug("Issue event received.")

    # get calendar id
    calId = calIdMap[config['repoMap'][data['project']['name']]]
    
    # get event attributes
    attrs = data['object_attributes']
    
    # if this is not a new issue, check for an existing calendar entry and delete it
    if attrs['action'] != "open":
    
        searchRes = service.events().list(
            calendarId=calId,
            privateExtendedProperty="issueId=%d" % attrs['id']
        ).execute()
        search = searchRes.get('items', [])
        
        if len(search) > 0:
            prevId = search[0]['id']
            service.events().delete(
                calendarId=calId,
                eventId=prevId
            ).execute()
            logger.info("Existing event %s deleted." % prevId)
    
    # if issue is closed or there is no due date, we do not need to make a new issue
    if attrs['state'] in ['opened', 'reopened'] and attrs['due_date'] is not None:
        
        # build event body
        body = {
            'summary': attrs['title'],
            'description': "%s #%d\n%s" % (data['project']['name'], attrs['iid'], attrs['url']),
            'extendedProperties': {
                'private': {
                    'issueId': attrs['id']
                }
            },
            'start': {
                'date': attrs['due_date']
            },
            'end': {
                'date': attrs['due_date']
            },
            'guestsCanInviteOthers': False,
            'transparency': 'transparent',
            'attendees': []
        }
        
        # populate assignee field using email from gitlab, if feature is enabled
        
        if 'assignees' in data:
            if gitlab and config['gitlabApi']['inviteAssignees']:
                for a in data['assignees']:
                    body['attendees'].append({
                        'email': gitlab.users.list(username=a['username'])[0].email,
                        'responseStatus': 'accepted'
                    })
            else:
                body['description'] += "\nAssignees: {:s}".format(', '.join(a['username'] for a in data['assignees']))
        
        # call api to create issue
        e = service.events().insert(
            calendarId=calId,
            body=body
        ).execute()
        logger.info("New event %s created." % e['id'])

def event_processor_thread(config, credentials, flag, queue):
    """
    Event processing thread. Gathers calendar IDs, signals the synchronization
    event "flag" to wake the main thread, then enters the event handling
    loop.
    """
    
    logger = logging.getLogger('calmgr')
    
    logger.info("Event processing thread starting...")
    
    # set success flag to true initially
    current_thread().successful_init = True
    
    # instantiate google api client
    service = discovery.build('calendar', 'v3', credentials=credentials)
    
    # instantiate gitlab api client if enabled
    gitlab = None
    if config['gitlabApi']['enable']:
        try:
            from gitlab import Gitlab
            gitlab = Gitlab(config['gitlabApi']['url'], config['gitlabApi']['token'])
        except Exception as e:
            logger.error("Failed to instantiate GitLab API client.")
            logger.exception(e)
            current_thread().successful_init = False
    
    # get calendar mappings
    logger.info("Initializing calendar ID mapping...")
    try:
        calIdMap = get_cal_id_map(service, config)
    except Exception as e:
        logger.error("Failed to load calendar ID mapping.")
        logger.exception(e)
        current_thread().successful_init = False
    
    for calName, calId in calIdMap.items():
        logger.info("ID for calendar \"%s\" is \"%s\"" % (calName, calId))
    
    # wake main thread
    flag.set()
    
    # if successful, start event loop
    if current_thread().successful_init:
    
        logger.info("Entering event loop...")
    
        while True:
        
            # try to get event from queue. break loop on thread_terminator.
            event = queue.get()
            if isinstance(event, thread_terminator):
                queue.task_done()
                break
            
            # process event, logging any error
            try:
                handle_event(event, service, gitlab, calIdMap, config)
            except Exception as e:
                logger.error("Unhandled exception while processing event.")
                logger.exception(e)
                
            queue.task_done()
        

def get_http_handler(queue, config):
    """
    Factory to build a WebhookHTTPRequestHandler class with closure over the
    passed parameters.
    
    Returns the new WebhookHTTPRequestHandler class.
    """
    
    logger = logging.getLogger('calmgr')

    class WebhookHTTPRequestHandler (http.server.BaseHTTPRequestHandler):
        """
        Handles incoming webhook POSTs from GitLab. Checks POST headers for
        validity, determines whether event is actionable, and if so delivers
        it to the event queue for processing.
        """
        
        def log_message(self, format, *args):
            """ Pass HTTP events to our logger
            """
            logger.debug(format % args)
    
        def _success_headers(self):
            """ Send success response (HTTP 200)
            """
            self.send_response(200)
            self.send_header('content-type', 'text/plain')
            self.end_headers()
        
        def _failure_headers(self):
            """ Send failure response (HTTP 403)
            """
            self.send_response(403)
            self.send_header('content-type', 'text/plain')
            self.end_headers()
    
        def do_POST(self):
            """ Handle incoming webhook POST
            """
            
            # verify auth token
            if not 'X-Gitlab-Token' in self.headers or self.headers['X-Gitlab-Token'] != config['gitlabSecret']:
                logger.debug('Dropping event with bad secret')
                self._failure_headers()
                return
            
            # verify correct event
            if not 'X-Gitlab-Event' in self.headers or not self.headers['X-Gitlab-Event'] in ["Issue Hook"]:
                logger.debug('Dropping non-issue event')
                self._failure_headers()
                return
            
            # send 200 response
            self._success_headers()
            
            # decode json post
            raw_data = self.rfile.read(int(self.headers['Content-Length']))
            dec_data = json.loads(raw_data.decode('utf8'))
            
            # enqueue event for async processing
            queue.put(dec_data)
            
            return
        
    return WebhookHTTPRequestHandler

def get_cal_id_map(service, config):
    """ Returns a mapping from calendar names (discovered via "config") to
        calendar IDs, by quering "service".
    """

    logger = logging.getLogger('calmgr')

    # fetch list of calendars to determine if setup is necessary
    calsRes = service.calendarList().list().execute()
    cals = calsRes.get('items', [])
    
    # create set of calendars we need id's for
    calNames = set(config['repoMap'].values())
    
    # create map to contain id's
    calIdMap = {}
    
    # iterate through calendars
    for calName in calNames:
    
        # try to find calendar
        try:
            calIdMap[calName] = next(filter(
                lambda c: c['summary'] == calName,
                cals
            ))['id']
            logger.info("Found existing calendar \"%s\"" % calName)
        
        # if no calendar exists...
        except StopIteration:
    
            # create one
            created = service.calendars().insert(
                body = {
                    'summary':  calName,
                    'timeZone': config['timezone']
                }
            ).execute()
            
            # get the id
            calIdMap[calName] = created['id']
            
            # give the domain read access
            service.acl().insert(
                calendarId = calIdMap[calName],
                body = {
                    'scope': {
                        'type':  'domain',
                        'value': config['authorizedDomain']
                    },
                    'role': 'reader'
                }
            ).execute()
            
            logger.info("Created new calendar \"%s\"" % calName)
        
    return calIdMap

def main(config_file="config.json"):
    """ Usage: python3 calendar_manager.py [path/to/config_file.json]
    """

    stream = logging.StreamHandler()
    stream.setFormatter(logging.Formatter("%(asctime)-15s [%(levelname)s] %(message)s"))
    logger = logging.getLogger('calmgr')
    logger.addHandler(stream)

    # load configuration
    config = deepcopy(DEFAULT_CONFIG)
    try:
        with open(config_file, 'r') as fh:
            config.update(json.load(fh))
    except Exception as e:
        logger.error('Could not load configuration file, terminating.')
        logger.exception(e)
        return 1

    # start logging
    logger.setLevel(level=getattr(logging, config['logLevel']))
    
    # create synchronization structures
    flag = Event()
    queue = Queue()

    # instantiate http listener
    try:
        httpd = socketserver.TCPServer(("", config['listenPort']), get_http_handler(queue, config))
        if config['ssl']['enable']:
            httpd.socket = ssl.wrap_socket(
                httpd.socket, 
                server_side=True,
                keyfile=config['ssl']['keyfile'],
                certfile=config['ssl']['certfile'],
            )
        httpd.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except Exception as e:
        logger.error("Failed to initialize HTTP server. Terminating.")
        logger.exception(e)
        return 1
    
    # load google api credentials
    logger.info("Loading API credentials...")
    creds = ServiceAccountCredentials.from_json_keyfile_name(
        config['googleSecretFile'], 'https://www.googleapis.com/auth/calendar'
    )
    
    # drop root privileges
    if os.geteuid() == 0 and config['dropPrivileges']['enable']:
        logger.info("Dropping root privileges...")
        uid = pwd.getpwnam(config['dropPrivileges']['user']).pw_uid
        gid = grp.getgrnam(config['dropPrivileges']['group']).gr_gid
        os.setgroups([])
        os.setgid(gid)
        os.setegid(gid)
        os.setuid(uid)
        os.seteuid(uid)
        os.umask(0o077)
    
    # make child thread ignore sigint
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    
    # instantiate event processing thread
    thread = Thread(
        target=event_processor_thread,
        args=[config, creds, flag, queue]
    )
    thread.start()
    flag.wait()
    
    # check for successful initialization
    if not thread.successful_init:
        logger.error("Event processing thread failed to initialize. Terminating.")
        thread.join()
        queue.join()
        return 1
    
    logger.info("Event processing thread successfully initialized.")
    logger.info("Starting HTTP listener...")
    
    # re-enable sigint and register a handler to translate it to KeyboardInterrupt
    def sig_hdl(sig, frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGINT, sig_hdl)
    
    # start listening
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
        
    logger.info("Received interrupt, closing threads...")
    
    # terminate event thread
    stop_thread(thread, queue)
    
    logger.info("Goodbye.")
    
    return 0

if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
