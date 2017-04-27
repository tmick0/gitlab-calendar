# common libs
import sys
import logging
import json

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

def handle_event(data, service, calIdMap, config):
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
    
    # var to store id of existing calendar entry
    prevId = None
    
    # if this is not a new issue, check for an existing calendar entry
    if attrs['action'] != "open":
    
        searchRes = service.events().list(
            calendarId=calId,
            privateExtendedProperty="issueId=%d" % attrs['id']
        ).execute()
        search = searchRes.get('items', [])
        
        if len(search) > 0:
            prevId = search[0]['id']
            logger.debug("Issue corresponds to existing event: %s." % prevId)
        else:
            logger.debug("Issue does not correspond to an existing event.")
    
    # build event body
    body = {
        'summary': attrs['title'],
        'description': attrs['url'],
        'extendedProperties': {
            'private': {
                'issueId': attrs['id']
            }
        }
    }
    
    if 'assignee' in data:
        body['description'] += "\nAssignee: %s" % data['assignee']['username']
    
    if attrs['due_date'] is not None:
        body['start'] = {
            'date': attrs['due_date']
        }
        body['end'] = {
            'date': attrs['due_date']
        }
    
    # if an existing entry was found...
    if prevId is not None:
    
        # delete from calendar if either the issue is closed, or the due date was removed
        if attrs['state'] == 'closed' or attrs['due_date'] is None:
            service.events().delete(
                calendarId=calId,
                eventId=prevId
            ).execute()
            logger.info("Event %s deleted." % prevId)
            return
        
        # otherwise, update the event
        else:
            service.events().update(
                calendarId=calId,
                eventId=prevId,
                body=body
            ).execute()
            logger.info("Event %s updated." % prevId)
            return
    
    # else if an existing entry was not found...
    else:
        
        # if the issue is open and there is a due date, create a new event
        if attrs['state'] in ['opened', 'reopened'] and attrs['due_date'] is not None:
            e = service.events().insert(
                calendarId=calId,
                body=body
            ).execute()
            logger.info("Event %s created." % e['id'])
            return
    
    # if we get here, that means no action was taken on the event
    logger.debug("No action taken on event:")
    logger.debug(data)

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
    
    # instantiate client
    service = discovery.build('calendar', 'v3', credentials=credentials)
    
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
                handle_event(event, service, calIdMap, config)
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

    class WebhookHTTPRequestHandler (http.server.BaseHTTPRequestHandler):
        """
        Handles incoming webhook POSTs from GitLab. Checks POST headers for
        validity, determines whether event is actionable, and if so delivers
        it to the event queue for processing.
        """
        
        def log_message(self, format, *args):
            """ Silence request logging
            """
            return
    
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
            if self.headers['X-Gitlab-Token'] != config['gitlabSecret']:
                self._failure_headers()
                return
            
            # verify correct event
            if not self.headers['X-Gitlab-Event'] in ["Issue Hook"]:
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
    config = {}
    try:
        with open(config_file, 'r') as fh:
            config = json.load(fh)
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
