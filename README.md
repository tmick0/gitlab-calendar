# gitlab-calendar
Webhook-based integration to add GitLab issue deadlines to Google Calendar

## Overview

This application receives issue webhooks from GitLab and manages events in
Google Calendar corresponding to those issues' deadlines.

No storage is required on the webhook server. All necessary state is stored in
extended attributes of Google Calendar events.

You must define a mapping between GitLab repositories and calendars. Any
calendars defined in the mapping will automatically be created.

A service account is utilized so that the application owns the calendars it
creates. You can add the service's calendars to your own Google Calendar account
via their IDs.

As-is, a G Suite domain is required for the purpose of access control, however
you can also modify the ACL instantiation manually to authenticate at a level
other than the domain.

## Dependencies

Tested on Python 3.5.2. May work on older versions, but not guaranteed.

Requires `google-api-python-client`, available through `pip`.

## Configuration

An example configuration file is provided in `config.json`. The following
keys are defined:

- `logLevel`: Logging detail level, choose from `DEBUG`, `INFO`, `WARNING`,
  `ERROR`.
- `timezone`: Time zone for created calendars, in standard `tzdata` format.
- `googleSecretFile`: Filename containing credentials for the Google service
  account.
- `gitlabSecret`: Webhook authentication token for GitLab.
- `authorizedDomain`: The G Suite domain name authorized to access calendars.
- `listenPort`: Port to listen for on for incoming webhooks.
- `ssl`: Configuration for TLS.
    - `enable`: Boolean indicating whether TLS should be used.
    - `keyfile`: Path to PEM file containing private key. Not required if
      `enable` is false.
    - `certfile`: Path to PEM file containing certificate. Not required if
      `enable` is false.
- `repoMap`: Mapping between GitLab project names (keys) and calendars (values).
- `dropPrivileges`: Configuration for dropping root privileges after necessary
  files and sockets are open.
   - `enable`: Boolean indicating whether to drop root privileges.
   - `user`: Name of user to switch to after initialization. Not required if
     `enable` is false.
   - `group`: Name of group to switch to after initialization. Not required if
     `enable` is false.

The Google credential file is obtained when you create a service account. A
service account can be created at
https://console.developers.google.com/iam-admin/serviceaccounts/.

Timezones and ACLs are set up at the time a calendar is created, so make sure
that the `timezone` and `authorizedDomain` values are set correctly before
populating the `repoMap` and starting the daemon for the first time.

Note that in the `repoMap`, only the actual project names are used -- not the
full namespaces. Multiple projects may be mapped to the same calendar.

The `dropPrivileges` configuration allows root privileges to be dropped after
loading TLS keys, loading API credentials, and opening the listen socket. If you
must run this application as root in order to open these files, or you are
listening on a privileged port, then it is highly recommended to enable this
feature.

## Running

Invoke as `python3 calendar_manager.py config.json`. The process will persist in
the foreground by default, so run it in a screen or under a daemon manager if
you want to background it.

The first time you run this application, it will create all calendars listed
in the `repoMap`. The IDs of these calendars will be printed to the console.
Paste an ID in Google Calendar's "Add a coworker's calendar" box to synchronize
it with your account.

A `KeyboardInterrupt` or SIGINT will cleanly stop the process.

## Behavior

Issue deadlines will be inserted as events in the specified calendars. Each
event description will include the URL of the issue, and the username of the
assignee (if applicable). Modifications to issues (title changes, deadline
changes, assignee changes) will automatically be synchronized to the calendar.

Closing an issue or removing its deadline will remove it from your calendar.
Reopening the issue or resetting its deadline will add it back again.

## Caveats

This application does not load issues from GitLab -- it only listens for events
pertaining to them in real time. Therefore, previously existing issues and
issues created or modified while this service is inactive will not be reflected
in your calendars.

Changing a repo's calendar in the `repoMap` will break things. Don't do it.

As stated above, `timezone` and `authorizedDomain` attributes of calendars
are set at the time they are created, so make sure they are correct before
you run the application for the first time.

## Implementation Details

This application consists of a webhook listener and an event processing thread.

The webhook listener is simple. It is based on Python's built-in
`BaseHTTPRequestHandler` class. When it receives a valid event from GitLab, it
adds it to the processing queue, where the processing thread will later service
it.

On initialization, the processing thread instantiates a session with the Google
Calendar API and fetches the IDs of mapped calendars. It then enters an event
loop, wherein it receives events from the queue and asynchronously processes
them. All contact with the Google calendar API occurs within this event thread.

## Contributing

If you can make this program better without breaking anything, I will gladly
accept your pull request. If you find something that is already broken, submit
a report and I'll get to it as soon as possible.

## License

This software is provided as-is without warranty under the terms of the MIT
License, available in the `LICENSE` file distributed alongside it.
