qicinga2
========

Short script to display Icinga 2 status on the commandline

Installation
------------

    pip install .
    
or    
    
    pip install git+https://github.com/jamespo/qicinga2.git

Configuration
-------------

Create a config file in either /etc/qicinga2 or ~/.config/.qicinga2 with contents as below

    [Main]
    icinga_url: https://icinga.example.com:5665/
    username: qicinga
    password: mypass
	cafile: ~/.config/icinga2.crt

- As this file contains a password ENSURE it is permissioned correctly (ie chmod 0600).
- The icinga_url is for the Icinga2 API
- You can create multiple menu entries for multiple servers, Main is the default.
- Best practise as this is just a reporting script it should be a read-only user.

You can create a user specifically for this script in your Icinga api-users.conf as below:

    object ApiUser "qicinga" {
        password = "bimbamboomtishtosh"
        permissions = [ "objects/query/*", "status/query" ]
    }


Command line options:

	  -h, --help   show this help message and exit
	  -a, --all    show all statuses
	  -s           short summary
	  -t           show time of last check
	  -c           colour output
	  -b           no colour output
	  -d           truncate output
	  -q           quiet - no output, no summary, just return code
	  -i ISERVER   icinga server (default: Main)
	  -x HOSTNAME  hostname - AUTOSHORT / AUTOLONG

The colour output option works best on black background terminals.

Misc
----

*Icinga 1 version here: https://github.com/jamespo/jp_nagios_checks/tree/master/qicinga*

