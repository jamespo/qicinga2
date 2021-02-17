qicinga2
========

Short script to display Icinga 2 status on the commandline

Installation
------------

    python3 setup.py install
    
or    
    
    pip install git+https://github.com/jamespo/qicinga2.git

Configuration
-------------

Create a config file in either /etc/qicinga2 or ~/.config/.qicinga2 with contents as below

    [Main]
    icinga_url: https://icinga.example.com:5665/
    username: myicingauser
    password: mypass
	verify_ssl: on
	cafile: ~/.config/icinga2.crt

- As this file contains your password ENSURE it is permissioned correctly (ie chmod 0600).
- The icinga_url is for the Icinga2 API
- Specifying a cafile and disabling verify_ssl is of course quite pointless.
- Best practise as this is just a reporting script it should be a read-only user.

Command line options:

	-h, --help   show this help message and exit
	-a, --all    show all statuses
	-s           short summary
	-c           colour output
	-b           no colour output
	-q           quiet - no output, no summary, just return code
	-x HOSTNAME  hostname - AUTOSHORT / AUTOLONG   NOT IMPLEMENTED YET
		  

The colour output option works best on black background terminals.

Misc
----

*Icinga 1 version here: https://github.com/jamespo/jp_nagios_checks/tree/master/qicinga*

