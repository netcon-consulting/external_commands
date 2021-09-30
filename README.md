external_commands.py V2.1.0
===========================

Installation script for Clearswift external commands (see https://github.com/netcon-consulting/clearswift-external-commands).

## Usage
The directory for storing the external command script can be configured with the `-d` option. Access permissions for the user `gw-services` are required.

The Python interpreter used for running the external commands can be configured with the `-i` option. Python 3.8 (yum package `rh-python38`) is recommended since the default Python 3.6 interpreter shipping with Clearswift has bugs in the `email` module used.

Following the installation or update of external commands, the Clearswift web interface needs to be reloaded. This can be done automatically on installation/update with the `-r` option or afterwards manually with `cs-servicecontrol restart tomcat`.

## Notes
On installation of an external command the corresponding policy rule(s) as well as required address, URL and lexical expression lists and Hold Areas will be created. Furthermore a lexical expression list containing customizable parameters for the external command (in TOML syntax) will be generated with default values. For a detailed documentation of the created lists and areas as well as parameters see the information for the external command with `info`.

For a multi-peer setup first install the external command on all peers, then apply the configuration to the cluster.
