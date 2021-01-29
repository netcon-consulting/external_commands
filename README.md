external_commands.py V1.2.0
===========================

Installation script for Clearswift external commands (see https://github.com/netcon-consulting/clearswift-external-commands).

## Usage
Following the installation of new external commands, the Clearswift web interface needs to be reloaded. This can be done automatically on installation with the `-r` option or afterwards manually with `cs-servicecontrol restart tomcat`.

## Notes
On installation of an external command the corresponding policy rule(s) as well as required address, URL and lexical expression lists and Hold Areas will be created. Furthermore a lexical expression list containing customizable parameters for the external command (in TOML syntax) will be generated with default values. For a detailed documentation of the created lists and areas as well as parameters see the information for the external command with `info`.

For a multi-peer setup first install the external command on all peers, then apply the configuration to the cluster.
