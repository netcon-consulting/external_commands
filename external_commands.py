#!/usr/bin/env python3

# external_commands.py V1.6.0
#
# Copyright (c) 2021 NetCon Unternehmensberatung GmbH, https://www.netcon-consulting.com
# Author: Marc Dierksen (m.dierksen@netcon-consulting.com)

import argparse
import enum
import sys
from pathlib import Path
from string import Template
from collections import namedtuple, Counter
from xml.sax import make_parser, handler, SAXException
from xml.sax.saxutils import quoteattr, escape
from uuid import uuid4 as generate_uuid
from os import chmod, SEEK_END
from subprocess import run, DEVNULL
from shutil import chown
import json
from urllib.request import urlopen, urlretrieve

DESCRIPTION = "install and update external commands for Clearswift SEG 5"

FILE_README = "README.md"
FILE_CONFIG = "config.json"

URL_REPO = "https://raw.githubusercontent.com/netcon-consulting/clearswift-external-commands/old2"
URL_README = "{}/{}".format(URL_REPO, FILE_README)
URL_LIBRARY = "https://raw.githubusercontent.com/netcon-consulting/netcon.py/master/netcon.py"

DIR_UICONFIG = Path("/var/cs-gateway/uicfg")
DIR_POLICY = DIR_UICONFIG.joinpath("policy")
DIR_RULES = DIR_POLICY.joinpath("rules")
DIR_ADDRESS = DIR_POLICY.joinpath("addresslists")
DIR_FILENAME = DIR_POLICY.joinpath("filenames")
DIR_URL = DIR_POLICY.joinpath("urllists")
DIR_LEXICAL = DIR_POLICY.joinpath("ta")
DIR_SCRIPTS = Path('/opt/cs-gateway/scripts/netcon')

FILE_DISPOSAL = DIR_POLICY.joinpath("disposals.xml")
FILE_MEDIATYPES = Path("/opt/cs-gateway/cfg/ui/mediatypes.xml")
FILE_STATUS = DIR_UICONFIG.joinpath("trail.xml")
FILE_LIBRARY = DIR_SCRIPTS.joinpath("netcon.py")

MODULES_LIBRARY = { "toml", "pyzipper", "beautifulsoup4", "html5lib", "dnspython" }

TEMPLATE_ADDRESS = Template('<?xml version="1.0" encoding="UTF-8" standalone="no"?><AddressList name=$name type="static" uuid="$uuid"><Address>dummy@dummy.com</Address></AddressList>')
TEMPLATE_FILENAME = Template('<?xml version="1.0" encoding="UTF-8" standalone="no"?><FilenameList name=$name type="static" uuid="$uuid"><Filename>dummy</Filename></FilenameList>')
TEMPLATE_URL = Template('<?xml version="1.0" encoding="UTF-8" standalone="no"?><UrlList name=$name type="CUSTOM" uuid="$uuid"><Url>dummy.com</Url></UrlList>')
TEMPLATE_LEXICAL = Template('<?xml version="1.0" encoding="UTF-8" standalone="no"?><TextualAnalysis count="$count" followedby="10" name=$name nearness="10" summary="" threshold="10" triggerOnce="false" uuid="$uuid">$phrases</TextualAnalysis>')
TEMPLATE_PHRASE = Template('<Phrase case="false" redact="false" summary="" text=$text type="custom" uuid="$uuid" weight="10"><customEntityIndexes/><qualifierIndexes/></Phrase>')
TEMPLATE_AREA = Template('<MessageArea auditorNotificationAuditor="admin" auditorNotificationAuditorAddress="" auditorNotificationEnabled="false" auditorNotificationpwdOtherAddress="" auditorNotificationPlainBody="A message was released by %RELEASEDBY% which violated the policy %POLICYVIOLATED%. A version of the email has been attached.&#10;&#10;To: %RCPTS%&#10;Subject: %SUBJECT%&#10;Date sent: %DATE%" auditorNotificationSender="admin" auditorNotificationSubject="A message which violated policy %POLICYVIOLATED% has been released." delayedReleaseDelay="15" expiry="30" name=$name notificationEnabled="false" notificationOtherAddress="" notificationPlainBody="A message you sent has been released by the administrator&#10;&#10;To: %RCPTS%&#10;Subject: %SUBJECT%&#10;Date sent: %DATE%" notificationSender="admin" notificationSubject="A message you sent has been released" notspam="true" pmm="false" releaseRate="10000" releaseScheduleType="throttle" scheduleEnabled="false" system="false" uuid="$uuid"><PMMAddressList/><WeeklySchedule mode="ONE_HOUR"><DailyScheduleList><DailySchedule day="1" mode="ONE_HOUR">000000000000000000000000</DailySchedule><DailySchedule day="2" mode="ONE_HOUR">000000000000000000000000</DailySchedule><DailySchedule day="3" mode="ONE_HOUR">000000000000000000000000</DailySchedule><DailySchedule day="4" mode="ONE_HOUR">000000000000000000000000</DailySchedule><DailySchedule day="5" mode="ONE_HOUR">000000000000000000000000</DailySchedule><DailySchedule day="6" mode="ONE_HOUR">000000000000000000000000</DailySchedule><DailySchedule day="7" mode="ONE_HOUR">000000000000000000000000</DailySchedule></DailyScheduleList></WeeklySchedule></MessageArea></DisposalCollection>')
TEMPLATE_RULE = Template('<?xml version="1.0" encoding="UTF-8" standalone="no"?><ExecutablePolicyRule name=$name siteSpecific="false" template="9255cf2d-3000-832b-406e-38bd46975444" uuid="$uuid_rule"><WhatToFind><MediaTypes selection="anyof" uuid="$uuid_media">$media_types</MediaTypes><Direction direction="either" uuid="$uuid_direction"/><ExecutableSettings uuid="$uuid_command"><Filename>$command</Filename><CmdLine>$parameters</CmdLine><ResponseList>$return_codes</ResponseList><Advanced mutex="false" timeout="$timeout"><LogFilePrefix>&gt;&gt;&gt;&gt;</LogFilePrefix><LogFilePostfix>&lt;&lt;&lt;&lt;</LogFilePostfix></Advanced></ExecutableSettings></WhatToFind><PrimaryActions><WhatToDo><Disposal disposal="$uuid_deliver" primaryCrypto="UNDEFINED" secondary="$uuid_none" secondaryCrypto="UNDEFINED" uuid="$uuid_deliver_action"/></WhatToDo><WhatToDoWeb><PrimaryWebAction editable="true" type="allow" uuid="$uuid_deliver_web"/></WhatToDoWeb><WhatElseToDo/></PrimaryActions><ModifiedActions><WhatToDo><Disposal disposal="$uuid_modified_primary" primaryCrypto="UNDEFINED" secondary="$uuid_modified_secondary" secondaryCrypto="UNDEFINED" uuid="$uuid_modified_action"/></WhatToDo><WhatToDoWeb><PrimaryWebAction editable="true" type="none" uuid="$uuid_modified_web"/></WhatToDoWeb><WhatElseToDo/></ModifiedActions><DetectedActions><WhatToDo><Disposal disposal="$uuid_detected_primary" primaryCrypto="UNDEFINED" secondary="$uuid_detected_secondary" secondaryCrypto="UNDEFINED" uuid="$uuid_detected_action"/></WhatToDo><WhatToDoWeb><PrimaryWebAction editable="true" type="none" uuid="$uuid_detected_web"/></WhatToDoWeb><WhatElseToDo/></DetectedActions></ExecutablePolicyRule>')
TEMPLATE_MEDIA = Template('<MediaType$sub_types>$uuid</MediaType>')
TEMPLATE_RETURN = Template('<Response action="$action" code="$return_code">$description</Response>')
TEMPLATE_PARAMETER = Template("# $name\n# type: $type\n# description: $description\n\n$name = $value")

CS_USER = "tomcat"
CS_GROUP = "cs-adm"

KEY_PACKAGES = "packages"
KEY_MODULES = "modules"
KEY_LIST_ADDRESS = "list_address"
KEY_LIST_FILENAME = "list_filename"
KEY_LIST_URL = "list_url"
KEY_LIST_LEXICAL = "list_lexical"
KEY_PARAMETERS = "parameters"
KEY_TIMEOUT = "timeout"
KEY_MEDIA_TYPES = "media_types"
KEY_RETURN_CODES = "return_codes"
KEY_ACTION = "action"
KEY_DESCRIPTION = "description"
KEY_DISPOSAL_ACTIONS = "disposal_actions"
KEY_MODIFIED = "modified"
KEY_DETECTED = "detected"
KEY_PRIMARY = "primary"
KEY_SECONDARY = "secondary"
KEY_CONFIG = "config"

SUBTYPE_ENCRYPTED = "encrypted"
SUBTYPE_SIGNED = "signed"
SUBTYPE_SIGNED_ENCRYPTED = "signed_encrypted"
SUBTYPE_DRM = "drm"
SUBTYPE_NOT_PROTECTED = "not_protected"

ACTION_NONE = "NONE"
ACTION_DETECTED = "DETECTED"
ACTION_MODIFIED = "MODIFIED"
ACTION_ERROR = "NOT_CHECKED"

ACTIONS = { ACTION_NONE, ACTION_DETECTED, ACTION_MODIFIED, ACTION_ERROR }

DISPOSAL_NONE = "none"
DISPOSAL_DELIVER = "deliver"
DISPOSAL_REJECT = "reject"
DISPOSAL_DROP = "drop"
DISPOSAL_NDR = "ndr"
DISPOSAL_TAG = "tag"

DICT_DISPOSAL = {
    "None": DISPOSAL_NONE,
    "Deliver": DISPOSAL_DELIVER,
    "Reject": DISPOSAL_REJECT,
    "Drop": DISPOSAL_DROP,
    "NDR": DISPOSAL_NDR,
    "TagAndDeliver": DISPOSAL_TAG
}

PARAMETERS_NO_CONFIG = "%FILENAME% %LOGNAME%"
PARAMETERS_CONFIG = '%FILENAME% %LOGNAME% "Config - {}"'
TIMEOUT = 60

PARAMETER_TYPE = "type"
PARAMETER_DESCRIPTION = "description"
PARAMETER_VALUE = "value"

TupleMediaType = namedtuple("TupleMediaType", "uuid sub_types")
TupleResult = namedtuple("TupleResult", "action description")
TupleAction = namedtuple("TupleAction", "primary secondary")
TupleDisposalAction = namedtuple("TupleDisposalAction", "detected modified")
TupleParameter = namedtuple("TupleParameter", "type description value")
TupleRule = namedtuple("TupleRule", "packages modules list_address list_filename list_url list_lexical parameters timeout media_types return_codes disposal_actions config")

@enum.unique
class ReturnCode(enum.IntEnum):
    """
    Return code.

    0 - ok
    1 - error
    """
    OK = 0
    ERROR = 1

@enum.unique
class MediaSubtype(enum.IntEnum):
    """
    Media sub-type.

    0 - encrypted
    1 - signed
    2 - signed and encrypted
    3 - DRM protected
    4 - not protected
    """
    ENCRYPTED = 0
    SIGNED = 1
    SIGNED_ENCRYPTED = 2
    DRM = 3
    NOT_PROTECTED = 4

MEDIA_SUBTYPE = {
    SUBTYPE_ENCRYPTED: MediaSubtype.ENCRYPTED,
    SUBTYPE_SIGNED: MediaSubtype.SIGNED,
    SUBTYPE_SIGNED_ENCRYPTED: MediaSubtype.SIGNED_ENCRYPTED,
    SUBTYPE_DRM: MediaSubtype.DRM,
    SUBTYPE_NOT_PROTECTED: MediaSubtype.NOT_PROTECTED
}

class SAXExceptionFinished(SAXException):
    """
    Custom SAXException for stopping parsing after all info has been read.
    """
    def __init__(self):
        super().__init__("Stop parsing")

class HandlerName(handler.ContentHandler):
    """
    Custom content handler for xml.sax for extracting name attribute for defined tag.
    """
    def __init__(self, tag):
        """
        :type tag: str
        """
        self.tag = tag
        self.name = None

        super().__init__()

    def startElement(self, name, attrs):
        if name == self.tag and "name" in attrs:
            self.name = attrs["name"]

            raise SAXExceptionFinished

    def getName(self):
        """
        Return name.

        :rtype: str
        """
        return self.name

class HandlerMediaTypes(handler.ContentHandler):
    """
    Custom content handler for xml.sax for extracting media types.
    """
    def __init__(self):
        self.dict_media_type = dict()
        self.found = False

        super().__init__()

    def startElement(self, name, attrs):
        if self.found and name == "MediaType" and "mnemonic" in attrs and "uuid" in attrs:
            mnemonic = attrs["mnemonic"]

            if mnemonic in self.dict_media_type:
                raise SAXException("Duplicate media type mnemonic '{}'".format(mnemonic))

            self.dict_media_type[mnemonic] = TupleMediaType(attrs["uuid"], set())

            if "encrypted" in attrs:
                self.dict_media_type[mnemonic].sub_types.add(MediaSubtype.ENCRYPTED)

            if "signed" in attrs:
                self.dict_media_type[mnemonic].sub_types.add(MediaSubtype.SIGNED)

            if "signedAndEncrypted" in attrs:
                self.dict_media_type[mnemonic].sub_types.add(MediaSubtype.SIGNED_ENCRYPTED)

            if "drm" in attrs:
                self.dict_media_type[mnemonic].sub_types.add(MediaSubtype.DRM)

            if "notProtected" in attrs:
                self.dict_media_type[mnemonic].sub_types.add(MediaSubtype.NOT_PROTECTED)
        elif name == "MediaTypes":
            self.found = True

    def endElement(self, name):
        if self.found and name == "MediaTypes":
            raise SAXExceptionFinished

    def getMediaTypes(self):
        """
        Return dict of media types.

        :rtype: dict
        """
        return self.dict_media_type

class HandlerDisposalActions(handler.ContentHandler):
    """
    Custom content handler for xml.sax for extracting disposal actions.
    """
    def __init__(self):
        self.dict_disposal_action = dict()
        self.found = False

        super().__init__()

    def startElement(self, name, attrs):
        if self.found:
            if name == "MessageArea" and "name" in attrs and "uuid" in attrs:
                name_area = attrs["name"]
                disposal = "hold:{}".format(name_area)

                if disposal in self.dict_disposal_action:
                    raise SAXException("Duplicate message area '{}'".format(name_area))

                self.dict_disposal_action[disposal] = attrs["uuid"]
            elif name in DICT_DISPOSAL and "uuid" in attrs:
                disposal = DICT_DISPOSAL[name]

                if disposal in self.dict_disposal_action:
                    raise SAXException("Duplicate disposal action '{}'".format(disposal))

                self.dict_disposal_action[disposal] = attrs["uuid"]
        elif name == "DisposalCollection":
            self.found = True

    def endElement(self, name):
        if self.found and name == "DisposalCollection":
            raise SAXExceptionFinished

    def getDisposalActions(self):
        """
        Return dict of disposal actions.

        :rtype: dict
        """
        return self.dict_disposal_action

def eprint(*args, **kwargs):
    """
    Print to stderr.
    """
    print(*args, file=sys.stderr, **kwargs)

def get_commands():
    """
    Download readme file from repo and extract external command info.

    :rtype: dict
    """
    try:
        readme = urlopen(URL_README).read().decode("utf-8")
    except Exception:
        raise Exception("Cannot download readme file '{}'".format(URL_README))

    list_readme = readme.split("\n")

    dict_command = dict()

    found = False

    for line in list_readme:
        if line == "## External commands":
            found = True
        elif found:
            if not line:
                break

            split_line = line[2:].split(": ")

            if len(split_line) != 2:
                raise Exception("Invalid external command line in readme")

            command = split_line[0]

            if command in dict_command:
                raise Exception("Duplicate command '{}'".format(command))

            dict_command[command] = split_line[1]

    return dict_command

def get_names(directory, tag):
    """
    Get names of Clearswift item lists.

    :type directory: Path
    :type tag: str
    :rtype: set
    """
    handler = HandlerName(tag)

    parser = make_parser()
    parser.setContentHandler(handler)

    set_names = set()

    for entry in directory.iterdir():
        if entry.is_file() and entry.suffix == ".xml":
            try:
                parser.parse(str(entry))
            except SAXExceptionFinished:
                pass

            name = handler.getName()

            if name is not None:
                set_names.add(name)

    return set_names

def get_media_types():
    """
    Get Clearswift media type info.

    :rtype: dict
    """
    handler = HandlerMediaTypes()

    parser = make_parser()
    parser.setContentHandler(handler)

    try:
        parser.parse(str(FILE_MEDIATYPES))
    except SAXExceptionFinished:
        pass

    return handler.getMediaTypes()

def get_disposal_actions():
    """
    Get Clearswift disposal actions info.

    :rtype: dict
    """
    handler = HandlerDisposalActions()

    parser = make_parser()
    parser.setContentHandler(handler)

    try:
        parser.parse(str(FILE_DISPOSAL))
    except SAXExceptionFinished:
        pass

    return handler.getDisposalActions()

def create_lists(set_name, template, directory, tag):
    """
    Create Clearswift item list.

    :type set_name: set
    :type template: Template
    :type directory: Path
    :type tag: str
    """
    for name in set_name - get_names(directory, tag):
        while True:
            uuid = generate_uuid()
            file_list = directory.joinpath("{}.xml".format(uuid))

            if not file_list.exists():
                break

        try:
            with open(file_list, "w") as f:
                f.write(template.substitute(name=quoteattr(name), uuid=uuid))

            chown(file_list, user=CS_USER, group=CS_GROUP)
        except Exception:
            raise Exception("Cannot write list file '{}'".format(file_list))

def create_lexical_lists(set_name):
    """
    Create Clearswift lexical expression list.

    :type set_name: set
    """
    for name in set_name - get_names(DIR_LEXICAL, "TextualAnalysis"):
        while True:
            uuid = generate_uuid()
            file_lexical = DIR_LEXICAL.joinpath("{}.xml".format(uuid))

            if not file_lexical.exists():
                break

        try:
            with open(file_lexical, "w") as f:
                f.write(TEMPLATE_LEXICAL.substitute(count="1", name=quoteattr(name), uuid=uuid, phrases=TEMPLATE_PHRASE.substitute(text=quoteattr("dummy"), uuid=generate_uuid())))

            chown(file_lexical, user=CS_USER, group=CS_GROUP)
        except Exception:
            raise Exception("Cannot write lexical list file '{}'".format(file_lexical))

def list2set(list_in):
    """
    Create set from list and check for duplicate items.

    :type list_in: list
    :rtype: set
    """
    if list_in is None:
        return None

    set_out = set(list_in)

    if len(set_out) < len(list_in):
        raise Exception("Duplicate list items {}".format(str({ item for (item, count) in Counter(list_in).items() if count > 1 })[1:-1]))

    return set_out

def parse_config(str_config):
    """
    Parse external command config.

    :type str_config: str
    :rtype: dict
    """
    try:
        dict_config = json.loads(str_config)
    except Exception:
        raise Exception("Config not valid JSON format")

    config_command = dict()

    for (name, rule) in dict_config.items():
        if name in config_command:
            raise Exception("Duplicate rule name '{}'".format(name))

        if KEY_MEDIA_TYPES in rule:
            media_types = dict()

            for (mnemonic, list_subtype) in rule[KEY_MEDIA_TYPES].items():
                if mnemonic in media_types:
                    raise Exception("Duplicate media type '{}'".format(mnemonic))

                if list_subtype is None:
                    raise Exception("Media type '{}' missing sub-types".format(mnemonic))

                set_subtype = list2set(list_subtype)

                invalid_subtype = set_subtype - MEDIA_SUBTYPE.keys()

                if invalid_subtype:
                    raise Exception("Invalid media sub-types '{}'".format(invalid_subtype))

                media_types[mnemonic] = { MEDIA_SUBTYPE[sub_type] for sub_type in set_subtype }
        else:
            raise Exception("Media types missing from config")

        if KEY_RETURN_CODES in rule:
            return_codes = dict()

            for (return_code, result) in rule[KEY_RETURN_CODES].items():
                try:
                    return_code = int(return_code)
                except Exception:
                    raise Exception("Non-integer return code '{}'".format(return_code))

                if return_code in return_codes:
                    raise Exception("Duplicate return code '{}'".format(return_code))

                if not KEY_ACTION in result:
                    raise Exception("Return code '{}' missing action".format(return_code))

                if not KEY_DESCRIPTION in result:
                    raise Exception("Return code '{}' missing description".format(return_code))

                action = result[KEY_ACTION]

                if action not in ACTIONS:
                    raise Exception("Return code '{}' has invalid action '{}'".format(return_code, action))

                return_codes[return_code] = TupleResult(action=action, description=result[KEY_DESCRIPTION])
        else:
            raise Exception("Return codes missing from config")

        if KEY_DISPOSAL_ACTIONS in rule:
            disposal_actions = DICT_DISPOSAL.values()

            if KEY_MODIFIED in rule[KEY_DISPOSAL_ACTIONS]:
                modified = rule[KEY_DISPOSAL_ACTIONS][KEY_MODIFIED]

                primary = modified.get(KEY_PRIMARY)

                if primary is None:
                    primary = DISPOSAL_NONE
                elif primary not in disposal_actions and not primary.startswith("hold:"):
                    raise Exception("Modified disposal has invalid primary action '{}'".format(primary))

                secondary = modified.get(KEY_SECONDARY)

                if secondary is None:
                    secondary = DISPOSAL_NONE
                elif secondary not in disposal_actions and not secondary.startswith("hold:"):
                    raise Exception("Modified disposal has invalid secondary action '{}'".format(secondary))

                modified = TupleAction(primary=primary, secondary=secondary)
            else:
                modified = TupleAction(primary=DISPOSAL_NONE, secondary=DISPOSAL_NONE)

            if KEY_DETECTED in rule[KEY_DISPOSAL_ACTIONS]:
                detected = rule[KEY_DISPOSAL_ACTIONS][KEY_DETECTED]

                primary = detected.get(KEY_PRIMARY)

                if primary is None:
                    primary = DISPOSAL_NONE
                elif primary not in disposal_actions and not primary.startswith("hold:"):
                    raise Exception("Detected disposal has invalid primary action '{}'".format(primary))

                secondary = detected.get(KEY_SECONDARY)

                if secondary is None:
                    secondary = DISPOSAL_NONE
                elif secondary not in disposal_actions and not secondary.startswith("hold:"):
                    raise Exception("Detected disposal has invalid secondary action '{}'".format(secondary))

                detected = TupleAction(primary=primary, secondary=secondary)
            else:
                detected = TupleAction(primary=DISPOSAL_NONE, secondary=DISPOSAL_NONE)

            disposal_actions = TupleDisposalAction(modified=modified, detected=detected)
        else:
            disposal_actions = TupleDisposalAction(modified=TupleAction(primary=DISPOSAL_NONE, secondary=DISPOSAL_NONE) , detected=TupleAction(primary=DISPOSAL_NONE, secondary=DISPOSAL_NONE))

        if KEY_CONFIG in rule:
            config = dict()

            for (key, parameter) in rule[KEY_CONFIG].items():
                if key in config:
                    raise Exception("Duplicate parameter '{}'".format(key))

                if not PARAMETER_TYPE in parameter:
                    raise Exception("Parameter '{}' missing type".format(key))

                if not PARAMETER_DESCRIPTION in parameter:
                    raise Exception("Parameter '{}' missing description".format(key))

                if not PARAMETER_VALUE in parameter:
                    raise Exception("Parameter '{}' missing value".format(key))

                config[key] = TupleParameter(type=parameter[PARAMETER_TYPE], description=parameter[PARAMETER_DESCRIPTION], value=parameter[PARAMETER_VALUE])
        else:
            config = None

        config_command[name] = TupleRule(
            packages=list2set(rule.get(KEY_PACKAGES)),
            modules=list2set(rule.get(KEY_MODULES)),
            list_address=list2set(rule.get(KEY_LIST_ADDRESS)),
            list_filename=list2set(rule.get(KEY_LIST_FILENAME)),
            list_url=list2set(rule.get(KEY_LIST_URL)),
            list_lexical=list2set(rule.get(KEY_LIST_LEXICAL)),
            parameters=rule.get(KEY_PARAMETERS, PARAMETERS_CONFIG.format(name) if KEY_CONFIG in rule else PARAMETERS_NO_CONFIG),
            timeout=rule.get(KEY_TIMEOUT, TIMEOUT),
            media_types=media_types,
            return_codes=return_codes,
            disposal_actions=disposal_actions,
            config=config
        )

    return config_command

def download_script(command):
    """
    Download external command script.

    :type command: str
    """
    file_script = DIR_SCRIPTS.joinpath("{}.py".format(command))

    url_script = "{}/{}/{}.py".format(URL_REPO, command, command)

    try:
        urlretrieve(url_script, file_script)
    except Exception:
        raise Exception("Cannot download script '{}'".format(url_script))

    chmod(file_script, 0o755)

def command_list(_, command_description):
    """
    List available external commands.

    :type command_description: dict
    """
    for command in sorted(command_description.keys()):
        print("{}\t\t{}".format(command, command_description[command]))

def command_info(args, _):
    """
    Print information about external commands.

    :type args: argparse.Namespace
    """
    for command in args.command:
        url_readme = "{}/{}/{}".format(URL_REPO, command, FILE_README)

        try:
            readme = urlopen(url_readme).read().decode("utf-8")
        except Exception:
            raise Exception("Cannot download readme file '{}'".format(url_readme))

        print(readme)

def command_install(args, command_description):
    """
    Install external commands.

    :type args: argparse.Namespace
    :type command_description: dict
    """
    dict_media_type = get_media_types()

    dict_disposal_action = get_disposal_actions()

    command_update(args, command_description)

    for command in args.command:
        url_config = "{}/{}/{}".format(URL_REPO, command, FILE_CONFIG)

        try:
            config = urlopen(url_config).read().decode("utf-8")
        except Exception:
            raise Exception("Cannot download config file '{}'".format(url_config))

        config = parse_config(config)

        set_rule = get_names(DIR_RULES, "ExecutablePolicyRule")

        duplicate_rules = config.keys() & set_rule

        if duplicate_rules:
            raise Exception("Policy rules {} already exist".format(str(duplicate_rules)[1:-1]))

        download_script(command)

        for (name, rule) in config.items():
            if rule.packages:
                for package in rule.packages:
                    try:
                        run([ "/usr/bin/yum", "install", "-y", package ], stdout=DEVNULL, stderr=DEVNULL, check=True)
                    except Exception:
                        raise Exception("Cannot install package '{}'".format(package))

            if rule.modules:
                for module in rule.modules:
                    try:
                        run([ sys.executable, "-m", "pip", "install" , module ], stdout=DEVNULL, stderr=DEVNULL, check=True)
                    except Exception:
                        raise Exception("Cannot install Python module '{}'".format(module))

            for disposal_action in rule.disposal_actions:
                for action in disposal_action:
                    if not action in dict_disposal_action:
                        while True:
                            uuid = generate_uuid()

                            if uuid not in dict_disposal_action.values():
                                break

                        try:
                            with open(FILE_DISPOSAL, "r+b") as f:
                                f.seek(-21, SEEK_END)

                                f.write(TEMPLATE_AREA.substitute(name=quoteattr(action[5:]), uuid=uuid).encode("utf-8"))
                        except Exception:
                            raise Exception("Cannot write disposal actions file '{}'".format(FILE_DISPOSAL))

                        dict_disposal_action[action] = uuid

            if rule.list_address:
                create_lists(rule.list_address, TEMPLATE_ADDRESS, DIR_ADDRESS, "AddressList")

            if rule.list_filename:
                create_lists(rule.list_filename, TEMPLATE_FILENAME, DIR_FILENAME, "FilenameList")

            if rule.list_url:
                create_lists(rule.list_url, TEMPLATE_URL, DIR_URL, "UrlList")

            if rule.list_lexical:
                create_lexical_lists(rule.list_lexical)

            if rule.config:
                while True:
                    uuid = generate_uuid()
                    file_lexical = DIR_LEXICAL.joinpath("{}.xml".format(uuid))

                    if not file_lexical.exists():
                        break

                try:
                    with open(file_lexical, "w") as f:
                        f.write(TEMPLATE_LEXICAL.substitute(
                            count=str(len(rule.config)),
                            name=quoteattr("Config - {}".format(name)),
                            uuid=uuid,
                            phrases="".join([ TEMPLATE_PHRASE.substitute(
                                text=quoteattr(TEMPLATE_PARAMETER.substitute(
                                    name=parameter,
                                    type=rule.config[parameter].type,
                                    description=rule.config[parameter].description,
                                    value=rule.config[parameter].value)),
                                uuid=generate_uuid()
                            ) for parameter in sorted(rule.config.keys()) ])
                        ))

                    chown(file_lexical, user=CS_USER, group=CS_GROUP)
                except Exception:
                    raise Exception("Cannot write config lexical list file '{}'".format(file_lexical))

            while True:
                uuid = generate_uuid()
                file_rule = DIR_RULES.joinpath("{}.xml".format(uuid))

                if not file_rule.exists():
                    break

            try:
                with open(file_rule, "w") as f:
                    f.write(TEMPLATE_RULE.substitute(
                        name=quoteattr(name),
                        uuid_rule=uuid,
                        media_types="".join([ TEMPLATE_MEDIA.substitute(
                            uuid=dict_media_type[mnemonic].uuid,
                            sub_types="{}{}{}{}{}".format(' enc="true"' if MediaSubtype.ENCRYPTED in dict_media_type[mnemonic].sub_types and MediaSubtype.ENCRYPTED in sub_types else "", ' digsign="true"' if MediaSubtype.SIGNED in dict_media_type[mnemonic].sub_types and MediaSubtype.SIGNED in sub_types else "", ' digsignenc="true"' if MediaSubtype.SIGNED_ENCRYPTED in dict_media_type[mnemonic].sub_types and MediaSubtype.SIGNED_ENCRYPTED in sub_types else "", ' drm="true"' if MediaSubtype.DRM in dict_media_type[mnemonic].sub_types and MediaSubtype.DRM in sub_types else "", ' notprotect="true"' if MediaSubtype.NOT_PROTECTED in dict_media_type[mnemonic].sub_types and MediaSubtype.NOT_PROTECTED in sub_types else "")
                        ) for (mnemonic, sub_types) in rule.media_types.items() ]),
                        uuid_media=generate_uuid(),
                        uuid_direction=generate_uuid(),
                        uuid_command=generate_uuid(),
                        command=DIR_SCRIPTS.joinpath("{}.py".format(command)),
                        parameters=escape(rule.parameters),
                        return_codes="".join([ TEMPLATE_RETURN.substitute(
                            action=result.action,
                            return_code=return_code,
                            description=result.description
                        ) for (return_code, result) in rule.return_codes.items() ]),
                        timeout=rule.timeout,
                        uuid_deliver=dict_disposal_action["deliver"],
                        uuid_none=dict_disposal_action["none"],
                        uuid_deliver_action=generate_uuid(),
                        uuid_deliver_web=generate_uuid(),
                        uuid_modified_primary=dict_disposal_action[rule.disposal_actions.modified.primary],
                        uuid_modified_secondary=dict_disposal_action[rule.disposal_actions.modified.secondary],
                        uuid_modified_action=generate_uuid(),
                        uuid_modified_web=generate_uuid(),
                        uuid_detected_primary=dict_disposal_action[rule.disposal_actions.detected.primary],
                        uuid_detected_secondary=dict_disposal_action[rule.disposal_actions.detected.secondary],
                        uuid_detected_action=generate_uuid(),
                        uuid_detected_web=generate_uuid()
                    ))

                chown(file_rule, user=CS_USER, group=CS_GROUP)
            except Exception:
                raise Exception("Cannot write policy rule file '{}'".format(file_rule))

    try:
        with open(FILE_STATUS, "r") as f:
            content = f.read()
    except Exception:
        raise Exception("Cannot read status file '{}'".format(FILE_STATUS))

    try:
        with open(FILE_STATUS, "w") as f:
            f.write(content.replace(' changesMade="false" ', ' changesMade="true" '))
    except Exception:
        raise Exception("Cannot write status file '{}'".format(FILE_STATUS))

    if args.reload:
        try:
            run("source /etc/profile.d/cs-vars.sh; /opt/cs-gateway/bin/cs-servicecontrol restart tomcat", shell=True, stdout=DEVNULL, stderr=DEVNULL, check=True)
        except Exception:
            raise Exception("Cannot restart Tomcat service")

def command_update(_, command_description):
    """
    Update installed external commands.

    :type command_description: dict
    """
    for module in MODULES_LIBRARY:
        try:
            run([ sys.executable, "-m", "pip", "install" , module ], stdout=DEVNULL, stderr=DEVNULL, check=True)
        except Exception:
            raise Exception("Cannot install Python module '{}'".format(module))

    try:
        urlretrieve(URL_LIBRARY, FILE_LIBRARY)
    except Exception:
        raise Exception("Cannot download library '{}'".format(URL_LIBRARY))

    for command in command_description.keys():
        if DIR_SCRIPTS.joinpath("{}.py".format(command)).exists():
            download_script(command)

def main(args):
    command_description = get_commands()

    if hasattr(args, "command"):
        args.command = set(args.command)

        invalid_commands = args.command - command_description.keys()

        if invalid_commands:
            eprint("Invalid external commands {}".format(str(invalid_commands)[1:-1]))

            return ReturnCode.ERROR

    try:
        args.action(args, command_description)
    except Exception as ex:
        eprint(ex)

        return ReturnCode.ERROR

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.set_defaults(action=parser.print_help)
    subparsers = parser.add_subparsers()

    parser_list = subparsers.add_parser("list", help="list available external commands")
    parser_list.set_defaults(action=command_list)

    parser_info = subparsers.add_parser("info", help="print information about external commands")
    parser_info.set_defaults(action=command_info)
    parser_info.add_argument("command", metavar="COMMAND", type=str, nargs="+", help="one or more external commands")

    parser_install = subparsers.add_parser("install", help="install external commands")
    parser_install.set_defaults(action=command_install)
    parser_install.add_argument("command", metavar="COMMAND", type=str, nargs="+", help="one or more external commands")
    parser_install.add_argument("-r", "--reload", action="store_true", help="reload Clearswift web interface")

    parser_update = subparsers.add_parser("update", help="update all installed external commands to latest version")
    parser_update.set_defaults(action=command_update)

    args = parser.parse_args()

    if not args.action in { command_list, command_info, command_install, command_update }:
        args.action()

        sys.exit(ReturnCode.OK)

    sys.exit(main(args))
