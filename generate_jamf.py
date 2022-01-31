#!/usr/bin/env python3
# filename: generate_guidance.py
# description: Process a given baseline, and output guidance files
import types
import sys
import os.path
import plistlib
import io
import glob
import os
import yaml
import re
import argparse
import subprocess
import logging
import tempfile
from string import Template
from itertools import groupby
from uuid import uuid4
from collections import namedtuple
from xml.sax.saxutils import escape



class MacSecurityRule():
    def __init__(self, title, rule_id, severity, discussion, check, fix, cci, cce, nist_controls, nist_171, disa_stig, srg, cisv8, custom_refs, tags, result_value, mobileconfig, mobileconfig_info, customized):
        self.rule_title = title
        self.rule_id = rule_id
        self.rule_severity = severity
        self.rule_discussion = discussion
        self.rule_check = check
        self.rule_fix = fix
        self.rule_cci = cci
        self.rule_cce = cce
        self.rule_80053r5 = nist_controls
        self.rule_800171 = nist_171
        self.rule_disa_stig = disa_stig
        self.rule_srg = srg
        self.rule_cisv8 = cisv8
        self.rule_custom_refs = custom_refs
        self.rule_result_value = result_value
        self.rule_tags = tags
        self.rule_mobileconfig = mobileconfig
        self.rule_mobileconfig_info = mobileconfig_info
        self.rule_customized = customized

    def create_asciidoc(self, adoc_rule_template):
        """Pass an AsciiDoc template as file object to return formatted AsciiDOC"""
        rule_adoc = ""
        rule_adoc = adoc_rule_template.substitute(
            rule_title=self.rule_title,
            rule_id=self.rule_id,
            rule_severity=self.rule_severity,
            rule_discussion=self.rule_discussion,
            rule_check=self.rule_check,
            rule_fix=self.rule_fix,
            rule_cci=self.rule_cci,
            rule_80053r5=self.rule_80053r5,
            rule_disa_stig=self.rule_disa_stig,
            rule_cisv8=self.rule_cisv8,
            rule_srg=self.rule_srg,
            rule_result=self.rule_result_value
        )
        return rule_adoc

    def create_mobileconfig(self):
        pass

    # Convert a list to AsciiDoc
def ulify(elements):
    string = "\n"
    for s in elements:
        string += "* " + str(s) + "\n"
    return string

def group_ulify(elements):
    string = "\n * "
    for s in elements:
        string += str(s) + ", "
    return string[:-2]


def group_ulify_comment(elements):
    string = "\n * "
    for s in elements:
        string += str(s) + ", "
    return string[:-2]


def get_check_code(check_yaml):
    try:
        check_string = check_yaml.split("[source,bash]")[1]
    except:
        return check_yaml
    #print check_string
    check_code = re.search('(?:----((?:.*?\r?\n?)*)----)+', check_string)
    #print(check_code.group(1).rstrip())
    return(check_code.group(1).strip())


def quotify(fix_code):
    string = fix_code.replace("'", "\'\"\'\"\'")
    string = string.replace("%", "%%")

    return string


def get_fix_code(fix_yaml):
    fix_string = fix_yaml.split("[source,bash]")[1]
    fix_code = re.search('(?:----((?:.*?\r?\n?)*)----)+', fix_string)
    return(fix_code.group(1))


def format_mobileconfig_fix(mobileconfig):
    """Takes a list of domains and setting from a mobileconfig, and reformats it for the output of the fix section of the guide.
    """
    rulefix = ""
    for domain, settings in mobileconfig.items():
        if domain == "com.apple.ManagedClient.preferences":
            rulefix = rulefix + \
                (f"NOTE: The following settings are in the ({domain}) payload. This payload requires the additional settings to be sub-payloads within, containing their their defined payload types.\n\n")
            rulefix = rulefix + format_mobileconfig_fix(settings)

        else:
            rulefix = rulefix + (
                f"Create a configuration profile containing the following keys in the ({domain}) payload type:\n\n")
            rulefix = rulefix + "[source,xml]\n----\n"
            for item in settings.items():
                rulefix = rulefix + (f"<key>{item[0]}</key>\n")

                if type(item[1]) == bool:
                    rulefix = rulefix + \
                        (f"<{str(item[1]).lower()}/>\n")
                elif type(item[1]) == list:
                    rulefix = rulefix + "<array>\n"
                    for setting in item[1]:
                        rulefix = rulefix + \
                            (f"    <string>{setting}</string>\n")
                    rulefix = rulefix + "</array>\n"
                elif type(item[1]) == int:
                    rulefix = rulefix + \
                        (f"<integer>{item[1]}</integer>\n")
                elif type(item[1]) == str:
                    rulefix = rulefix + \
                        (f"<string>{item[1]}</string>\n")

            rulefix = rulefix + "----\n\n"

    return rulefix

class AdocTemplate:
    def __init__(self, name, path, template_file):
        self.name = name
        self.path = path
        self.template_file = template_file

class PayloadDict:
    """Class to create and manipulate Configuration Profiles.
    The actual plist content can be accessed as a dictionary via the 'data' attribute.
    """

    def __init__(self, identifier, uuid=False, removal_allowed=False, description='', organization='', displayname=''):
        self.data = {}
        self.data['PayloadVersion'] = 1
        self.data['PayloadOrganization'] = organization
        if uuid:
            self.data['PayloadUUID'] = uuid
        else:
            self.data['PayloadUUID'] = makeNewUUID()
        if removal_allowed:
            self.data['PayloadRemovalDisallowed'] = False
        else:
            self.data['PayloadRemovalDisallowed'] = True
        self.data['PayloadType'] = 'Configuration'
        self.data['PayloadScope'] = 'System'
        self.data['PayloadDescription'] = description
        self.data['PayloadDisplayName'] = displayname
        self.data['PayloadIdentifier'] = identifier
        self.data['ConsentText'] = {"default": "THE SOFTWARE IS PROVIDED 'AS IS' WITHOUT ANY WARRANTY OF ANY KIND, EITHER EXPRESSED, IMPLIED, OR STATUTORY, INCLUDING, BUT NOT LIMITED TO, ANY WARRANTY THAT THE SOFTWARE WILL CONFORM TO SPECIFICATIONS, ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND FREEDOM FROM INFRINGEMENT, AND ANY WARRANTY THAT THE DOCUMENTATION WILL CONFORM TO THE SOFTWARE, OR ANY WARRANTY THAT THE SOFTWARE WILL BE ERROR FREE.  IN NO EVENT SHALL NIST BE LIABLE FOR ANY DAMAGES, INCLUDING, BUT NOT LIMITED TO, DIRECT, INDIRECT, SPECIAL OR CONSEQUENTIAL DAMAGES, ARISING OUT OF, RESULTING FROM, OR IN ANY WAY CONNECTED WITH THIS SOFTWARE, WHETHER OR NOT BASED UPON WARRANTY, CONTRACT, TORT, OR OTHERWISE, WHETHER OR NOT INJURY WAS SUSTAINED BY PERSONS OR PROPERTY OR OTHERWISE, AND WHETHER OR NOT LOSS WAS SUSTAINED FROM, OR AROSE OUT OF THE RESULTS OF, OR USE OF, THE SOFTWARE OR SERVICES PROVIDED HEREUNDER."}

        # An empty list for 'sub payloads' that we'll fill later
        self.data['PayloadContent'] = []

    def _updatePayload(self, payload_content_dict, baseline_name):
        """Update the profile with the payload settings. Takes the settings dictionary which will be the
        PayloadContent dict within the payload. Handles the boilerplate, naming and descriptive
        elements.
        """
        #description = "Configuration settings for the {} preference domain.".format(payload_type)
        payload_dict = {}

        # Boilerplate
        payload_dict['PayloadVersion'] = 1
        payload_dict['PayloadUUID'] = makeNewUUID()
        payload_dict['PayloadEnabled'] = True
        payload_dict['PayloadType'] = payload_content_dict['PayloadType']
        payload_dict['PayloadIdentifier'] = f"alacarte.macOS.{baseline_name}.{payload_dict['PayloadUUID']}"

        payload_dict['PayloadContent'] = payload_content_dict
        # Add the payload to the profile
        self.data.update(payload_dict)

    def _addPayload(self, payload_content_dict, baseline_name):
        """Add a payload to the profile. Takes the settings dictionary which will be the
        PayloadContent dict within the payload. Handles the boilerplate, naming and descriptive
        elements.
        """
        #description = "Configuration settings for the {} preference domain.".format(payload_type)
        payload_dict = {}

        # Boilerplate
        payload_dict['PayloadVersion'] = 1
        payload_dict['PayloadUUID'] = makeNewUUID()
        payload_dict['PayloadEnabled'] = True
        payload_dict['PayloadType'] = payload_content_dict['PayloadType']
        payload_dict['PayloadIdentifier'] = f"alacarte.macOS.{baseline_name}.{payload_dict['PayloadUUID']}"

        payload_dict['PayloadContent'] = payload_content_dict
        # Add the payload to the profile
        #print payload_dict
        del payload_dict['PayloadContent']['PayloadType']
        self.data['PayloadContent'].append(payload_dict)

    def addNewPayload(self, payload_type, settings, baseline_name):
        """Add a payload to the profile. Takes the settings dictionary which will be the
        PayloadContent dict within the payload. Handles the boilerplate, naming and descriptive
        elements.
        """
        #description = "Configuration settings for the {} preference domain.".format(payload_type)
        payload_dict = {}

        # Boilerplate
        payload_dict['PayloadVersion'] = 1
        payload_dict['PayloadUUID'] = makeNewUUID()
        payload_dict['PayloadEnabled'] = True
        payload_dict['PayloadType'] = payload_type
        payload_dict['PayloadIdentifier'] = f"alacarte.macOS.{baseline_name}.{payload_dict['PayloadUUID']}"

        # Add the settings to the payload
        for setting in settings:
            for k, v in setting.items():
                payload_dict[k] = v

        # Add the payload to the profile
        #
        self.data['PayloadContent'].append(payload_dict)

    def addMCXPayload(self, settings, baseline_name):
        """Add a payload to the profile. Takes the settings dictionary which will be the
        PayloadContent dict within the payload. Handles the boilerplate, naming and descriptive
        elements.
        """
        keys = settings[1]
        plist_dict = {}
        for key in keys.split():
            plist_dict[key] = settings[2]

        #description = "Configuration settings for the {} preference domain.".format(payload_type)
        payload_dict = {}

        state = "Forced"
        domain = settings[0]

        # Boilerplate
        payload_dict[domain] = {}
        payload_dict[domain][state] = []
        payload_dict[domain][state].append({})
        payload_dict[domain][state][0]['mcx_preference_settings'] = plist_dict
        payload_dict['PayloadType'] = "com.apple.ManagedClient.preferences"

        self._addPayload(payload_dict, baseline_name)

    def finalizeAndSave(self, output_path):
        """Perform last modifications and save to configuration profile.
        """
        plistlib.dump(self.data, output_path)
        print(f"Configuration profile written to {output_path.name}")

    def finalizeAndSavePlist(self, output_path):
        """Perform last modifications and save to an output plist.
        """
        output_file_path = output_path.name
        preferences_path = os.path.dirname(output_file_path)
        

        settings_dict = {}
        for i in self.data['PayloadContent']:
            if i['PayloadType'] == "com.apple.ManagedClient.preferences":
                for key, value in i['PayloadContent'].items():
                    domain=key
                    preferences_output_file = os.path.join(preferences_path, domain + ".plist")
                    if not os.path.exists(preferences_output_file):
                        with open(preferences_output_file, 'w'): pass
                    with open (preferences_output_file, 'rb') as fp:
                        try:
                            settings_dict = plistlib.load(fp)
                        except:
                            settings_dict = {}
                    with open(preferences_output_file, 'wb') as fp:
                        for setting in value['Forced']:
                            for key, value in setting['mcx_preference_settings'].items():
                                settings_dict[key] = value
                    
                        #preferences_output_path = open(preferences_output_file, 'wb')
                        plistlib.dump(settings_dict, fp)
                        print(f"Settings plist written to {preferences_output_file}")
                    settings_dict.clear()
                    try:
                        os.unlink(output_file_path)
                    except:
                        continue
            else:
                if os.path.exists(output_file_path):
                    with open (output_file_path, 'rb') as fp:
                        try:
                            settings_dict = plistlib.load(fp)
                        except:
                            settings_dict = {}
                for key,value in i.items():
                    if not key.startswith("Payload"):
                        settings_dict[key] = value
        
                plistlib.dump(settings_dict, output_path)
                print(f"Settings plist written to {output_path.name}")
            

def makeNewUUID():
    return str(uuid4())


def concatenate_payload_settings(settings):
    """Takes a list of dictionaries, removed duplicate entries and concatenates an array of settings for the same key
    """
    settings_list = []
    settings_dict = {}
    for item in settings:
        for key, value in item.items():
            if isinstance(value, list):
                settings_dict.setdefault(key, []).append(value[0])
            else:
                settings_dict.setdefault(key, value)
        if item not in settings_list:
            settings_list.append(item)

    return [settings_dict]


def generate_profiles(baseline_name, build_path, parent_dir, baseline_yaml, signing, hash=''):
    """Generate the configuration profiles for the rules in the provided baseline YAML file
    """
    organization = "macOS Security Compliance Project"
    displayname = f"macOS {baseline_name} Baseline settings"

    # import profile_manifests.plist
    manifests_file = os.path.join(
        parent_dir, 'includes', 'supported_payloads.yaml')
    with open(manifests_file) as r:
        manifests = yaml.load(r, Loader=yaml.SafeLoader)

    # Output folder
    


    unsigned_mobileconfig_output_path = os.path.join(
        f'{build_path}', 'mobileconfigs', 'unsigned')
    if not (os.path.isdir(unsigned_mobileconfig_output_path)):
        try:
            os.makedirs(unsigned_mobileconfig_output_path)
        except OSError:
            print("Creation of the directory %s failed" %
                  unsigned_mobileconfig_output_path)
    
    if signing:
        signed_mobileconfig_output_path = os.path.join(
            f'{build_path}', 'mobileconfigs', 'signed')
        if not (os.path.isdir(signed_mobileconfig_output_path)):
            try:
                os.makedirs(signed_mobileconfig_output_path)
            except OSError:
                print("Creation of the directory %s failed" %
                    signed_mobileconfig_output_path)

    settings_plist_output_path = os.path.join(
        f'{build_path}', 'mobileconfigs', 'preferences')
    if not (os.path.isdir(settings_plist_output_path)):
        try:
            os.makedirs(settings_plist_output_path)
        except OSError:
            print("Creation of the directory %s failed" %
                  settings_plist_output_path)
    # setup lists and dictionaries
    profile_errors = []
    profile_types = {}

    for sections in baseline_yaml['profile']:
        
        for profile_rule in sections['rules']:
            logging.debug(f"checking for rule file for {profile_rule}")
            if glob.glob('../custom/rules/**/{}.yaml'.format(profile_rule),recursive=True):
                rule = glob.glob('../custom/rules/**/{}.yaml'.format(profile_rule),recursive=True)[0]
                custom=True
                logging.debug(f"{rule}")
            elif glob.glob('../rules/*/{}.yaml'.format(profile_rule)):
                rule = glob.glob('../rules/*/{}.yaml'.format(profile_rule))[0]
                custom=False
                logging.debug(f"{rule}")

            #for rule in glob.glob('../rules/*/{}.yaml'.format(profile_rule)) + glob.glob('../custom/rules/**/{}.yaml'.format(profile_rule),recursive=True):
            rule_yaml = get_rule_yaml(rule, custom)
    
            if rule_yaml['mobileconfig']:
                for payload_type, info in rule_yaml['mobileconfig_info'].items():
                    valid = True
                    try:
                        if payload_type not in manifests['payloads_types']:
                            profile_errors.append(rule)
                            raise ValueError(
                                "{}: Payload Type is not supported".format(payload_type))
                        else:
                            pass
                    except (KeyError, ValueError) as e:
                        profile_errors.append(rule)
                        logging.debug(e)
                        valid = False

                    try:
                        if isinstance(info, list):
                            raise ValueError(
                                "Payload key is non-conforming")
                        else:
                            pass
                    except (KeyError, ValueError) as e:
                        profile_errors.append(rule)
                        logging.debug(e)
                        valid = False
                    
                    if valid:
                        if payload_type == "com.apple.ManagedClient.preferences":
                            for payload_domain, settings in info.items():
                                for key, value in settings.items():
                                    payload_settings = (
                                        payload_domain, key, value)
                                    profile_types.setdefault(
                                        payload_type, []).append(payload_settings)
                        else:
                            for profile_key, key_value in info.items():
                                payload_settings = {profile_key: key_value}
                                profile_types.setdefault(
                                    payload_type, []).append(payload_settings)

    if len(profile_errors) > 0:
        print("There are errors in the following files, please correct the .yaml file(s)!")
        for error in profile_errors:
            print(error)
    # process the payloads from the yaml file and generate new config profile for each type
    for payload, settings in profile_types.items():
        if payload.startswith("."):
            unsigned_mobileconfig_file_path = os.path.join(
                unsigned_mobileconfig_output_path, "com.apple" + payload + '.mobileconfig')
            settings_plist_file_path = os.path.join(
                settings_plist_output_path, "com.apple" + payload + '.plist')
            if signing:
                signed_mobileconfig_file_path = os.path.join(
                signed_mobileconfig_output_path, "com.apple" + payload + '.mobileconfig')
        else:
            unsigned_mobileconfig_file_path = os.path.join(
                unsigned_mobileconfig_output_path, payload + '.mobileconfig')
            settings_plist_file_path = os.path.join(
                settings_plist_output_path, payload + '.plist')
            if signing:
                signed_mobileconfig_file_path = os.path.join(
                signed_mobileconfig_output_path, payload + '.mobileconfig')
        identifier = payload + f".{baseline_name}"
        description = "Configuration settings for the {} preference domain.".format(
            payload)

        newProfile = PayloadDict(identifier=identifier,
                                 uuid=False,
                                 removal_allowed=False,
                                 organization=organization,
                                 displayname=displayname,
                                 description=description)

        

        if payload == "com.apple.ManagedClient.preferences":
            for item in settings:
                newProfile.addMCXPayload(item, baseline_name)
        # handle these payloads for array settings
        elif (payload == "com.apple.applicationaccess.new") or (payload == 'com.apple.systempreferences'):
            newProfile.addNewPayload(
                payload, concatenate_payload_settings(settings), baseline_name)
        else:
            newProfile.addNewPayload(payload, settings, baseline_name)

        if signing:
            unsigned_file_path=os.path.join(unsigned_mobileconfig_file_path)
            unsigned_config_file = open(unsigned_file_path, "wb")
            newProfile.finalizeAndSave(unsigned_config_file)
            settings_config_file = open(settings_plist_file_path, "wb")
            newProfile.finalizeAndSavePlist(settings_config_file)
            unsigned_config_file.close()
            # sign the profiles
            sign_config_profile(unsigned_file_path, signed_mobileconfig_file_path, hash)
            # delete the unsigned

        else:
            config_file = open(unsigned_mobileconfig_file_path, "wb")
            settings_config_file = open(settings_plist_file_path, "wb")
            newProfile.finalizeAndSave(config_file)
            newProfile.finalizeAndSavePlist(settings_config_file)
            config_file.close()
            
    print(f"""
    CAUTION: These configuration profiles are intended for evaluation in a TEST
    environment. Certain configuration profiles (Smartcards), when applied could 
    leave a system in a state where a user can no longer login with a password. 
    Please use caution when applying configuration settings to a system.
    
    NOTE: If an MDM is already being leveraged, many of these profile settings may
    be available through the vendor.
    """)

def default_audit_plist(baseline_name, build_path, baseline_yaml):
    """"Generate the default audit plist file to define exemptions
    """
    
    # Output folder
    plist_output_path = os.path.join(
        f'{build_path}', 'preferences')
    if not (os.path.isdir(plist_output_path)):
        try:
            os.makedirs(plist_output_path)
        except OSError:
            print("Creation of the directory %s failed" %
                  plist_output_path)

    plist_file_path = os.path.join(
                plist_output_path, 'org.' + baseline_name + '.audit.plist')

    plist_file = open(plist_file_path, "wb")

    plist_dict = {}

    for sections in baseline_yaml['profile']:
        for profile_rule in sections['rules']:
            if profile_rule.startswith("supplemental"):
                continue
            plist_dict[profile_rule] = { "exempt": False }
    
    plistlib.dump(plist_dict, plist_file)


def generate_script(baseline_name, build_path, baseline_yaml, reference):
    categories_path = os.path.join(
        f'{build_path}', '1.categories')
    
    if not (os.path.isdir(categories_path)):
        try:
            os.makedirs(categories_path)
        except OSError:
            print("Creation of the directory %s failed" %
                  categories_path)

    ea_output_path = os.path.join(
        f'{build_path}', '2.ea')
    
    if not (os.path.isdir(ea_output_path)):
        try:
            os.makedirs(ea_output_path)
        except OSError:
            print("Creation of the directory %s failed" %
                  ea_output_path)

    scripts_output_path = os.path.join(
        f'{build_path}', '3.scripts')
    
    if not (os.path.isdir(scripts_output_path)):
        try:
            os.makedirs(scripts_output_path)
        except OSError:
            print("Creation of the directory %s failed" %
                  scripts_output_path)

    smartgroups_output_path = os.path.join(
        f'{build_path}', '4.smartgroups')
    
    if not (os.path.isdir(smartgroups_output_path)):
        try:
            os.makedirs(smartgroups_output_path)
        except OSError:
            print("Creation of the directory %s failed" %
                  smartgroups_output_path)
    

    policy_output_path = os.path.join(
        f'{build_path}', '5.policies')
    
    if not (os.path.isdir(policy_output_path)):
        try:
            os.makedirs(policy_output_path)
        except OSError:
            print("Creation of the directory %s failed" %
                  policy_output_path)

   

    check_function_string = ""
    fix_function_string = ""
    smart_group_string = ""

    # create header of fix zsh script
   

    # Read all rules in the section and output the check functions
    for sections in baseline_yaml['profile']:
        for profile_rule in sections['rules']:
            logging.debug(f"checking for rule file for {profile_rule}")
            if glob.glob('../custom/rules/**/{}.yaml'.format(profile_rule),recursive=True):
                rule = glob.glob('../custom/rules/**/{}.yaml'.format(profile_rule),recursive=True)[0]
                custom=True
                logging.debug(f"{rule}")
            elif glob.glob('../rules/*/{}.yaml'.format(profile_rule)):
                rule = glob.glob('../rules/*/{}.yaml'.format(profile_rule))[0]
                custom=False
                logging.debug(f"{rule}")

            rule_yaml = get_rule_yaml(rule, custom)

            if rule_yaml['id'].startswith("supplemental"):
                continue
            if "manual" in rule_yaml['tags']:
                continue

            if "arm64" in rule_yaml['tags']:
                arch="arm64"
            elif "intel" in rule_yaml['tags']:
                arch="i386"
            else:
                arch=""
            
            # grab the 800-53 controls
            try:
                rule_yaml['references']['800-53r5']
            except KeyError:
                nist_80053r5 = 'N/A'
            else:
                nist_80053r5 = rule_yaml['references']['800-53r5']
            
            if reference == "default":
                log_reference_id = [rule_yaml['id']]
            else:
                try: 
                    rule_yaml['references'][reference]
                except KeyError:
                    try: 
                        rule_yaml['references']['custom'][reference]
                    except KeyError:
                        log_reference_id = [rule_yaml['id']]
                    else:
                        if isinstance(rule_yaml['references']['custom'][reference], list):
                            log_reference_id = rule_yaml['references']['custom'][reference] + [rule_yaml['id']]
                        else:
                            log_reference_id = [rule_yaml['references']['custom'][reference]] + [rule_yaml['id']]
                else:
                    if isinstance(rule_yaml['references'][reference], list):
                        log_reference_id = rule_yaml['references'][reference] + [rule_yaml['id']]
                    else:
                            log_reference_id = [rule_yaml['references'][reference]] + [rule_yaml['id']]
                            
                
        # group the controls
            if not nist_80053r5 == "N/A":
                nist_80053r5.sort()
                res = [list(i) for j, i in groupby(
                    nist_80053r5, lambda a: a.split('(')[0])]
                nist_controls = ''
                for i in res:
                    nist_controls += group_ulify(i)
            else:
                nist_controls = "N/A"

            # print checks and result
            try:
                check = rule_yaml['check']
            except KeyError:
                print("no check found for {}".format(rule_yaml['id']))
                continue
            try:
                result = rule_yaml['result']
            except KeyError:
                #print("no result found for {}".format(rule_yaml['id']))
                continue

            if "integer" in result:
                result_value = result['integer']
            elif "boolean" in result:
                result_value = result['boolean']
            elif "string" in result:
                result_value = result['string']
            else:
                continue

            # write the checks

            jamf_category = '''<category><name>{}</name><priority>9</priority></category>'''.format(baseline_name + " - " + sections['section'])


            with open("{}/1.categories/{}.xml".format(build_path,sections['section']),'w') as rite:
                    rite.write(jamf_category)
            
            rite.close()

            zsh_check_text = """#!/bin/zsh        
#####----- Rule: {0} -----#####
## Addresses the following NIST 800-53 controls: {1}
rule_arch="{6}"
plb="/usr/libexec/PlistBuddy"
# setup files
audit_plist_managed="/Library/Managed Preferences/org.{7}.audit.plist"

if [[ ! -e "$audit_plist_managed" ]];then
    audit_plist_managed="/Library/Preferences/org.{7}.audit.plist"
fi

audit_plist="/Library/Preferences/org.{7}.audit.plist"
audit_log="/Library/Logs/{7}_baseline.log"
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: {0} ...' 
    unset result_value
    result_value=$({2})
    # expected result {3}

    # check to see if rule is exempt
    unset exempt
    unset exempt_reason
    exempt=$($plb -c "print {0}:exempt" "$audit_plist_managed" 2>/dev/null)
    exempt_reason=$($plb -c "print {0}:exempt_reason" "$audit_plist_managed" 2>/dev/null)

    if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
        if [[ $result_value == "{4}" ]]; then
            echo "<result>{5} passed (Result: $result_value, Expected: "{3}")</result>" 
            
        else
            echo "<result>{5} failed (Result: $result_value, Expected: "{3}")</result>" 
            
        fi
    elif [[ ! -z "$exempt_reason" ]];then
        echo "<result>{5} has an exemption (Reason: "$exempt_reason")</result>" 
        
        /bin/sleep 1
    fi
else
    echo "<result>{5} does not apply to this architechture</result>" 
fi""".format(rule_yaml['id'], nist_controls.replace("\n", "\n#"), check.strip(), result, result_value, ' '.join(log_reference_id), arch, baseline_name)
            
            extension_attribute = '''<computer_extension_attribute>
<id>0</id>
<name>{3} - {0}</name>
<description>{1}</description>
<data_type>String</data_type>
<input_type>
<type>script</type>
<platform>Mac</platform>
<script>{2}</script>
</input_type>
<inventory_display>Extension Attributes</inventory_display>
<recon_display>Extension Attributes</recon_display>
</computer_extension_attribute>
            '''.format(rule_yaml['id'],rule_yaml['discussion'],escape(zsh_check_text).replace("\n","&#13;\n"),baseline_name) 
            
            with open("{}/2.ea/{}.xml".format(build_path,rule_yaml['id']),'w') as rite:
                rite.write(extension_attribute)
            
            rite.close()

            # print fix and result
            try:
                rule_yaml['fix']
            except KeyError:
                fix_text = 'N/A'
            else:
                fix_text = rule_yaml['fix'] or ["n/a"]

# write the fixes

            if "[source,bash]" in fix_text:
                nist_controls_commented = nist_controls.replace('\n', '\n#')
                zsh_fix_text = f"""#!/bin/zsh
#####----- Rule: {rule_yaml['id']} -----#####
## Addresses the following NIST 800-53 controls: {nist_controls_commented}

plb="/usr/libexec/PlistBuddy"
# setup files
audit_plist_managed="/Library/Managed Preferences/org.{0}.audit.plist"

if [[ ! -e "$audit_plist_managed" ]];then
    audit_plist_managed="/Library/Preferences/org.{0}.audit.plist"
fi

audit_plist="/Library/Preferences/org.{0}.audit.plist"
audit_log="/Library/Logs/{0}_baseline.log"

# check to see if rule is exempt
unset exempt
unset exempt_reason
exempt=$($plb -c "print {rule_yaml['id']}:exempt" "$audit_plist_managed" 2>/dev/null)
exempt_reason=$($plb -c "print {rule_yaml['id']}:exempt_reason" "$audit_plist_managed" 2>/dev/null)

{rule_yaml['id']}_audit_score=$($plb -c "print {rule_yaml['id']}:finding" $audit_plist)
if [[ ! $exempt == "true" ]] || [[ -z $exempt ]];then
    if [[ ${rule_yaml['id']}_audit_score == "true" ]]; then
            echo 'Running the command to configure the settings for: {rule_yaml['id']} ...' 
            {get_fix_code(rule_yaml['fix']).strip()}
    else
        echo 'Settings for: {rule_yaml['id']} already configured, continuing...' 
    fi
elif [[ ! -z "$exempt_reason" ]];then
    echo "$(date -u) {rule_yaml['id']} has an exemption (Reason: "$exempt_reason")" 
fi
    """
                jamf_script = '''<script>
<name>{0} - {1}</name>
 <category>{3}</category>
<script_contents>{2}</script_contents>
</script>'''.format(baseline_name, rule_yaml['id'] + " - Fix",escape(zsh_fix_text).replace("\n","&#13;\n"),baseline_name + " - " + sections['section'])
                
                with open("{}/3.scripts/{}-fix.xml".format(build_path,rule_yaml['id']),'w') as rite:
                    rite.write(jamf_script)
            
                rite.close()

                smart_group_string = '''<computer_group>
<name>{0} - Enforced</name>
<is_smart>true</is_smart>
<criteria>
<criterion>
<name>{1} - {0}</name>
            <priority>0</priority>
            <and_or>and</and_or>
            <search_type>like</search_type>
            <value>{0} passed</value>
            <opening_paren>false</opening_paren>
            <closing_paren>false</closing_paren>
        </criterion>
    </criteria>
</computer_group>'''.format(rule_yaml['id'],baseline_name)
                with open("{}/4.smartgroups/{}-SG-enforced.xml".format(build_path,rule_yaml['id']),'w') as rite:
                    rite.write(smart_group_string)
                
                rite.close()
    
                smart_group_string = '''<computer_group>
<name>{0} - Failed</name>
<is_smart>true</is_smart>
<criteria>
<criterion>
<name>{1} - {0}</name>
<priority>0</priority>
<and_or>and</and_or>
<search_type>like</search_type>
<value>{0} failed</value>
<opening_paren>false</opening_paren>
<closing_paren>false</closing_paren>
</criterion>
</criteria>
</computer_group>'''.format(rule_yaml['id'],baseline_name)
                with open("{}/4.smartgroups/{}-SG-failed.xml".format(build_path,rule_yaml['id']),'w') as rite:
                    rite.write(smart_group_string)
                
                rite.close()

                policy_string = '''<policy>
<general>
<name>{0} - Enforce</name>
<enabled>true</enabled>
<trigger>CHECKIN</trigger>
<trigger_checkin>true</trigger_checkin>
<frequency>Once every day</frequency>
    <category>
        <name>{2}</name>
    </category>
</general>
<scope>
        <all_computers>false</all_computers>
        <computers/>
        <computer_groups>
            <computer_group>
                <name>{0} - Failed</name>
            </computer_group>
        </computer_groups>
        <exclusions>
            <computers/>
            <computer_groups>
                <computer_group>
                    <name>{0} - Enforced</name>
                </computer_group>
            </computer_groups>
        </exclusions>
    </scope>
    <scripts>
        <size>1</size>
        <script>
            <name>{1} - {0} - Fix</name>
            <priority>After</priority>
        </script>
    </scripts>
</policy>'''.format(rule_yaml['id'],baseline_name,baseline_name + " - " + sections['section'])
                with open("{}/5.policies/{}.xml".format(build_path,rule_yaml['id']),'w') as rite:
                    rite.write(policy_string)
                
                rite.close()

    print(f"Finished building ")


def get_rule_yaml(rule_file, custom=False):
    """ Takes a rule file, checks for a custom version, and returns the yaml for the rule
    """
    resulting_yaml = {}
    names = [os.path.basename(x) for x in glob.glob('../custom/rules/**/*.yaml', recursive=True)]
    file_name = os.path.basename(rule_file)

    if custom:
        print(f"Custom settings found for rule: {rule_file}")
        try:
            override_path = glob.glob('../custom/rules/**/{}'.format(file_name), recursive=True)[0]
        except IndexError:
            override_path = glob.glob('../custom/rules/{}'.format(file_name), recursive=True)[0]
        with open(override_path) as r:
            rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)
    else:
        with open(rule_file) as r:
            rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)
    
    try:
        og_rule_path = glob.glob('../rules/**/{}'.format(file_name), recursive=True)[0]
    except IndexError:
        #assume this is a completely new rule
        og_rule_path = glob.glob('../custom/rules/**/{}'.format(file_name), recursive=True)[0]
        resulting_yaml['customized'] = ["customized rule"]
    
    # get original/default rule yaml for comparison
    with open(og_rule_path) as og:
        og_rule_yaml = yaml.load(og, Loader=yaml.SafeLoader)

    for yaml_field in og_rule_yaml:
        #print('processing field {} for rule {}'.format(yaml_field, file_name))
        if yaml_field == "references":
            if not 'references' in resulting_yaml:
                resulting_yaml['references'] = {}
            for ref in og_rule_yaml['references']:
                try:
                    if og_rule_yaml['references'][ref] == rule_yaml['references'][ref]:
                        resulting_yaml['references'][ref] = og_rule_yaml['references'][ref]
                    else:
                        resulting_yaml['references'][ref] = rule_yaml['references'][ref]
                except KeyError:
                    #  reference not found in original rule yaml, trying to use reference from custom rule
                    try:
                        resulting_yaml['references'][ref] = rule_yaml['references'][ref]
                    except KeyError:
                        resulting_yaml['references'][ref] = og_rule_yaml['references'][ref]
                try: 
                    if "custom" in rule_yaml['references']:
                        resulting_yaml['references']['custom'] = rule_yaml['references']['custom']
                        if 'customized' in resulting_yaml:
                            if 'customized references' not in resulting_yaml['customized']:
                                resulting_yaml['customized'].append("customized references")
                        else:
                            resulting_yaml['customized'] = ["customized references"]
                except:
                    pass
            
        else: 
            try:
                if og_rule_yaml[yaml_field] == rule_yaml[yaml_field]:
                    #print("using default data in yaml field {}".format(yaml_field))
                    resulting_yaml[yaml_field] = og_rule_yaml[yaml_field]
                else:
                    #print('using CUSTOM value for yaml field {} in rule {}'.format(yaml_field, file_name))
                    resulting_yaml[yaml_field] = rule_yaml[yaml_field]
                    if 'customized' in resulting_yaml:
                        resulting_yaml['customized'].append("customized {}".format(yaml_field))
                    else:
                        resulting_yaml['customized'] = ["customized {}".format(yaml_field)]
            except KeyError:
                resulting_yaml[yaml_field] = og_rule_yaml[yaml_field]

    return resulting_yaml

def create_rules(baseline_yaml):
    """Takes a baseline yaml file and parses the rules, returns a list of containing rules
    """
    all_rules = []
    #expected keys and references
    keys = ['mobileconfig',
            'macOS',
            'severity',
            'title',
            'check',
            'fix',
            'tags',
            'id',
            'references',
            'result',
            'discussion',
            'customized']
    references = ['disa_stig',
                  'cci',
                  'cce',
                  '800-53r5',
                  '800-171r2',
                  'cisv8',
                  'srg',
                  'custom']


    for sections in baseline_yaml['profile']:
        for profile_rule in sections['rules']:
            if glob.glob('../custom/rules/**/{}.yaml'.format(profile_rule),recursive=True):
                rule = glob.glob('../custom/rules/**/{}.yaml'.format(profile_rule),recursive=True)[0]
                custom=True
            elif glob.glob('../rules/*/{}.yaml'.format(profile_rule)):
                rule = glob.glob('../rules/*/{}.yaml'.format(profile_rule))[0]
                custom=False

            #for rule in glob.glob('../rules/*/{}.yaml'.format(profile_rule)) + glob.glob('../custom/rules/**/{}.yaml'.format(profile_rule),recursive=True):
            rule_yaml = get_rule_yaml(rule, custom)

            for key in keys:
                try:
                    rule_yaml[key]
                except:
                    #print("{} key missing ..for {}".format(key, rule))
                    rule_yaml.update({key: ""})
                if key == "references":
                    for reference in references:
                        try:
                            rule_yaml[key][reference]
                            #print("FOUND reference {} for key {} for rule {}".format(reference, key, rule))
                        except:
                            #print("expected reference '{}' is missing in key '{}' for rule{}".format(reference, key, rule))
                            rule_yaml[key].update({reference: ["None"]})
            all_rules.append(MacSecurityRule(rule_yaml['title'].replace('|', '\|'),
                                        rule_yaml['id'].replace('|', '\|'),
                                        rule_yaml['severity'].replace('|', '\|'),
                                        rule_yaml['discussion'].replace('|', '\|'),
                                        rule_yaml['check'].replace('|', '\|'),
                                        rule_yaml['fix'].replace('|', '\|'),
                                        rule_yaml['references']['cci'],
                                        rule_yaml['references']['cce'],
                                        rule_yaml['references']['800-53r5'],
                                        rule_yaml['references']['800-171r2'],
                                        rule_yaml['references']['disa_stig'],
                                        rule_yaml['references']['srg'],
                                        rule_yaml['references']['cisv8'],
                                        rule_yaml['references']['custom'],
                                        rule_yaml['tags'],
                                        rule_yaml['result'],
                                        rule_yaml['mobileconfig'],
                                        rule_yaml['mobileconfig_info'],
                                        rule_yaml['customized']
                                        ))

    return all_rules

def create_args():
    """configure the arguments used in the script, returns the parsed arguements
    """
    parser = argparse.ArgumentParser(
        description='Given a baseline, create guidance documents and files.')
    parser.add_argument("baseline", default=None,
                        help="Baseline YAML file used to create the guide.", type=argparse.FileType('rt'))
    parser.add_argument("-c", "--clean", default=None,
                        help=argparse.SUPPRESS, action="store_true")
    parser.add_argument("-d", "--debug", default=None,
                        help=argparse.SUPPRESS, action="store_true")
    parser.add_argument("-p", "--profiles", default=None,
                        help="Generate configuration profiles for the rules.", action="store_true")
    parser.add_argument("-j", "--jamf", default=None,
                        help="Generate the compliance script for the rules.", action="store_true")
    parser.add_argument("-H", "--hash", default=None,
                        help="sign the configuration profiles with subject key ID (hash value without spaces)")
    return parser.parse_args()


def verify_signing_hash(hash):
    """Attempts to validate the existence of the certificate provided by the hash
    """
    with tempfile.NamedTemporaryFile(mode="w") as in_file:
        unsigned_tmp_file_path=in_file.name
        in_file.write("temporary file for signing")
    
        cmd = f"security cms -S -Z {hash} -i {unsigned_tmp_file_path}"
        FNULL = open(os.devnull, 'w')
        process = subprocess.Popen(cmd.split(), stdout=FNULL, stderr=FNULL)
        output, error = process.communicate()
    if process.returncode == 0:
        return True
    else:
        return False
        
def sign_config_profile(in_file, out_file, hash):
    """Signs the configuration profile using the identity associated with the provided hash
    """
    cmd = f"security cms -S -Z {hash} -i {in_file} -o {out_file}"
    process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    print(f"Signed Configuration profile written to {out_file}")
    return output.decode("utf-8")


def main():

    args = create_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)

    try:
        output_basename = os.path.basename(args.baseline.name)
        output_filename = os.path.splitext(output_basename)[0]
        baseline_name = os.path.splitext(output_basename)[0]#.capitalize()
        file_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(file_dir)

        # stash current working directory
        original_working_directory = os.getcwd()

        # switch to the scripts directory
        os.chdir(file_dir)

        build_path = os.path.join(parent_dir, 'build', f'{baseline_name}')
        if not (os.path.isdir(build_path)):
            try:
                os.makedirs(build_path)
            except OSError:
                print(f"Creation of the directory {build_path} failed")
        print('Profile YAML:', args.baseline.name)
        print('Output path:', build_path)

        if args.hash:
            signing = True
            if not verify_signing_hash(args.hash):
                sys.exit('Cannot use the provided hash to sign.  Please make sure you provide the subject key ID hash from an installed certificate')
        else:
            signing = False

    except IOError as msg:
        parser.error(str(msg))
    

    baseline_yaml = yaml.load(args.baseline, Loader=yaml.SafeLoader)

    # Create sections and rules
    for sections in baseline_yaml['profile']:
        section_yaml_file = sections['section'].lower() + '.yaml'
        #check for custom section
        if section_yaml_file in glob.glob1('../custom/sections/', '*.yaml'):
            #print(f"Custom settings found for section: {sections['section']}")
            override_section = os.path.join(
                f'../custom/sections/{section_yaml_file}')
            with open(override_section) as r:
                section_yaml = yaml.load(r, Loader=yaml.SafeLoader)
        else:
            with open(f'../sections/{section_yaml_file}') as s:
                section_yaml = yaml.load(s, Loader=yaml.SafeLoader)



        # Read all rules in the section and output them

        for rule in sections['rules']:
            logging.debug(f'processing rule id: {rule}')
            rule_path = glob.glob('../rules/*/{}.yaml'.format(rule))
            if not rule_path:
                print(f"Rule file not found in library, checking in custom folder for rule: {rule}")
                rule_path = glob.glob('../custom/rules/**/{}.yaml'.format(rule), recursive=True)
            try:
                rule_file = (os.path.basename(rule_path[0]))
            except IndexError:
                logging.debug(f'defined rule {rule} does not have valid yaml file, check that rule ID and filename match.')

            #check for custom rule
            if glob.glob('../custom/rules/**/{}'.format(rule_file), recursive=True):
                print(f"Custom settings found for rule: {rule_file}")
                #override_rule = glob.glob('../custom/rules/**/{}'.format(rule_file), recursive=True)[0]
                rule_location = glob.glob('../custom/rules/**/{}'.format(rule_file), recursive=True)[0]
                custom=True
            else:
                rule_location = rule_path[0]
                custom=False
            
            rule_yaml = get_rule_yaml(rule_location, custom)

    
    if args.profiles:
        print("Generating configuration profiles...")
        generate_profiles(baseline_name, build_path, parent_dir, baseline_yaml, signing, args.hash)
    
    if args.jamf:
        print("Generating jamf xml pieces...")
        generate_script(baseline_name, build_path, baseline_yaml, "default")
        default_audit_plist(baseline_name, build_path, baseline_yaml)

    # finally revert back to the prior directory
    os.chdir(original_working_directory)

if __name__ == "__main__":
    main()

