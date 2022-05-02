#!/usr/bin/env python3
import argparse
import sys
import os
import os.path
import yaml
import glob
import warnings
from pathlib import Path

def get_rule_yaml(rule_file, custom=False):
    """ Takes a rule file, checks for a custom version, and returns the yaml for the rule
    """
    resulting_yaml = {}
    names = [os.path.basename(x) for x in glob.glob('../custom/rules/**/*.yaml', recursive=True)]
    file_name = os.path.basename(rule_file)
    # if file_name in names:
    #     print(f"Custom settings found for rule: {rule_file}")
    #     try:
    #         override_path = glob.glob('../custom/rules/**/{}'.format(file_name), recursive=True)[0]
    #     except IndexError:
    #         override_path = glob.glob('../custom/rules/{}'.format(file_name), recursive=True)[0]
    #     with open(override_path) as r:
    #         rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)
    #     r.close()
    # else:
    #     with open(rule_file) as r:
    #         rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)
    #     r.close()
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

def main():
    parser = argparse.ArgumentParser(description='Given a profile, create JSON custom schema to use in Jamf.')
    parser.add_argument("baseline", default=None, help="Baseline YAML file used to create the JSON custom schema.", type=argparse.FileType('rt'))

    results = parser.parse_args()
    try:
        
        output_basename = os.path.basename(results.baseline.name)
        output_filename = os.path.splitext(output_basename)[0]
        baseline_name = os.path.splitext(output_basename)[0]
        file_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(file_dir)
        # stash current working directory
        original_working_directory = os.getcwd()

        # switch to the scripts directory
        os.chdir(file_dir)
        build_path = os.path.join(parent_dir, 'build', f'{baseline_name}')
        output = build_path + "/" + baseline_name + ".json"

        if not (os.path.isdir(build_path)):
            try:
                os.makedirs(build_path)
            except OSError:
                print(f"Creation of the directory {build_path} failed")
        print('Profile YAML:', results.baseline.name)
        print('Output path:', output)
        
       
        
    except IOError as msg:
        parser.error(str(msg))

    profile_yaml = yaml.load(results.baseline, Loader=yaml.SafeLoader)

    json = '''
    {{
  "title": "org.{0}.audit.plist",
  "description": "Preference Domain: org.{0}.audit,  Application: macOS Security Compliance Project",
  "__version": "1.0",
  "__feedback": "boberito@mac.com",
  "type": "object",
  "options": {{
    "remove_empty_properties": true
  }},
  "properties": {{'''.format(baseline_name,baseline_name)


    for sections in profile_yaml['profile']:
        if sections['section'] == "Supplemental":
            continue
        
        for profile_rule in sections['rules']:
            

            if glob.glob('../custom/rules/**/{}.yaml'.format(profile_rule),recursive=True):
                rule = glob.glob('../custom/rules/**/{}.yaml'.format(profile_rule),recursive=True)[0]
                custom=True
            
            elif glob.glob('../rules/*/{}.yaml'.format(profile_rule)):
                rule = glob.glob('../rules/*/{}.yaml'.format(profile_rule))[0]
                custom=False
            
            rule_yaml = get_rule_yaml(rule, custom)

            
            if "inherent" in rule_yaml['tags'] or "n_a" in rule_yaml['tags'] or "permanent" in rule_yaml['tags']:
                continue

            json = json + '''
      "{0}": {{
      "title": "{0}",
      "description": "{1}",
      "property_order": 1,
      "anyOf": [
        {{
          "type": "null",
          "title": "Not Configured"
        }},
        {{
          "title": "Configured",
          "type": "object",
          "properties": {{
            "exempt": {{
              "description": "If value is true, exempt_reason is required",
              "type": "boolean"
            }},
            "exempt_reason": {{
              "description": "Specify Exempt Reasoning",
              "type": "string"
            }}
          }}
        }}
      ]
    }},'''.format(rule_yaml['id'],rule_yaml['title'])
                
    json = json[:-1]

    json = json + '''
    }}'''

    with open(output,'w') as rite:
            rite.write(json)
            rite.close()
    
    os.chdir(original_working_directory)
            
if __name__ == "__main__":
    main()
