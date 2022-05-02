#!/usr/bin/env python3
import argparse
import sys
import os
import os.path
import yaml
import glob
import warnings
from pathlib import Path

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
        for profile_rule in sections['rules']:
            for rule_file in glob.glob('../rules/*/{}.yaml'.format(profile_rule)):
                
                if "srg" in rule_file or "supplemental" in rule_file:
                    continue
                with open(rule_file) as r:
                    rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)
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
            
if __name__ == "__main__":
    main()
