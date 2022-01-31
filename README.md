# mscp_jamf
 Build compliance in jamf

Built for use with the macOS Security Compliance Project (https://github.com/usnistgov/macos_security)

Drop the generate_jamf.py script in the scripts directory within the project folders.

Then when running generate_jamf.py use the -j to generate the pieces for jamf and the -p to generate profiles.

Use the build_jamf.py script to upload the pieces built by the generate_jamf.py script. This will not upload the configuration profiles however, as Jamf will modify the contents which can cause issues.
