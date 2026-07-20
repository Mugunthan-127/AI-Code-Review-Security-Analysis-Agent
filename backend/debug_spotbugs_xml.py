import xml.etree.ElementTree as ET

tree = ET.parse('/tmp/spotbugs_out.xml')
root = tree.getroot()

for bug in root.findall('.//BugInstance'):
    print(bug.get('type'), bug.get('category'))
