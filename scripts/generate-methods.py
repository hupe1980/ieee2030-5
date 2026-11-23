"""Emit Rust method policy rows from the IEEE 2030.5-2018 supplemental WADL."""
import hashlib
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

METHODS = ("GET", "HEAD", "PUT", "POST", "DELETE")
MODES = {"M": "Mandatory", "O": "Optional", "D": "Discouraged", "E": "Error"}
data = Path(sys.argv[1]).read_bytes()
if hashlib.sha256(data).hexdigest() != "93ee874d3a7e216dd1074781a0be390af2fa075f8f9145f5fbf08d509f4fa1c5":
    sys.exit("Expected the 2018 supplemental sep_wadl.xml")
schema = ET.fromstring(data)
rows = []
for resource in schema.findall(".//{*}resource"):
    modes = {method.attrib["name"]: MODES[method.attrib["{urn:ieee:std:2030.5:wadlExt}mode"]]
             for method in resource.findall("{*}method")}
    post = resource.find("{*}method[@name='POST']")
    bodies = sorted({rep.attrib["element"].split(":")[-1]
                     for rep in post.findall("{*}request/{*}representation")
                     if rep.get("mediaType") == "application/sep+xml"})
    representation = resource.find("{*}method[@name='GET']/{*}response/{*}representation")
    returned_type = representation.attrib["element"].split(":")[-1]
    rows.append((resource.attrib["id"], [modes[name] for name in METHODS], bodies, returned_type))
lines = ['// Generated from IEEE 2030.5-2018 sep_wadl.xml by generate-methods.py.', '&[']
for name, modes, bodies, returned_type in sorted(rows):
    types = ", ".join(f'"{body}"' for body in bodies)
    lines.append(f'    ("{name}", [{", ".join(modes)}], &[{types}], "{returned_type}"),')
lines.append(']')
Path(sys.argv[2]).write_text('\n'.join(lines) + '\n')
