"""Regression checks for schema inventory and build provenance."""
from pathlib import Path
from tempfile import TemporaryDirectory
import os
import unittest
from xml.etree import ElementTree as ET
import re

from codegen import PIN, XSD, read_pinned


class SchemaGeneration(unittest.TestCase):
    # 001-schema-codegen/SR-003
    def test_altered_schema_is_rejected_before_parsing(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "sep.xsd"
            source.write_text("<schema/>")
            with self.assertRaisesRegex(SystemExit, "differs from the pinned release"):
                read_pinned(source, PIN)

    def test_generated_inventory_matches_schema(self):
        def names(path):
            schema = ET.parse(path)
            return {node.attrib["name"] for tag in ("complexType", "simpleType")
                    for node in schema.findall(XSD + tag)}

        source = os.environ.get("IEEE2030_5_SCHEMA")
        if not source:
            self.skipTest("set IEEE2030_5_SCHEMA to the publisher XSD")
        base = names(source)
        australian = names(Path(source).with_name("csipaus-ext-v1.2.xsd"))
        generated = Path("src/model/generated.rs").read_text()
        found = re.findall(r"^view!\((\w+)\);", generated, re.M)
        self.assertCountEqual(found, base | australian)
        self.assertIn(f"pub const BASE_TYPE_COUNT: usize = {len(base)};", generated)
        print(f"{len(base)} generated base types match the pinned schema")



if __name__ == "__main__":
    unittest.main()
