"""Run Calc's CSV importer and exporter on the fixture from generate.go."""

import csv
from pathlib import Path
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from zipfile import ZipFile

# UTF-8, comma, double quotes, en-US, standard columns, evaluate formulas on
# import, save displayed values on export. See LibreOffice's CSV Filter Options.
CSV_FILTER = "Text - txt - csv (StarCalc):44,34,76,1,,1033,false,true,true,false,false,0,true"
TABLE = "{urn:oasis:names:tc:opendocument:xmlns:table:1.0}"
OFFICE = "{urn:oasis:names:tc:opendocument:xmlns:office:1.0}"


def records(path):
    with path.open(encoding="utf-8", newline="") as f:
        return list(csv.reader(f))


def check_cells(path, expected, first_open):
    with ZipFile(path) as archive:
        sheet = ET.fromstring(archive.read("content.xml"))
    rows = sheet.findall(f".//{TABLE}table-row")
    if len(rows) != len(expected):
        raise ValueError(f"{path}: expected {len(expected)} rows, found {len(rows)}")
    for row, (label, _) in zip(rows, expected):
        key, cell = row.findall(f"{TABLE}table-cell")
        if "".join(key.itertext()) != label:
            raise ValueError(f"{path}: missing row {label}")
        formula = cell.get(TABLE + "formula")
        if label == "raw control":
            if bool(formula) != first_open or cell.get(OFFICE + "value") != "42":
                raise ValueError(f"{path}: raw control did not calculate and export as 42")
        elif formula or cell.get(OFFICE + "value-type") != "string":
            raise ValueError(f"{path}: {label} is not a text cell: {cell.attrib}")


def check_calc(source, work):
    expected = records(source)
    if expected[:2] != [["case", "value"], ["raw control", "=6*7"]] or len(expected) <= 2:
        raise ValueError("Expected the generated fixture, including the raw formula control")
    calc = [
        "libreoffice", f"-env:UserInstallation={(work / 'profile').as_uri()}",
        "--headless", f"--infilter={CSV_FILTER}",
    ]

    def convert(path, folder, fmt):
        dest = work / folder
        dest.mkdir()
        subprocess.run(
            [*calc, "--convert-to", fmt, "--outdir", dest, path], check=True, timeout=60
        )
        return dest / (path.stem + "." + fmt.split(":")[0])

    check_cells(convert(source, "first", "ods"), expected, first_open=True)
    saved = convert(source, "saved", "csv:" + CSV_FILTER)
    # Calc saves the calculated control, normalizes CR to LF and drops NUL.
    values = [
        [label, "42" if label == "raw control" else value.replace("\r", "\n").replace("\0", "")]
        for label, value in expected
    ]
    if records(saved) != values:
        raise ValueError(f"Unexpected re-exported CSV records for {source}")
    check_cells(convert(saved, "reopen", "ods"), expected, first_open=False)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmp:
        check_calc(Path(sys.argv[1]).resolve(), Path(tmp))
    print("Calc round-trip passed")
