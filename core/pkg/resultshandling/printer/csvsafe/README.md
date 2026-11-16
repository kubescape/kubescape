# CSV formula injection

Kubescape prefixes formula-like cells with the literal characters `text: `. For
example, the exported value of `=6*7` is `text: =6*7`. The marker is visible in
spreadsheets and to programs that read the CSV. Removing it can expose the
original formula. CSV quoting alone only escapes delimiters.

## Application checks on 2026-11-16

The baseline was Kubescape `3feb8931` (single-apostrophe mitigation). Both
versions used the same harmless fixture. The raw control in B2 evaluated to
42 on initial import in both tested applications and exported as the number 42.

| Application and import method | Baseline first open | Baseline CSV re-export and reopen | With the visible prefix |
| --- | --- | --- | --- |
| Google Sheets, native Drive CSV conversion, en_GB | The ten apostrophe-prefixed cells imported as strings. Their stored and displayed values omitted the apostrophe. | Five became formulas on reimport: `equals`, `space`, `tab`, `already prefixed` and `embedded quotes`. The first four evaluated to 42 and the last to `a,bc`. | All twelve protected cells were strings on both imports. The downloaded CSV retained the marker on every one. |
| LibreOffice Calc 26.2.7.3, Linux, UTF-8, en-US, formula evaluation enabled | All ten apostrophe-prefixed cells kept the apostrophe as literal text. The leading-NUL cell received no prefix on the baseline and evaluated to 42. | The apostrophes survived and those cells remained text. The NUL case exported as its calculated value, 42. | All twelve protected cells were strings on both imports and retained the marker in the saved CSV. |
| Microsoft Excel desktop | Pending | Pending | Pending |

A separate Google Sheets import of an em space (U+2003) followed by `=6*7`
evaluated to 42. Drive's automatic encoding detection misdecoded the em space
in the combined fixture. Calc discarded embedded NULs and both applications
normalized embedded CR to LF. The checks cover formula status and the marker.
Spreadsheet conversions can also change the underlying text.

## Reproduce

From the repository root, generate the file with the production sanitizer. To
compare an older revision, run the same generator by absolute path with the
older checkout as the working directory.

```sh
pkg=core/pkg/resultshandling/printer/csvsafe
go run "./$pkg/testdata/generate.go" > fixture.csv
python3 "$pkg/testdata/check_calc.py" fixture.csv
```

The Calc check requires the Calc component of LibreOffice on PATH and Python 3.
It opens the CSV with formulas enabled, checks the actual cell types in an ODS
snapshot, saves the original CSV through Calc's CSV filter, and opens the saved
bytes in Calc again. The profile and outputs are temporary.
[LibreOffice CSV filter options](https://help.libreoffice.org/latest/en-US/text/shared/guide/csv_params.html)

For Google Sheets, import the file as a native spreadsheet, export the first
sheet as CSV, and import that file as a new spreadsheet. Inspect
`userEnteredValue.formulaValue` versus `stringValue` on both imports. In the
UI, enable conversion of text to numbers, dates and formulas when using File
→ Import.

For Excel, record the edition, version, OS, locale and opening method. Open
the CSV normally and check that `ISFORMULA(B2)` is TRUE and B2 displays 42.
Check `ISFORMULA` on B3 through B15, for example by filling the formula down
an unused column. Inspect whether the prefix is visible. Save a new copy as
CSV UTF-8 (comma delimited), close the workbook, inspect the saved CSV in a
text editor, and open that copy in Excel. **Enter the ISFORMULA checks again**
because the CSV may contain only their old results. Record which cells are
formulas on reopen. The fixed fixture should have zero formulas in B3:B15.
