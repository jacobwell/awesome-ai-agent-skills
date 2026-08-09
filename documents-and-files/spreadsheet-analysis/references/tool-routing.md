# Spreadsheet tool routing

Inventory the environment first. Choose the smallest toolchain that preserves the required workbook features.

| Need | Preferred capability | Examples when already available | Key limitation to verify |
|---|---|---|---|
| Visual edit/recalculation | Native spreadsheet application | Excel, LibreOffice Calc, Numbers | Cross-engine formula and layout differences |
| XLSX formulas/styles | Workbook-aware library | openpyxl, ExcelJS, SheetJS | Usually does not calculate formulas or fully preserve every feature |
| XLS/XLSB legacy formats | Format-specific reader or office conversion | xlrd-compatible tooling, pyxlsb, office suite | Conversion can lose macros, names, formatting, charts |
| ODS | ODF-aware library/application | LibreOffice, odfpy | Formula syntax and style differences |
| Large tabular analysis | Dataframe or query engine | pandas, Polars, DuckDB | Workbook semantics and formatting are lost |
| CSV/TSV inspection | Standard parser with explicit dialect/encoding | Python `csv`, DuckDB | No formulas, multiple sheets, types, or formatting metadata |
| Formula recalculation | Compatible calculation engine | Excel or LibreOffice | Engine/version may change results or unsupported functions |
| Rendering | Application export or headless office suite | Excel/LibreOffice PDF or image export | Print areas and fonts affect output |

## Rules

1. Do not infer a dependency exists from a file extension; check it.
2. Use a native or compatible application when macros, pivots, slicers, charts, external links, protection, or exact layout must survive.
3. Use `data_only=False`-style reads to inspect formulas and a separate read for cached values when supported.
4. Treat formula calculation and workbook serialization as separate capabilities.
5. Do not convert XLSM to XLSX if macros must be preserved. Never enable or run macros for inspection.
6. Before recalculating an untrusted workbook, use a low-privilege isolated environment with no secrets or network access and explicitly disable macros/VBA, workbook events, DDE, add-ins, automatic links, data connections, queries, and external-content refresh.
7. Treat cached or recalculated results that depend on disabled macros, events, add-ins, links, or connections as unverified; record the dependency rather than enabling it.
8. Use database/query engines only after defining table grain, types, nulls, and workbook-specific exclusions.
9. If the required isolation or a suitable engine does not exist, report the gap and stop before changing or recalculating the source.
