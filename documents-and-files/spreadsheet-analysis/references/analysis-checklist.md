# Spreadsheet analysis checklist

## Structure and semantics

- Record file hash, format, workbook date system, calculation mode, locale, and last calculation indicators.
- Inventory visible/hidden sheets, named ranges, tables, filters, merged cells, validations, comments, links, queries, macros, charts, pivots, and protection.
- Define row grain, primary key, allowed duplicates, units, signs, currencies, period, and source of truth.
- Distinguish blank, zero, empty string, `NA`, suppressed, not applicable, and formula error.

## Data quality

- Row/column counts and duplicate headers/keys.
- Missingness by field and by relevant segment.
- Type drift, mixed date systems, locale-specific numbers, and IDs coerced to numeric/scientific notation.
- Invalid categories, whitespace, casing, encoding, and delimiter issues.
- Date gaps/overlaps, impossible dates, future dates, and time-zone boundaries.
- Outliers, negative values, unit changes, stale refresh dates, and hidden exclusions.

## Formula integrity

- Formula count and error count by sheet.
- Formula consistency across contiguous regions.
- Hard-coded values inside formula regions.
- Relative/absolute reference drift, incomplete ranges, and off-by-one totals.
- Circular references, volatile functions, array/spill behavior, error suppression, external references, DDE, and web functions.
- Cached values compared with a real recalculation when available.

## Joins and aggregation

- Cardinality checked before every join; unmatched and multiplied rows reported.
- Grouping keys and filters documented.
- Subtotals are not double-counted with detail rows.
- Percentages use the stated denominator; weighted averages use explicit weights.
- Currency conversion rates, effective dates, and rounding rules are recorded.

## Verification

- Key totals reconcile to an independent control or variance is explained.
- A sample of source rows traces through each transformation to final output.
- Re-run from the preserved source produces the same result.
- Saved output re-opens without repair warnings and, if relevant, recalculates.
- For untrusted recalculation, macros/VBA, workbook events, DDE, add-ins, network access, external links, connections, queries, and automatic refresh were demonstrably disabled.
- Results dependent on disabled macros, events, add-ins, links, or connections are labeled unverified rather than accepted from cached values.
- Changed sheets and dashboards are visually inspected in the intended viewer.
- Findings distinguish facts, assumptions, estimates, cached values, and unresolved gaps.
