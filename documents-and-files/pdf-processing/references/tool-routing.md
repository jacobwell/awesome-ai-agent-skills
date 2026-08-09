# PDF tool routing

Read this reference after inventorying the environment. Choose by capability and test on a copy; tool availability and behavior vary by version.

| Need | Suitable capability | Common local options when present | Required check |
|---|---|---|---|
| Structural inventory | Read metadata, page tree, encryption, objects | `qpdf`, `pdfinfo`, pypdf | Re-open and compare page count |
| Text extraction | Preserve page association and layout hints | `pdftotext`, PyMuPDF, pdfplumber | Compare representative pages visually |
| OCR | Render pages and add/search a text layer | OCRmyPDF, Tesseract with a PDF pipeline | Check language, confidence, names, numbers |
| Render pages | Deterministic page rasterization | Poppler, MuPDF, Ghostscript | Inspect changed pages at readable scale |
| Merge/split/rotate | Rewrite page trees without rasterizing | `qpdf`, pypdf, MuPDF | Confirm order, labels, bookmarks, forms |
| Tables | Geometry-aware extraction | pdfplumber, Camelot/Tabula when appropriate | Reconcile row/column totals to the page |
| Create PDF | Layout engine with font embedding | ReportLab, browser print, office export | Render and check fonts, links, pagination |
| True redaction | Remove underlying page objects | PyMuPDF or another redaction-capable editor | Search objects/text with a second method |
| Forms | Read/write AcroForm fields | pypdf, dedicated PDF editor | Open in intended viewer and inspect values |
| Repair/linearize | Validate and rewrite malformed structure | `qpdf`, Ghostscript as a controlled fallback | Compare content; rewriting can discard features |
| PDF/A or PDF/UA | Dedicated conformance validator | veraPDF or equivalent | Retain machine-readable validation report |

## Routing rules

1. Prefer existing workspace tools and user-approved applications.
2. Do not assume a Python package, command-line tool, GUI, font, or OCR language pack is installed.
3. Avoid office-suite round trips for PDFs that must retain exact geometry, forms, layers, or signatures.
4. Avoid rasterizing text PDFs unless the user accepts loss of searchability, accessibility, vectors, links, and signatures.
5. Use at least two independent methods for high-stakes redaction or document integrity checks.
6. Record exact tool versions for repeatability.
7. For untrusted files, use a disposable low-privilege sandbox with no secrets/network, read-only input, isolated output, resource/time limits, and disabled JavaScript/actions/form submission/external fetches/attachment activation/rich media/host integrations.
8. Verify the exact parser/renderer exposes or inherently enforces those controls. If it does not, stop after raw-byte inspection; availability alone is not a safe routing decision.
9. For redaction, select a tool and save mode that performs a complete non-incremental rewrite with garbage/object cleanup; reject an output that retains prior revisions.

If no suitable tool exists, stop before changing the file. Explain the capability gap, expected installation, privacy implications, and a non-destructive fallback.
