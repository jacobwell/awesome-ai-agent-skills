# PDF verification checklist

Select checks that match the requested operation and state which were not possible.

## Structural

- Input and output paths, hashes, and byte sizes recorded.
- Output opens in an independent parser/viewer without repair warnings.
- PDF header, EOF, cross-reference/page tree, page count, order, labels, size, and rotation are expected.
- Encryption, permissions, metadata, attachments, bookmarks, links, forms, annotations, layers, and signatures are preserved or intentionally changed.
- No unexpected JavaScript, automatic action, launch action, rich media, or embedded file was introduced.
- For untrusted parsing/rendering, the exact sandbox/tool configuration disabled network, JavaScript/actions, form submission, attachment activation/extraction, rich media, and host integrations; otherwise parsing/rendering was not performed.

## Content

- Text that should remain unchanged compares page-by-page after normalization.
- OCR output is checked against page images, especially names, dates, amounts, identifiers, and negation.
- Tables reconcile row/column counts and totals to the rendered source.
- Images are present, correctly cropped, and sufficiently resolved.
- Page mapping is explicit for merge, split, reorder, delete, or rotation operations.

## Visual

- Every changed page is rendered and inspected.
- Representative unchanged pages include the first, last, dense, image-heavy, and unusual-size pages.
- No clipping, overlap, font substitution, missing glyph, broken link appearance, blank page, shifted table, or wrong rotation is visible.
- Print margins, bleed, color, and resolution are checked when the output is for printing.

## Operation-specific

- **Redaction:** underlying text/images are absent under independent extraction/object inspection; metadata, comments, thumbnails, attachments, and hidden layers are addressed; the output is a full non-incremental rewrite with no retained prior revisions or original/redacted objects. Multiple revision/EOF evidence is treated as a failed redaction check until explained by independent inspection.
- **OCR:** the image layer remains if required; hidden text aligns adequately; confidence limitations are reported.
- **Compression:** measured size reduction is paired with visual and searchability checks.
- **Forms:** values persist in the intended viewer; flattened and editable copies are labeled.
- **Signatures:** signer identity, time, certificate chain, covered byte range, and validation status are checked by an appropriate validator.
- **Accessibility/archival:** a dedicated validator report is retained; visual inspection alone is not sufficient.
