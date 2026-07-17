# Frontend Design System

Use `page-header`, `page-section`, `Panel`, `table-scroll`, `record-card`, `compact-stack`, `toolbar-row`, `filter-grid`, `pagination-row`, and the shared loading/error/empty components. Status uses the shared pill/badge tones; metrics use the Ops widgets instead of copied grids.

Long IDs and hashes must wrap or remain inside `table-scroll`. Payload previews have a bounded height and only show redacted summaries. New page code must not copy large inline style objects: promote repeated layout and visual rules to `index.css` or a reusable component.
