# ZF Tools visual system

## Direction

A concise engineering workspace. Entry screens use a deep navy canvas and white surfaces. Working screens use a pale blue canvas with consistent white forms. Use restrained borders, precise alignment and purposeful spacing. Do not add promotional headings, fake system indicators, oversized imagery or long supplier explanations.

## Foundations

- Font: Arial, sans-serif throughout, including controls, results and metadata.
- Canvas: #f4f7fb; entry canvas: #071a33.
- Surface: #ffffff; ink: #102a43; muted text: #52677e.
- Official ZF blue: #0057b7; borders: #dbe4ee.
- Controls: 8px radius and at least 44px height; panels: 12–18px radius.
- Functional headings: 27–38px; body: 13–16px; labels: 12–13px.

## Layout

The homepage has two equally sized tool entries within a 1008px content width. Login uses one centered form, at most 460px wide. Authenticated screens have a 1124px content width; forms and supporting notes use a 2:1 grid, collapsing below 900px. Administration uses equal columns. Mobile uses one column with 20px gutters.

## Identity

Use the original official ZF SVG, downloaded without modification from https://www.zf.com/master/media/toolbox/assets/img/ZF_logo_STD_Blue_3C.svg. Do not imitate or redraw the logo. Source file: app/wwwroot/images/zf-logo.svg.

## Interaction and accessibility

Keep all copy in English. Every input has a visible label, focus indication and clear validation. Mark active navigation, support keyboard operation and respect reduced motion. Transitions take 160–200ms; only tool selection cards use a slight hover lift. No continuous decorative animation. Preserve all supplier API mappings and permission boundaries.

## Validation

Validate rendered desktop and mobile entry screens, login behavior, workspace forms, navigation, administration and history. Inspect Arial, official logo loading, overflow, English copy and browser console health. Use Playwright when the Browser plugin is unavailable. Store QA screenshots outside committed source.
