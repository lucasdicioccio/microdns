# The microdns website

A [Kitchen-Sink](https://kitchensink-tech.github.io/) site, the same shape as
[agents-exe's](https://github.com/lucasdicioccio/agents-exe/tree/main/website).
A page is a `.cmark` file split into *sections* (content, metadata, CSS);
Kitchen-Sink assembles them into a static site.

- `src/` — the source: `kitchen-sink.json` (site config), the hand-written
  pages (`index.cmark`, `getting-started.cmark`, `dynamic-registration.cmark`,
  `microzone-files.cmark`, `llms.txt`), the layout pages (`topics`,
  `hashtags`, `glossary`) and the CSS/JS they reference.
- `scripts/` — `publish.sh` produces the site for publication.
- `www/` — the dev server's output directory (gitignored). The published
  site is produced into the repository's `docs/`, which GitHub Pages serves
  from `main` (`scripts/publish.sh`).

The pages are drawn from the repository's `README.md`, by hand: when the
README changes, update the matching page.

## Diagrams

Diagrams are [graphviz](https://graphviz.org/) `.dot` files in `src/`
(`design.dot`). `kitchen-sink produce`/`serve` renders each to
`/gen/images/<name>.dot.png`, which the pages reference. The PNGs are produce
output; the `.dot` files are the source.

**Producing the site therefore requires `graphviz` (`dot`) on the `PATH`**,
on top of `kitchen-sink`.

## Preview

```sh
mkdir -p website/www
kitchen-sink serve --srcDir website/src --outDir website/www --servMode DEV --httpPort 7655
```

Then open http://localhost:7655/. The dev server rebuilds on file changes
under `src/`.

## Publish

Produce the site into `docs/` and commit it:

```sh
./website/scripts/publish.sh    # kitchen-sink produce --srcDir website/src --outDir docs
```

GitHub Pages must be configured once, in the repository settings, to deploy
from the `main` branch and the `/docs` folder.

`kitchen-sink.json`'s `basePath` is `/microdns`, so every absolute `/x.html`
link and every CSS import (through `$ctx.pathPrefix`) resolves under
`https://lucasdicioccio.github.io/microdns/`.

## Learn more

- [Features](https://kitchensink-tech.github.io/features.html) — what
  Kitchen-Sink can do.
- [Sections](https://kitchensink-tech.github.io/sections.html) — the
  section format used inside each `.cmark` file.
