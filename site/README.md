# Documentation site

Run these commands from the repository root with Zola 0.23.6.

```sh
zola --root site serve
zola --root site check
zola --root site build
```

Edit guides in `site/content/guides/`. Each guide has a title, a description for search and link previews, and a weight for navigation order. Link to another guide with Zola’s content path, for example `[Device identity](@/guides/security.md)`.

The production build writes static HTML to `site/public/`. The Pages workflow checks internal links on pull requests and deploys changes to the site on `main`.
