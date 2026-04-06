# md

Shared Markdown utilities: YAML frontmatter parsing and HTML rendering with GitHub Flavored Markdown.

## Usage

```go
import "latere.ai/x/pkg/md"

// Untyped frontmatter
front, body, err := md.Parse(src)

// Typed frontmatter
var meta struct{ Title string }
body, err := md.ParseInto(src, &meta)

// GFM to HTML
html, err := md.Render(body)
```

### Functions

- `Parse(src)` — splits into untyped `map[string]any` frontmatter + body
- `ParseInto(src, v)` — decodes frontmatter into a typed struct + body
- `Render(src)` — converts Markdown to HTML (GFM extensions, auto heading IDs)
