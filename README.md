# pkg

Platform-wide Go packages for [Latere AI](https://latere.ai).

## Packages

| Package | Description |
|---|---|
| [`md`](md/) | YAML frontmatter parsing and GFM-to-HTML rendering |
| [`otel`](otel/) | OpenTelemetry tracing, metrics, and HTTP instrumentation |

## Development

```bash
make test       # run tests
make race       # run tests with race detector
make fuzz       # run fuzz tests (30s)
make cover      # run tests with coverage (95% minimum enforced)
make cover-html # open coverage report in browser
```

## License

[MIT](LICENSE)
