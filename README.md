# deci

## Development

### Running

```bash
go install ./cmd/deci

SESSION_AUTHENTICATION_KEY="$(openssl rand -base64 64)" \
  SESSION_ENCRYPTION_KEY="$(openssl rand -base64 32)" \
  deci
```

The app will be available at <http://localhost:5556>.
