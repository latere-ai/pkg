package luxsdk

import (
	"testing"
)

// The environment fallback fills only what the caller left unset. Every existing call site
// passes an explicit base and credential, so if the environment could
// override either, setting LUX_BASE_URL in a shell would silently
// redirect programs that never opted in.
func TestNewEnvFallbackPrecedence(t *testing.T) {
	const (
		envBase = "https://env.example"
		envKey  = "lux_from_env"
		argBase = "https://arg.example"
		argKey  = "lux_from_arg"
	)

	cases := []struct {
		name     string
		setBase  string
		setKey   string
		argBase  string
		opts     []Option
		wantBase string
		wantKey  string
	}{
		{
			name:     "explicit beats env",
			setBase:  envBase,
			setKey:   envKey,
			argBase:  argBase,
			opts:     []Option{WithAPIKey(argKey)},
			wantBase: argBase,
			wantKey:  argKey,
		},
		{
			name:     "env fills what was omitted",
			setBase:  envBase,
			setKey:   envKey,
			wantBase: envBase,
			wantKey:  envKey,
		},
		{
			name:     "default fills an unset base",
			setKey:   envKey,
			wantBase: DefaultBaseURL,
			wantKey:  envKey,
		},
		{
			// An unset credential must stay unset: defaulting to
			// unauthenticated would turn a misspelled variable into a
			// confusing 401 rather than an obvious one.
			name:     "missing credential stays empty",
			setBase:  envBase,
			wantBase: envBase,
			wantKey:  "",
		},
		{
			// A TokenSource is a credential, so the env key must not be
			// read at all; otherwise a stale export would shadow a live
			// token provider on every call.
			name:     "token source suppresses the env key",
			setKey:   envKey,
			opts:     []Option{WithTokenSource(staticTokens{token: "live"})},
			wantBase: DefaultBaseURL,
			wantKey:  "",
		},
		{
			// Trailing slashes are trimmed on the env path too, or every
			// request would carry a doubled separator.
			name:     "env base is trimmed",
			setBase:  envBase + "/",
			wantBase: envBase,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvBaseURL, tc.setBase)
			t.Setenv(EnvAPIKey, tc.setKey)

			c := New(tc.argBase, tc.opts...)
			if c.baseURL != tc.wantBase {
				t.Errorf("baseURL = %q, want %q", c.baseURL, tc.wantBase)
			}
			if c.apiKey != tc.wantKey {
				t.Errorf("apiKey = %q, want %q", c.apiKey, tc.wantKey)
			}
		})
	}
}
