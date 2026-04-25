package main

type Agent struct {
	AllowedHosts []string
	EnvVars      []string
	Mounts       []string
}

var agents = map[string]Agent{
	"claude": {
		AllowedHosts: []string{"api.anthropic.com", "platform.claude.com", "console.anthropic.com"},
		EnvVars:      []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL"},
		Mounts:       []string{"~/.claude", "~/.claude.json"},
	},
	"codex": {
		// chatgpt.com is the streaming endpoint when codex is authenticated via
		// ChatGPT login (the default for most users); api.openai.com is the API-key
		// path; auth.openai.com handles the OAuth flow for ChatGPT login.
		AllowedHosts: []string{"api.openai.com", "chatgpt.com", "auth.openai.com"},
		EnvVars:      []string{"OPENAI_API_KEY", "OPENAI_BASE_URL"},
		Mounts:       []string{"~/.codex", "~/.config/codex"},
	},
	"aider": {
		AllowedHosts: []string{"api.openai.com", "api.anthropic.com"},
		EnvVars:      []string{"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_BASE_URL", "ANTHROPIC_BASE_URL"},
		Mounts:       []string{"~/.aider.conf.yml"},
	},
	"opencode": {
		AllowedHosts: []string{"api.anthropic.com", "api.openai.com"},
		EnvVars:      []string{"OPENAI_API_KEY", "ANTHROPIC_API_KEY"},
		Mounts:       []string{"~/.config/opencode"},
	},
}

func knownAgents() []string {
	names := make([]string, 0, len(agents))
	for name := range agents {
		names = append(names, name)
	}
	return names
}
