package detect

import "testing"

func TestLLMJudgeFromEnvUnsetReturnsNil(t *testing.T) {
	if got := LLMJudgeFromEnv(func(string) string { return "" }); got != nil {
		t.Errorf("expected nil when HOPFRAME_LLM_JUDGE_URL is empty, got %+v", got)
	}
}

func TestLLMJudgeFromEnvAllFields(t *testing.T) {
	env := map[string]string{
		"HOPFRAME_LLM_JUDGE_URL":     "https://litellm.internal:4000/v1/chat/completions",
		"HOPFRAME_LLM_JUDGE_API_KEY": "sk-test",
		"HOPFRAME_LLM_JUDGE_MODEL":   "claude-3-5-haiku-latest",
	}
	got := LLMJudgeFromEnv(func(k string) string { return env[k] })
	if got == nil {
		t.Fatal("expected a judge, got nil")
	}
	if got.Endpoint != env["HOPFRAME_LLM_JUDGE_URL"] {
		t.Errorf("endpoint = %q", got.Endpoint)
	}
	if got.APIKey != "sk-test" {
		t.Errorf("api key not propagated")
	}
	if got.Model != "claude-3-5-haiku-latest" {
		t.Errorf("model = %q", got.Model)
	}
}

func TestLLMJudgeFromEnvURLOnlyIsValid(t *testing.T) {
	// API key and model are optional. Many self-hosted backends (vllm,
	// ollama, plain Anthropic compat) need only the URL.
	env := map[string]string{
		"HOPFRAME_LLM_JUDGE_URL": "http://localhost:11434/v1/chat/completions",
	}
	got := LLMJudgeFromEnv(func(k string) string { return env[k] })
	if got == nil {
		t.Fatal("expected a judge with just URL")
	}
	if got.APIKey != "" || got.Model != "" {
		t.Errorf("unset api key/model should remain empty: %+v", got)
	}
}
