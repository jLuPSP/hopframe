package detect

// LLMJudgeFromEnv returns a configured LLMJudge if the operator has
// set HOPFRAME_LLM_JUDGE_URL on the sensor's environment, otherwise
// nil. The lookup is parameterized so tests can drive it without
// mutating the process environment.
//
// Sensors call this during pipeline assembly:
//
//	detectors := []Detector{rs, classifier}
//	if j := LLMJudgeFromEnv(os.Getenv); j != nil {
//	    detectors = append(detectors, j)
//	}
//
// Both mcp-sensor and a2a-sensor share this so the Layer 3 judge is
// uniformly available across protocols.
func LLMJudgeFromEnv(getenv func(string) string) *LLMJudge {
	endpoint := getenv("HOPFRAME_LLM_JUDGE_URL")
	if endpoint == "" {
		return nil
	}
	return &LLMJudge{
		Endpoint: endpoint,
		APIKey:   getenv("HOPFRAME_LLM_JUDGE_API_KEY"),
		Model:    getenv("HOPFRAME_LLM_JUDGE_MODEL"),
	}
}
