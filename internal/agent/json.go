package agent

import (
	"encoding/json"
	"fmt"
)

func unmarshal(raw []byte, v any) error {
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("decode agent message: %w", err)
	}
	return nil
}
