// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
package operator

import "encoding/json"

func jsonValidImpl(b []byte) bool {
	var v interface{}
	return json.Unmarshal(b, &v) == nil
}
