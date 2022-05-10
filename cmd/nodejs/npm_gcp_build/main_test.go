// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"testing"

	gcp "github.com/GoogleCloudPlatform/buildpacks/pkg/gcpbuildpack"
)

func TestDetect(t *testing.T) {
	testCases := []struct {
		name  string
		files map[string]string
		want  int
	}{
		{
			name: "without package",
			files: map[string]string{
				"index.js": "",
			},
			want: 100,
		},
		{
			name: "with package without gcp_build",
			files: map[string]string{
				"index.js":     "",
				"package.json": "{}",
			},
			want: 100,
		},
		{
			name: "with package syntax error",
			files: map[string]string{
				"index.js":     "",
				"package.json": "{",
			},
			want: 1,
		},
		{
			name: "with package with gcp_build",
			files: map[string]string{
				"index.ts": "",
				"package.json": `
{
  "scripts": {
    "gcp-build": "tsc -p ."
  }
}
`,
			},
			want: 0,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gcp.TestDetect(t, detectFn, tc.name, tc.files, []string{}, tc.want)
		})
	}
}
