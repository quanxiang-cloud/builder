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

// Package acceptance implements acceptance tests for a buildpack builder.
package acceptance

const (
	// Buildpack identifiers used to verify that buildpacks were or were not used.
	entrypoint      = "google.config.entrypoint"
	nodeFF          = "openfunction.nodejs.functions-framework"
	nodeNPM         = "openfunction.nodejs.npm"
	nodeYarn        = "openfunction.nodejs.yarn"
)
