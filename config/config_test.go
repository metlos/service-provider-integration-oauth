// Copyright (c) 2021 Red Hat, Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRead(t *testing.T) {
	secretFile, err := os.CreateTemp(os.TempDir(), "testSecret")
	assert.NoError(t, err)
	defer os.Remove(secretFile.Name())

	assert.NoError(t, ioutil.WriteFile(secretFile.Name(), []byte("secret"), fs.ModeExclusive))

	absPath, err := filepath.Abs(secretFile.Name())
	assert.NoError(t, err)

	yaml := `
sharedSecretFile: ` + absPath + `
serviceProviders:
- type: GitHub
  clientId: "123"
  clientSecret: "42"
  redirectUrl: https://localhost:8080/github/callback
- type: Quay
  clientId: "456"
  clientSecret: "54"
  redirectUrl: https://localhost:8080/quay/callback
`

	cfg, err := ReadFrom(strings.NewReader(yaml))
	assert.NoError(t, err)

	assert.Equal(t, []byte("secret"), cfg.SharedSecret)
}
