// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//go:build integration

package cfgfile

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	conf "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp/logptest"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

func TestReloader(t *testing.T) {
	// Create random temp directory
	dir, err := os.MkdirTemp("", "libbeat-reloader")
	defer func() {
		if t.Failed() {
			t.Logf("test failed, temp dir '%s' was kept", dir)
			return
		}
		os.RemoveAll(dir)
	}()

	if err != nil {
		t.Fatalf("could not create temp dir: %s", err)
	}
	glob := filepath.Join(dir, "*.yml")

	config := conf.MustNewConfigFrom(mapstr.M{
		"path": glob,
		"reload": mapstr.M{
			"period":  "1s",
			"enabled": true,
		},
	})
	// config.C{}

	reloader := NewReloader(logptest.NewTestingLogger(t, "cfgfile-test.reload"), nil, config)
	retryCount := 10

	go reloader.Run(nil)
	defer reloader.Stop()

	// wait until configScans >= 2 (which should happen after ~1 second)
	for i := 0; i < retryCount; i++ {
		if configScans.Get() >= 2 {
			break
		}
		// time interval is slightly more than a second so we don't slightly
		// undershoot the first iteration and wait a whole extra second.
		time.Sleep(1100 * time.Millisecond)
	}
	if configScans.Get() < 2 {
		assert.Fail(t, "Timed out waiting for configScans >= 2")
	}

	// The first scan should cause a reload, but additional ones should not,
	// so configReloads should still be 1.
	require.Equalf(
		t,
		int64(1),
		configReloads.Get(),
		"config reload should be called once, but it was called %d times",
		configReloads.Get(),
	)

	// Write a file to the reloader path to trigger a real reload
	content := []byte("test\n")
	err = os.WriteFile(filepath.Join(dir, "config1.yml"), content, 0644)
	assert.NoError(t, err)

	// Wait for the number of scans to increase at least twice. This is somewhat
	// pedantic, but if we just wait for the next scan, it's possible to wake up
	// during the brief interval after configScans is updated but before
	// configReloads is, giving a false negative. Waiting two iterations
	// guarantees that the change from the first one has taken effect.
	targetScans := configScans.Get() + 2
	for i := 0; i < retryCount; i++ {
		time.Sleep(time.Second)
		if configScans.Get() >= targetScans {
			break
		}
	}
	if configScans.Get() < targetScans {
		assert.Fail(t,
			fmt.Sprintf("Timed out waiting for configScans >= %d", targetScans))
	}

	// The number of reloads should now have increased. It would be nicer to
	// check if the value is exactly 2, but we can't guarantee this: the glob
	// watcher includes an extra 1-second margin around the real modification
	// time, so changes that fall too close to a scan interval can be detected
	// twice.
	if configReloads.Get() < 2 {
		assert.Fail(t,
			fmt.Sprintf(
				"Reloader performed %d scans but only reloaded once",
				configScans.Get()))
	}
}
