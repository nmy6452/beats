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

package actions

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"

	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/processors"
	"github.com/elastic/beats/v7/libbeat/processors/checks"
	conf "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

type decompressGzipField struct {
	config decompressGzipFieldConfig
	log    *logp.Logger
}

type decompressGzipFieldConfig struct {
	Field         fromTo `config:"field"`
	IgnoreMissing bool   `config:"ignore_missing"`
	FailOnError   bool   `config:"fail_on_error"`
}

func init() {
	processors.RegisterPlugin("decompress_gzip_field",
		checks.ConfigChecked(NewDecompressGzipFields,
			checks.RequireFields("field"),
			checks.AllowedFields("field", "ignore_missing", "overwrite_keys", "overwrite_keys", "fail_on_error")))
}

// NewDecompressGzipFields construct a new decompress_gzip_fields processor.
func NewDecompressGzipFields(c *conf.C, log *logp.Logger) (beat.Processor, error) {
	config := decompressGzipFieldConfig{
		IgnoreMissing: false,
		FailOnError:   true,
	}

	err := c.Unpack(&config)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack the decompress_gzip_fields configuration: %w", err)
	}

	return &decompressGzipField{config: config, log: log.Named("decompress_gzip_field")}, nil
}

// Run applies the decompress_gzip_fields processor to an event.
func (f *decompressGzipField) Run(event *beat.Event) (*beat.Event, error) {
	var backup *beat.Event
	if f.config.FailOnError {
		backup = event.Clone()
	}

	err := f.decompressGzipField(event)
	if err != nil {
		errMsg := fmt.Errorf("Failed to decompress field in decompress_gzip_field processor: %w", err)
		f.log.Debugw(errMsg.Error(), logp.EventType, logp.TypeKey)

		if f.config.FailOnError {
			event = backup
			_, _ = event.PutValue("error.message", errMsg.Error())
			return event, err
		}
	}
	return event, nil
}

func (f *decompressGzipField) decompressGzipField(event *beat.Event) error {
	data, err := event.GetValue(f.config.Field.From)
	if err != nil {
		if f.config.IgnoreMissing && errors.Is(err, mapstr.ErrKeyNotFound) {
			return nil
		}
		return fmt.Errorf("could not fetch value for key: %s, Error: %w", f.config.Field.From, err)
	}

	var inBuf *bytes.Buffer
	switch txt := data.(type) {
	case []byte:
		inBuf = bytes.NewBuffer(txt)
	case string:
		inBuf = bytes.NewBufferString(txt)
	default:
		return fmt.Errorf("cannot decompress type %+v", txt)
	}

	r, err := gzip.NewReader(inBuf)
	if err != nil {
		return fmt.Errorf("error decompressing field %s: %w", f.config.Field.From, err)
	}

	var outBuf bytes.Buffer
	//nolint:gosec // This is potentially vulnerable to "decompression bomb" DoS but that is inherent to this processor.
	_, err = io.Copy(&outBuf, r)
	if err != nil {
		r.Close()
		return fmt.Errorf("error while decompressing field: %w", err)
	}

	err = r.Close()
	if err != nil {
		return fmt.Errorf("error closing gzip reader: %w", err)
	}

	if _, err = event.PutValue(f.config.Field.To, outBuf.String()); err != nil {
		return fmt.Errorf("could not put decompressed data: %w", err)
	}
	return nil
}

// String returns a string representation of this processor.
func (f decompressGzipField) String() string {
	return fmt.Sprintf("decompress_gzip_fields=%+v", f.config.Field)
}
