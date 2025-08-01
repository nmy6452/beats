// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !aix

package add_cloudfoundry_metadata

import (
	"fmt"

	"github.com/gofrs/uuid/v5"

	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/processors"
	"github.com/elastic/beats/v7/x-pack/libbeat/common/cloudfoundry"
	conf "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

const (
	processorName = "add_cloudfoundry_metadata"
)

func init() {
	processors.RegisterPlugin(processorName, New)
}

type addCloudFoundryMetadata struct {
	log    *logp.Logger
	client cloudfoundry.Client
}

const selector = "add_cloudfoundry_metadata"

// New constructs a new add_cloudfoundry_metadata processor.
func New(cfg *conf.C, log *logp.Logger) (beat.Processor, error) {
	var config cloudfoundry.Config

	// ShardID is required in cloudfoundry config to consume from the firehose,
	// but not for metadata requests, randomly generate one and use it.
	config.ShardID = uuid.Must(uuid.NewV4()).String()

	if err := cfg.Unpack(&config); err != nil {
		return nil, fmt.Errorf("fail to unpack the %v configuration: %w", processorName, err)
	}

	log = logp.NewLogger(selector)
	hub := cloudfoundry.NewHub(&config, "add_cloudfoundry_metadata", log)
	client, err := hub.ClientWithCache()
	if err != nil {
		return nil, fmt.Errorf("%s: creating cloudfoundry client: %w", processorName, err)
	}

	return &addCloudFoundryMetadata{
		log:    log,
		client: client,
	}, nil
}

func (d *addCloudFoundryMetadata) Run(event *beat.Event) (*beat.Event, error) {
	if d.client == nil {
		return event, nil
	}
	valI, err := event.GetValue("cloudfoundry.app.id")
	if err != nil {
		//nolint:nilerr // doesn't have the required cloudfoundry.app.id value to add more information
		return event, nil
	}
	val, _ := valI.(string)
	if val == "" {
		// wrong type or not set
		return event, nil
	}
	if hasMetadataFields(event) {
		// nothing to do, fields already present
		return event, nil
	}
	app, err := d.client.GetAppByGuid(val)
	if err != nil {
		d.log.Debugf("failed to get application info for GUID(%s): %v", val, err)
		return event, nil
	}
	event.Fields.DeepUpdate(mapstr.M{
		"cloudfoundry": mapstr.M{
			"app": mapstr.M{
				"name": app.Name,
			},
			"space": mapstr.M{
				"id":   app.SpaceGuid,
				"name": app.SpaceName,
			},
			"org": mapstr.M{
				"id":   app.OrgGuid,
				"name": app.OrgName,
			},
		},
	})
	return event, nil
}

// String returns this processor name.
func (d *addCloudFoundryMetadata) String() string {
	return processorName
}

// Close closes the underlying client and releases its resources.
func (d *addCloudFoundryMetadata) Close() error {
	if d.client == nil {
		return nil
	}
	err := d.client.Close()
	if err != nil {
		return fmt.Errorf("closing client: %w", err)
	}
	return nil
}

var metadataFields = []string{
	"cloudfoundry.app.id",
	"cloudfoundry.app.name",
	"cloudfoundry.space.id",
	"cloudfoundry.space.name",
	"cloudfoundry.org.id",
	"cloudfoundry.org.name",
}

func hasMetadataFields(event *beat.Event) bool {
	for _, name := range metadataFields {
		if value, err := event.GetValue(name); value == "" || err != nil {
			return false
		}
	}
	return true
}
