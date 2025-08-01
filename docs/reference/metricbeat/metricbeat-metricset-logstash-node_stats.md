---
mapped_pages:
  - https://www.elastic.co/guide/en/beats/metricbeat/current/metricbeat-metricset-logstash-node_stats.html
---

% This file is generated! See scripts/docs_collector.py

# Logstash node_stats metricset [metricbeat-metricset-logstash-node_stats]

This is the node metricset of the module Logstash.

This is a default metricset. If the host module is unconfigured, this metricset is enabled by default.

## Fields [_fields]

For a description of each field in the metricset, see the [exported fields](/reference/metricbeat/exported-fields-logstash.md) section.

Here is an example document generated by this metricset:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "event": {
        "dataset": "logstash.node.stats",
        "duration": 115000,
        "module": "logstash"
    },
    "logstash": {
        "cluster": {
           "id": "VUwnkX_lTzCFP9VUoXT1IQ"
        },
        "elasticsearch": {
            "cluster": {
               "id": "VUwnkX_lTzCFP9VUoXT1IQ"
            }
        },
        "node": {
            "stats": {
                "events": {
                    "duration_in_millis": 0,
                    "in": 0,
                    "filtered": 0,
                    "out": 0
                },
                "jvm": {
                    "gc": {
                        "collectors": {
                            "old": {
                                "collection_count": 3,
                                "collection_time_in_millis": 738
                            },
                            "young": {
                                "collection_count": 9,
                                "collection_time_in_millis": 422
                            }
                        }
                    },
                    "mem": {
                        "heap_max_in_bytes": 1037959168,
                        "heap_used_in_bytes": 309034360,
                        "heap_used_percent": 29
                    },
                    "uptime_in_millis": 551958
                },
                "reloads": {
                    "failures": 0,
                    "successes": 0
                },
                "queue": {
                    "events_count": 0
                },
                "process": {
                    "open_file_descriptors": 171,
                    "max_file_descriptors": 1024,
                    "cpu": {
                        "percent": 0
                    }
                },
                "os": {
                    "cpu": {
                        "percent": 0,
                        "load_average": {
                            "15m": 1.69,
                            "1m": 1.51,
                            "5m": 1.69
                        }
                    },
                    "cgroup": {
                        "cpuacct": null,
                        "cpu": {
                            "stat": null,
                            "control_group": ""
                        }
                    }
                },
                "pipelines": [
                    {
                        "id": "main",
                        "hash": "5022893e09c573cc517eef12da3df428d41a45370e168b19031f5b6b0da3db22",
                        "ephemeral_id": "0a6062d1-85e8-4e9b-b943-d80573912692",
                        "events": {
                            "duration_in_millis": 0,
                            "filtered": 0,
                            "in": 0,
                            "out": 0,
                            "queue_push_duration_in_millis": 0
                        },
                        "reloads": {
                            "successes": 0,
                            "failures": 0
                        },
                        "queue": {
                            "events_count": 0,
                            "max_queue_size_in_bytes": 0,
                            "queue_size_in_bytes": 0,
                            "type": "memory"
                        },
                        "vertices": [
                            {
                                "events_out": 0,
                                "id": "293e8492626c637c237bf394279270356589b77d285ea009a555e19977779693",
                                "pipeline_ephemeral_id": "0a6062d1-85e8-4e9b-b943-d80573912692",
                                "queue_push_duration_in_millis": 0
                            },
                            {
                                "cluster_uuid": "VUwnkX_lTzCFP9VUoXT1IQ",
                                "duration_in_millis": 6011,
                                "events_in": 0,
                                "events_out": 0,
                                "id": "942f820402532e034dc5b27a680547732f49dc4b5e48df0475d280eb31382e0d",
                                "pipeline_ephemeral_id": "0a6062d1-85e8-4e9b-b943-d80573912692"
                            }
                        ]
                    }
                ],
                "logstash": {
                    "uuid": "9a1f83e1-52b9-4625-a98a-6aa336f41719",
                    "ephemeral_id": "cead1f28-1e2d-4ef3-9f0b-93c10447e6e7",
                    "name": "7dc1b688baf4",
                    "host": "7dc1b688baf4",
                    "version": "7.12.0",
                    "snapshot": false,
                    "status": "green",
                    "http_address": "0.0.0.0:9600",
                    "pipeline": {
                        "batch_size": 125,
                        "workers": 12
                    }
                },
                "timestamp": "2021-11-03T16:22:10.651Z"
            }
        }
    },
    "metricset": {
        "name": "node_stats",
        "period": 10000
    },
    "service": {
        "address": "172.20.0.3:9600",
        "hostname": "7dc1b688baf4",
        "id": "",
        "name": "logstash",
        "type": "logstash",
        "version": "7.12.0"
    }
}
```
