---
mapped_pages:
  - https://www.elastic.co/guide/en/beats/metricbeat/current/metricbeat-metricset-docker-cpu.html
---

% This file is generated! See scripts/docs_collector.py

# Docker cpu metricset [metricbeat-metricset-docker-cpu]

The Docker `cpu` metricset collects runtime CPU metrics.

This is a default metricset. If the host module is unconfigured, this metricset is enabled by default.

## Fields [_fields]

For a description of each field in the metricset, see the [exported fields](/reference/metricbeat/exported-fields-docker.md) section.

Here is an example document generated by this metricset:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "container": {
        "id": "7f3ca1f1b2b310362e90f700d2b2e52ebd46ef6ddf10c0704f22b25686c466ab",
        "image": {
            "name": "metricbeat_beat"
        },
        "name": "metricbeat_beat_run_8ba23fa682a6",
        "runtime": "docker"
    },
    "docker": {
        "container": {
            "labels": {
                "com_docker_compose_oneoff": "True",
                "com_docker_compose_project": "metricbeat",
                "com_docker_compose_service": "beat",
                "com_docker_compose_slug": "8ba23fa682a68e2dc082536da22f59eb2d200b3534909fe934807dd5d847424",
                "com_docker_compose_version": "1.24.1"
            }
        },
        "cpu": {
            "core": {
                "0": {
                    "norm": {
                        "pct": 0.00105707400990099
                    },
                    "pct": 0.00845659207920792,
                    "ticks": 7410396430
                },
                "1": {
                    "norm": {
                        "pct": 0.004389216831683168
                    },
                    "pct": 0.035113734653465345,
                    "ticks": 7079258391
                },
                "2": {
                    "norm": {
                        "pct": 0.003178435024752475
                    },
                    "pct": 0.0254274801980198,
                    "ticks": 7140978706
                },
                "3": {
                    "norm": {
                        "pct": 0.0033261257425742574
                    },
                    "pct": 0.02660900594059406,
                    "ticks": 7705738146
                },
                "4": {
                    "norm": {
                        "pct": 0.0016827236386138613
                    },
                    "pct": 0.01346178910891089,
                    "ticks": 8131054429
                },
                "5": {
                    "norm": {
                        "pct": 0.000781541707920792
                    },
                    "pct": 0.006252333663366336,
                    "ticks": 7213899699
                },
                "6": {
                    "norm": {
                        "pct": 0.0005364748762376238
                    },
                    "pct": 0.00429179900990099,
                    "ticks": 7961016581
                },
                "7": {
                    "norm": {
                        "pct": 0.0005079449257425743
                    },
                    "pct": 0.004063559405940594,
                    "ticks": 7946529895
                }
            },
            "kernel": {
                "norm": {
                    "pct": 0.007425742574257425
                },
                "pct": 0.0594059405940594,
                "ticks": 26810000000
            },
            "system": {
                "norm": {
                    "pct": 1
                },
                "pct": 8,
                "ticks": 65836400000000
            },
            "total": {
                "norm": {
                    "pct": 0.015459536757425743
                },
                "pct": 0.12367629405940594
            },
            "user": {
                "norm": {
                    "pct": 0.006188118811881188
                },
                "pct": 0.04950495049504951,
                "ticks": 35720000000
            }
        }
    },
    "event": {
        "dataset": "docker.cpu",
        "duration": 115000,
        "module": "docker"
    },
    "metricset": {
        "name": "cpu",
        "period": 10000
    },
    "service": {
        "address": "/var/run/docker.sock",
        "type": "docker"
    }
}
```
