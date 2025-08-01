---
mapped_pages:
  - https://www.elastic.co/guide/en/beats/metricbeat/current/metricbeat-module-redis.html
---

% This file is generated! See scripts/docs_collector.py

# Redis module [metricbeat-module-redis]

:::::{admonition} Prefer to use {{agent}} for this use case?
Refer to the [Elastic Integrations documentation](integration-docs://reference/redis/index.md).

::::{dropdown} Learn more
{{agent}} is a single, unified way to add monitoring for logs, metrics, and other types of data to a host. It can also protect hosts from security threats, query data from operating systems, forward data from remote services or hardware, and more. Refer to the documentation for a detailed [comparison of {{beats}} and {{agent}}](docs-content://reference/fleet/index.md).

::::


:::::


This module periodically fetches metrics from [Redis](http://redis.io/) servers.

The defaut metricsets are `info` and `keyspace`.


## Module-specific configuration notes [_module_specific_configuration_notes_18]

The Redis module has these additional config options:

**`hosts`**
:   URLs that are used to connect to Redis. URL format: redis://[:password@]host[:port][/db-number][?option=value] redis://HOST[:PORT][?password=PASSWORD[&db=DATABASE]]

**`password`**
:   The password to authenticate, by default it’s empty.

**`idle_timeout`**
:   The duration to remain idle before closing connections. If the value is zero, then idle connections are not closed. The default value is 2 times the module period to allow a connection to be reused across fetches. The `idle_timeout` should be set to less than the server’s connection timeout.

**`network`**
:   The network type to be used for the Redis connection. The default value is `tcp`.

**`maxconn`**
:   The maximum number of concurrent connections to Redis. The default value is 10.


## Compatibility [_compatibility_45]

The redis metricsets `info`, `key` and `keyspace` are compatible with all distributions of Redis (OSS and enterprise). They were tested with Redis 3.2.12, 4.0.11, 5.0-rc4 and 6.2.6, and are expected to work with all versions >= 3.0.


## Example configuration [_example_configuration]

The Redis module supports the standard configuration options that are described in [Modules](/reference/metricbeat/configuration-metricbeat.md). Here is an example configuration:

```yaml
metricbeat.modules:
- module: redis
  metricsets: ["info", "keyspace"]
  enabled: true
  period: 10s

  # Redis hosts
  hosts: ["127.0.0.1:6379"]

  # Timeout after which time a metricset should return an error
  # Timeout is by default defined as period, as a fetch of a metricset
  # should never take longer then period, as otherwise calls can pile up.
  #timeout: 1s

  # Optional fields to be added to each event
  #fields:
  #  datacenter: west

  # Network type to be used for redis connection. Default: tcp
  #network: tcp

  # Max number of concurrent connections. Default: 10
  #maxconn: 10

  # Filters can be used to reduce the number of fields sent.
  #processors:
  #  - include_fields:
  #      fields: ["beat", "metricset", "redis.info.stats"]

  # Redis AUTH username (Redis 6.0+). Empty by default.
  #username: user

  # Redis AUTH password. Empty by default.
  #password: pass

  # Optional SSL/TLS (Redis 6.0+). By default is false.
  #ssl.enabled: true

  # List of root certificates for SSL/TLS server verification
  #ssl.certificate_authorities: ["/etc/pki/root/ca.crt"]

  # Certificate for SSL/TLS client authentication
  #ssl.certificate: "/etc/pki/client/cert.crt"

  # Client certificate key file
  #ssl.key: "/etc/pki/client/cert.key"
```


## Metricsets [_metricsets]

The following metricsets are available:

* [info](/reference/metricbeat/metricbeat-metricset-redis-info.md)
* [key](/reference/metricbeat/metricbeat-metricset-redis-key.md)
* [keyspace](/reference/metricbeat/metricbeat-metricset-redis-keyspace.md)
