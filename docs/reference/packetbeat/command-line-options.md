---
navigation_title: "Command reference"
mapped_pages:
  - https://www.elastic.co/guide/en/beats/packetbeat/current/command-line-options.html
---

# Packetbeat command reference [command-line-options]


Packetbeat provides a command-line interface for starting Packetbeat and performing common tasks, like testing configuration files and loading dashboards.

The command-line also supports [global flags](#global-flags) for controlling global behaviors.

::::{tip}
Use `sudo` to run the following commands if:

* the config file is owned by `root`, or
* Packetbeat is configured to capture data that requires `root` access

::::


Some of the features described here require an Elastic license. For more information, see [https://www.elastic.co/subscriptions](https://www.elastic.co/subscriptions) and [License Management](docs-content://deploy-manage/license/manage-your-license-in-self-managed-cluster.md).

| Commands |  |
| --- | --- |
| [`export`](#export-command) | Exports the configuration, index template, ILM policy, or a dashboard to stdout. |
| [`help`](#help-command) | Shows help for any command. |
| [`keystore`](#keystore-command) | Manages the [secrets keystore](/reference/packetbeat/keystore.md). |
| [`run`](#run-command) | Runs Packetbeat. This command is used by default if you start Packetbeat without specifying a command. |
| [`setup`](#setup-command) | Sets up the initial environment, including the index template, ILM policy and write alias, and {{kib}} dashboards (when available). |
| [`test`](#test-command) | Tests the configuration. |
| [`version`](#version-command) | Shows information about the current version. |

Also see [Global flags](#global-flags).

## `export` command [export-command]

Exports the configuration, index template, ILM policy, or a dashboard to stdout. You can use this command to quickly view your configuration, see the contents of the index template and the ILM policy, or export a dashboard from {{kib}}.

**SYNOPSIS**

```sh
packetbeat export SUBCOMMAND [FLAGS]
```

**SUBCOMMANDS**

**`config`**
:   Exports the current configuration to stdout. If you use the `-c` flag, this command exports the configuration that’s defined in the specified file.

$$$dashboard-subcommand$$$**`dashboard`**
:   Exports a dashboard. You can use this option to store a dashboard on disk in a module and load it automatically. For example, to export the dashboard to a JSON file, run:

    ```shell
    packetbeat export dashboard --id="DASHBOARD_ID" > dashboard.json
    ```

    To find the `DASHBOARD_ID`, look at the URL for the dashboard in {{kib}}. By default, `export dashboard` writes the dashboard to stdout. The example shows how to write the dashboard to a JSON file so that you can import it later. The JSON file will contain the dashboard with all visualizations and searches. You must load the index pattern separately for Packetbeat.

    To load the dashboard, copy the generated `dashboard.json` file into the `kibana/6/dashboard` directory of Packetbeat, and run `packetbeat setup --dashboards` to import the dashboard.

    If {{kib}} is not running on `localhost:5061`, you must also adjust the Packetbeat configuration under `setup.kibana`.


$$$template-subcommand$$$**`template`**
:   Exports the index template to stdout. You can specify the `--es.version` flag to further define what gets exported. Furthermore you can export the template to a file instead of `stdout` by defining a directory via `--dir`.

$$$ilm-policy-subcommand$$$

**`ilm-policy`**
:   Exports the index lifecycle management policy to stdout. You can specify the `--es.version` and a `--dir` to which the policy should be exported as a file rather than exporting to `stdout`.

**FLAGS**

**`--es.version VERSION`**
:   When used with [`template`](#template-subcommand), exports an index template that is compatible with the specified version.  When used with [`ilm-policy`](#ilm-policy-subcommand), exports the ILM policy if the specified ES version is enabled for ILM.

**`-h, --help`**
:   Shows help for the `export` command.

**`--dir DIRNAME`**
:   Define a directory to which the template, pipelines, and ILM policy should be exported to as files instead of printing them to `stdout`.

**`--id DASHBOARD_ID`**
:   When used with [`dashboard`](#dashboard-subcommand), specifies the dashboard ID.

Also see [Global flags](#global-flags).

**EXAMPLES**

```sh subs=true
packetbeat export config
packetbeat export template --es.version {{version.stack}}
packetbeat export dashboard --id="a7b35890-8baa-11e8-9676-ef67484126fb" > dashboard.json
```


## `help` command [help-command]

Shows help for any command. If no command is specified, shows help for the `run` command.

**SYNOPSIS**

```sh
packetbeat help COMMAND_NAME [FLAGS]
```

**`COMMAND_NAME`**
:   Specifies the name of the command to show help for.

**FLAGS**

**`-h, --help`**
:   Shows help for the `help` command.

Also see [Global flags](#global-flags).

**EXAMPLE**

```sh
packetbeat help export
```


## `keystore` command [keystore-command]

Manages the [secrets keystore](/reference/packetbeat/keystore.md).

**SYNOPSIS**

```sh
packetbeat keystore SUBCOMMAND [FLAGS]
```

**SUBCOMMANDS**

**`add KEY`**
:   Adds the specified key to the keystore. Use the `--force` flag to overwrite an existing key. Use the `--stdin` flag to pass the value through `stdin`.

**`create`**
:   Creates a keystore to hold secrets. Use the `--force` flag to overwrite the existing keystore.

**`list`**
:   Lists the keys in the keystore.

**`remove KEY`**
:   Removes the specified key from the keystore.

**FLAGS**

**`--force`**
:   Valid with the `add` and `create` subcommands. When used with `add`, overwrites the specified key. When used with `create`, overwrites the keystore.

**`--stdin`**
:   When used with `add`, uses the stdin as the source of the key’s value.

**`-h, --help`**
:   Shows help for the `keystore` command.

Also see [Global flags](#global-flags).

**EXAMPLES**

```sh
packetbeat keystore create
packetbeat keystore add ES_PWD
packetbeat keystore remove ES_PWD
packetbeat keystore list
```

See [Secrets keystore](/reference/packetbeat/keystore.md) for more examples.


## `run` command [run-command]

Runs Packetbeat. This command is used by default if you start Packetbeat without specifying a command.

**SYNOPSIS**

```sh
packetbeat run [FLAGS]
```

Or:

```sh
packetbeat [FLAGS]
```

**FLAGS**

**`-I, --I FILE`**
:   Reads packet data from the specified file instead of reading packets from the network. This option is useful only for testing Packetbeat.

    ```sh
    packetbeat run -I ~/pcaps/network_traffic.pcap
    ```


**`-N, --N`**
:   Disables publishing for testing purposes. This option disables all outputs except the [File output](/reference/packetbeat/file-output.md).

**`-O, --O`**
:   Read packets one by one by pressing *Enter* after each. This option is useful only for testing Packetbeat.

**`--cpuprofile FILE`**
:   Writes CPU profile data to the specified file. This option is useful for troubleshooting Packetbeat.

**`-devices`**
:   Prints the list of devices that are available for sniffing and then exits.

**`--dump FILE`**
:   Writes all captured packets to the specified file. This option is useful for troubleshooting Packetbeat.

**`-h, --help`**
:   Shows help for the `run` command.

**`--httpprof [HOST]:PORT`**
:   Starts an http server for profiling. This option is useful for troubleshooting and profiling Packetbeat.

**`-l N`**
:   Reads the pcap file `N` number of times. The default is 1. Use this option in combination with the `-I` option. For an infinite loop, use *0*. The `-l` option is useful only for testing Packetbeat.

**`--memprofile FILE`**
:   Writes memory profile data to the specified output file. This option is useful for troubleshooting Packetbeat.

**`--system.hostfs MOUNT_POINT`**
:   Specifies the mount point of the host’s filesystem for use in monitoring a host. This flag is depricated, and an alternate hostfs should be specified via the `hostfs` module config value.

**`-t`**
:   Reads packets from the pcap file as fast as possible without sleeping. Use this option in combination with the `-I` option. The `-t` option is useful only for testing Packetbeat.

Also see [Global flags](#global-flags).

**EXAMPLE**

```sh
packetbeat run -e
```

Or:

```sh
packetbeat -e
```


## `setup` command [setup-command]

Sets up the initial environment, including the index template, ILM policy and write alias, and {{kib}} dashboards (when available)

* The index template ensures that fields are mapped correctly in Elasticsearch. If index lifecycle management is enabled it also ensures that the defined ILM policy and write alias are connected to the indices matching the index template. The ILM policy takes care of the lifecycle of an index, when to do a rollover, when to move an index from the hot phase to the next phase, etc.
* The {{kib}} dashboards make it easier for you to visualize Packetbeat data in {{kib}}.

This command sets up the environment without actually running Packetbeat and ingesting data. Specify optional flags to set up a subset of assets.

**SYNOPSIS**

```sh
packetbeat setup [FLAGS]
```

**FLAGS**

**`--dashboards`**
:   Sets up the {{kib}} dashboards (when available). This option loads the dashboards from the Packetbeat package. For more options, such as loading customized dashboards, see [Importing Existing Beat Dashboards](../../extend/import-dashboards.md).

**`-h, --help`**
:   Shows help for the `setup` command.

**`--index-management`**
:   Sets up components related to Elasticsearch index management including template, ILM policy, and write alias (if supported and configured).

Also see [Global flags](#global-flags).

**EXAMPLES**

```sh
packetbeat setup --dashboards
packetbeat setup --index-management
```


## `test` command [test-command]

Tests the configuration.

**SYNOPSIS**

```sh
packetbeat test SUBCOMMAND [FLAGS]
```

**SUBCOMMANDS**

**`config`**
:   Tests the configuration settings.

**`output`**
:   Tests that Packetbeat can connect to the output by using the current settings.

**FLAGS**

**`-h, --help`**
:   Shows help for the `test` command.

Also see [Global flags](#global-flags).

**EXAMPLE**

```sh
packetbeat test config
```


## `version` command [version-command]

Shows information about the current version.

**SYNOPSIS**

```sh
packetbeat version [FLAGS]
```

**FLAGS**

**`-h, --help`**
:   Shows help for the `version` command.

Also see [Global flags](#global-flags).

**EXAMPLE**

```sh
packetbeat version
```


## Global flags [global-flags]

These global flags are available whenever you run Packetbeat.

**`-E, --E "SETTING_NAME=VALUE"`**
:   Overrides a specific configuration setting. You can specify multiple overrides. For example:

    ```sh
    packetbeat -E "name=mybeat" -E "output.elasticsearch.hosts=['http://myhost:9200']"
    ```

    This setting is applied to the currently running Packetbeat process. The Packetbeat configuration file is not changed.


**`-c, --c FILE`**
:   Specifies the configuration file to use for Packetbeat. The file you specify here is relative to `path.config`. If the `-c` flag is not specified, the default config file, `packetbeat.yml`, is used.

**`-d, --d SELECTORS`**
:   Enables debugging for the specified selectors. For the selectors, you can specify a comma-separated list of components, or you can use `-d "*"` to enable debugging for all components. For example, `-d "publisher"` displays all the publisher-related messages.

**`-e, --e`**
:   Logs to stderr and disables syslog/file output.

**`--environment`**
:   For logging purposes, specifies the environment that Packetbeat is running in. This setting is used to select a default log output when no log output is configured. Supported values are: `systemd`, `container`, `macos_service`, and `windows_service`. If `systemd` or `container` is specified, Packetbeat will log to stdout and stderr by default.

**`--path.config`**
:   Sets the path for configuration files. See the [Directory layout](/reference/packetbeat/directory-layout.md) section for details.

**`--path.data`**
:   Sets the path for data files. See the [Directory layout](/reference/packetbeat/directory-layout.md) section for details.

**`--path.home`**
:   Sets the path for miscellaneous files. See the [Directory layout](/reference/packetbeat/directory-layout.md) section for details.

**`--path.logs`**
:   Sets the path for log files. See the [Directory layout](/reference/packetbeat/directory-layout.md) section for details.

**`--strict.perms`**
:   Sets strict permission checking on configuration files. The default is `--strict.perms=true`. See [Config file ownership and permissions](/reference/libbeat/config-file-permissions.md) for more information.

**`-v, --v`**
:   Logs INFO-level messages.


