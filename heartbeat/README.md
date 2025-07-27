# Heartbeat

Welcome to Heartbeat.

This is a beat for testing service availability using PING based on ICMP, TCP or higher level protocols.

Ensure that this folder is at the following location:
`${GOPATH}/src/github.com/elastic/beats`

## Template Variables

Heartbeat supports dynamic template variables in HTTP monitor configurations. These variables can be used in request bodies, headers, and host configurations to generate dynamic values at runtime.

### Available Template Variables


| Variable | Description | Format Example | Output Example |
|----------|-------------|----------------|----------------|
| `{{$date}}` | Current date/time (YYYY, MM, DD, HH, mm, ss) | `{{$date\|YYYY-MM-DD}}` | `2024-01-15` |
| `{{$guid}}` | Random GUID (UUID v4) | `{{$guid}}` | `550e8400-e29b-41d4-a716-446655440000` |
| `{{$randomUUID}}` | Same as `{{$guid}}` | `{{$randomUUID}}` | `550e8400-e29b-41d4-a716-446655440000` |
| `{{$timestamp}}` | Unix timestamp (seconds) | `{{$timestamp}}` | `1705315200` |
| `{{$randomInt}}` | Random integer (0-1000) | `{{$randomInt\|1-100}}` | `42` |
| `{{$randomBoolean}}` | Random boolean | `{{$randomBoolean}}` | `true` |
| `{{$randomHex}}` | Random hex string | `{{$randomHex\|32}}` | `a1b2c3d4e5f6` |
| `{{$randomAlphaNumeric}}` | Random alphanumeric string | `{{$randomAlphaNumeric\|10}}` | `Ab3x9K2mNp` |
| `{{$randomAlpha}}` | Random alphabetic string | `{{$randomAlpha\|8}}` | `HelloWorld` |
| `{{$randomWords}}` | Random words | `{{$randomWords\|5}}` | `lorem ipsum dolor sit amet` |
| `{{$randomPhoneNumber}}` | Random phone number | `{{$randomPhoneNumber\|0}}` | `555-123-4567` |
| `{{$randomEmail}}` | Random email address | `{{$randomEmail\|1}}` | `john@test.com` |
| `{{$randomFirstName}}` | Random first name | `{{$randomFirstName}}` | `John` |
| `{{$randomLastName}}` | Random last name | `{{$randomLastName}}` | `Smith` |
| `{{$randomFullName}}` | Random full name | `{{$randomFullName}}` | `John Smith` |
| `{{$randomUserName}}` | Random username | `{{$randomUserName\|8}}` | `user1234` |
| `{{$randomPassword}}` | Random password | `{{$randomPassword\|12}}` | `Kj9#mN2$pQr` |

### Usage Examples

#### HTTP Request Body
```yaml
heartbeat.monitors:
- type: http
  urls: ["https://api.example.com/users"]
  check.request:
    method: POST
    body: |
      {
        "id": "{{$guid}}",
        "user": "{{$randomFullName}}",
        "email": "{{$randomEmail}}",
        "phone": "{{$randomPhoneNumber}}",
        "created_at": "{{$timestamp}}"
      }
```

#### HTTP Headers
```yaml
heartbeat.monitors:
- type: http
  urls: ["https://api.example.com/data"]
  check.request:
    method: GET
    headers:
      "X-Request-ID": "{{$guid}}"
      "X-User-Name": "{{$randomUserName}}"
      "Authorization": "Bearer {{$randomHex|32}}"
      "Content-Type": "application/json"
```

#### Dynamic Host
```yaml
heartbeat.monitors:
- type: http
  urls: ["https://api.example.com"]
  check.request:
    method: GET
    headers:
      "Host": "api-{{$randomInt|1-100}}.example.com"
```

### Format Options

- **Date**: Use Go time format (e.g., `{{$date|2006-01-02 15:04:05}}`)
- **Random Int**: Specify range with `min-max` (e.g., `{{$randomInt|1-1000}}`)
- **Random Hex**: Specify length (e.g., `{{$randomHex|64}}`)
- **Random Strings**: Specify length (e.g., `{{$randomAlphaNumeric|20}}`)
- **Random Words**: Specify count (e.g., `{{$randomWords|10}}`)
- **Phone Number**: Choose format (0-2 for different formats)
- **Email**: Choose domain index (0-3 for different domains)

## Getting Started with Heartbeat

### Requirements

* [Golang](https://golang.org/dl/) 1.7

### Build

To build the binary for Heartbeat run the command below. This will generate a binary
in the same directory with the name heartbeat.

```
make
```


### Run

To run Heartbeat with debugging output enabled, run:

```
./heartbeat -c heartbeat.yml -e -d "*"
```

```
go run main.go -c heartbeat.yml -e -d "*" --path.home . --path.config .
```


### Update

Each beat has a template for the mapping in elasticsearch and a documentation for the fields
which is automatically generated based on `fields.yml`.

```
make update
```


### Cleanup

To clean  Heartbeat source code, run the following command:

```
make fmt
```

To clean up the build directory and generated artifacts, run:

```
make clean
```
