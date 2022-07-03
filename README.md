# protoc-gen-authz (PGAz)

PGAz is a protoc plugin to generate golang rpc authorization validators. 

Developers import the PGAz extension and annotate the rpc in their proto files with constraint rules:

```protobuf
syntax = "proto3";

package examplepb;

import "authz/authz.proto";

service Example {
  option (authz.roles) = "role1";
  option (authz.roles) = "role2";

  rpc Empty1 (Empty) returns (Empty) {
    option (authz.rules) = {
      allow: "role1",
      allow: "role2"
    };
  }
  rpc Empty2 (Empty) returns (Empty) {
    option (authz.rules) = {
      disallow: "role1",
      disallow: "role2"
    };
  }
  rpc Empty3 (Empty) returns (Empty) {
    option (authz.rules) = {
      any: true
    };
  }
}

message Empty {}
```

You need to set all roles to "rolses" in service.

You can set "rules.allow", "rules.disallow", "rules.any" in rpc. "rules.allow" and "rules.disallow" can be set to the role included in the roles list. "rules.allow" is white list. "rules.disallow" is black list. If you set true to "rules.any", all roles are allowed.

If multiple rules are set, the one with the highest priority will be set. The priority is "rules.allow", "rules.disallow", "rules.any". Also, if no rule is set, all roles will be disallowed.

## Install

You can install PGAz with following command:

```bash
$ go install github.com/ulbqb/protoc-gen-authz@latest
```

## Generate

You can generate an authz file with following command:

```bash
$ protoc \
  -I . \
  --go_out=./generated \
  --authz_out=./generated \
  example.proto
```

## Usage

You can validate recieved roles as in the following code.

```go
ValidateExampleAuthzRole(methodName, receivedRoles)
```