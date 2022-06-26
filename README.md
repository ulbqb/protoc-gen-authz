# protoc-gen-authz (PGAz)

PGAz is a protoc plugin to generate golang rpc authorization validators. 

Developers import the PGAz extension and annotate the rpc in their proto files with constraint rules:

```protobuf
syntax = "proto3";

package examplepb;

import "authz/authz.proto";

service Example {
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

You can set "allow", "disallow", "any". "allow" is white list. "disallow" is block list. If you set true to "any", all roles are allowed.

If multiple rules are set, the one with the highest priority will be set. The priority is "allow", "disallow", "any". Also, if no rule is set, all roles will be disallowed.

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
