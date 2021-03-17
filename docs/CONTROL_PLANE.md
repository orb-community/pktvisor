# Control Plane

**_Draft_**

pktvisord expose a control plane over REST API.

## Discovery

pktvisord exposes a method for discovering the available modules, their configurable properties, and their associated
metrics schema.

All interfaces are versioned.

```
/api/v1/handlers
 {dns: [v1, v2], net}
/api/v1/handlers/dns/v1/schema
/api/v1/handlers/net/v1/schema

```

