package agentv1

// ProtocolVersion identifies the RPC contract, independently of the application
// release (v3). Change it only when compatibility negotiation is required.
const ProtocolVersion uint32 = 1

const MaxEvents = 100
const MaxBytes = 2 << 20

// Keep CRL snapshots within the existing bounded RPC envelope.
const MaxTrustBytes = MaxBytes - 4096
