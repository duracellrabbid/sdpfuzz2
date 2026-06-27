# SDP Protocol Specifics & Packet Format

This document details the Service Discovery Protocol (SDP) specifics and packet structures implemented in SDPFuzz2.

## 1. SDP Packet Structure (PDU)

Every SDP request and response payload shares a common header:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    PDU ID     |      Transaction ID           | Parameter Length|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Parameter Length (cont)       |  Parameters ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Header Fields:
- **PDU ID** (1 byte): Identifies the SDP request or response type:
  - `0x02`: Service Search Request
  - `0x03`: Service Search Response
  - `0x04`: Service Attribute Request
  - `0x05`: Service Attribute Response
  - `0x06`: Service Search Attribute Request
  - `0x07`: Service Search Attribute Response
- **Transaction ID** (2 bytes): Identifies matching requests and responses. The client increments this monotonically with wrap-around.
- **Parameter Length** (2 bytes): Length of the parameters field in bytes.

---

## 2. Service Search Attribute Request (PDU 0x06)

SDPFuzz2 primarily uses the **Service Search Attribute Request** to discover target services. The parameters for this request are structured as follows:

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| ServiceSearchPattern (UUIDs)                                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| MaximumAttributeByteCount     | AttributeIDList               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| ContinuationState (Length + Token Bytes)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Parameter Details:
1. **ServiceSearchPattern**: A data element sequence containing one or more UUIDs (typically generic L2CAP or SDP UUIDs) identifying the service classes being queried.
2. **MaximumAttributeByteCount** (2 bytes): The maximum size (in bytes) of the attribute list the client can receive in the response.
3. **AttributeIDList**: A data element sequence containing specific attribute IDs (or ranges of IDs) the client wants to retrieve.
4. **ContinuationState**: Tells the server where to resume if a previous response was fragmented. It consists of:
   - **Length** (1 byte): The size of the token.
   - **Token** (0-255 bytes): Opaque bytes returned by the server. If this is `0` (or empty), the request is the first fragment of a new query.

---

## 3. Continuation State Pagination

When a target server's response exceeds `MaximumAttributeByteCount`, the server returns a non-zero Continuation State token at the end of the Service Search Attribute Response (PDU `0x07`).

```
Response PDU:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| AttributeListByteCount        | AttributeListFragments        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| ContinuationStateLength (1B)  | ContinuationStateToken ...    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Client Pagination Loop:
1. Client sends initial request with empty Continuation State (Length = `0`).
2. Server responds with a payload fragment and a non-empty Continuation State token (e.g. `[0x02, 0xAA, 0xBB]`).
3. Client records this token and sends a second request containing the exact token (`[0x02, 0xAA, 0xBB]`) to fetch the next fragment.
4. Loop repeats until the server returns a Continuation State with Length = `0`, indicating all data has been transmitted.

## 4. Fuzzing Attack Surface

Fuzzing strategies in SDPFuzz2 target these key binary structures:
- **Length Malformation**: Setting the parameter length or MaximumAttributeByteCount to mismatched values to cause buffer overflows.
- **Continuation state mutation**: Mutating the continuation token length byte (oversizing it) or modifying token bytes to trigger memory disclosure or target crashes.
