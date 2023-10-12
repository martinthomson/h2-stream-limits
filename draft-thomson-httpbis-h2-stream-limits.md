---
title: "Using HTTP/3 Stream Limits in HTTP/2"
category: std

docname: draft-thomson-httpbis-h2-stream-limits-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Applications and Real-Time"
workgroup: "HTTP"
keyword:
 - next generation
 - unicorn
 - sparkling distributed ledger
venue:
  group: "HTTP"
  type: "Working Group"
  mail: "ietf-http-wg@w3.org"
  arch: "https://lists.w3.org/Archives/Public/ietf-http-wg/"
  github: "martinthomson/h2-stream-limits"
  latest: "https://martinthomson.github.io/h2-stream-limits/draft-thomson-httpbis-h2-stream-limits.html"

author:
 -
    fullname: Martin Thomson
    organization: Mozilla
    email: "mt@lowentropy.net"

normative:
  RFC9113:
    display: HTTP/2

informative:
  RFC9114:
    display: HTTP/3

  CVE-2023-44487:
    target: "https://www.cve.org/CVERecord?id=CVE-2023-44487"
    title: "HTTP/2 Rapid Reset CVE Record"
    date: 2023-10-10


--- abstract

A variant mechanism for managing stream limits is described for HTTP/2.  This
scheme is based on that used in QUIC and is more robust against certain patterns
of abuse.


--- middle

# Introduction

HTTP/2 {{RFC9113}} allows endpoints to describe a concurrency limit for streams
(`SETTINGS_MAX_CONCURRENT_STREAMS`).  Initially, the stream concurrency limit is
only bounded by the maximum number of streams that can be created, which is
2<sup>30</sup> for each endpoint, but the value can be changed at any time.
Most endpoints set a smaller value in an attempt to protect the resources that
are committed when processing a stream.

This limit is not effective in the case that streams are quickly cancelled.
Stream cancellation with the `RST_STREAM` frame has immediate effect, which
means that the stream no longer counts against the concurrent stream limit.
This means that a malicious endpoint can create and cancel an unbounded number
of streams as long as its peer does not set a limit of zero.

If the creation of the stream results in the expenditure of resources, rapidly
creating and cancelling streams can exhaust resources.  For a server, clients
that create and cancel many requests can effectively deny service; for a client,
reserving and cancelling promised streams might have similar effect if a client
does not disable server push using the `SETTINGS_ENABLE_PUSH` setting.  This
creates a denial of service exposure for which a remedy is not supported in the
protocol.

However, as noted in {{Section 10.5 of RFC9113}}, many of the features in HTTP/2
that have some potential to create denial of service attacks also have
constructive uses.  Distinguishing constructive and destructive uses is often
challenging.  Some applications of HTTP might find that cancelling many requests
is necessary; if cancellation is treated as abusive, it is possible that the
treatment necessary to prevent attacks might unintentionally punish some
clients.

The QUIC protocol {{!QUIC=RFC9000}} on which HTTP/3 {{RFC9114}} is built
contains an alternative mechanism for limiting concurrency.  The scheme in QUIC,
as described in {{Section 4.6 of QUIC}}, does not set a concurrent stream limit,
but instead relies on a peer increasing the maximum allowed stream identifier.
An endpoint cannot create new streams immediately after cancelling an open
stream; their peer needs to send a message to make more streams available.  In
QUIC therefore, a malicious endpoint can only create and cancel a finite number
of streams, after which their peer needs to provide consent to continue.

This document ports the QUIC stream concurrency limit mechanisms to HTTP/2.  As
use of this system is voluntary and therefore not necessarily guaranteed, this
does not prevent abusive use of stream cancellation.  However, deployment of
this mechanism in popular implementations might allow endpoints to deploy more
aggressive strategies for managing abuse in its absence.


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# The HTTP/2 MAX_STREAMS Frame {#max-streams}

The `MAX_STREAMS` frame (type=0xTBD) is used to limit the streams that a
recipient is permitted to create.

The format of the `MAX_STREAMS` frame is illustrated in {{fig-max-streams}},
using the notation defined in {{Section 1.3 of QUIC}}.

~~~
MAX_STREAMS Frame {
  Length (24) = 0x04,
  Type (8) = 0x0TBD,

  Unused Flags (8),

  Reserved (1),
  Stream Identifier (31) = 0,

  Reserved (1),
  Maximum Stream Identifier (31),
}
~~~
{: #fig-max-streams title="MAX_STREAMS Frame Format"}

In addition to the common HTTP/2 frame header (see {{Section 4 of RFC9113}}),
the `MAX_STREAMS` contains a one-bit reserved field and a 31-bit Maxmimum Stream
Identifier field.

The Reserved field MUST be set to zero when sending and ignored on receipt.

The Maximum Stream Identifier field contains the maximum value that a stream
identifier can use when the recipient of this frame creates or reserves a
stream; see {{Section 5.1 of RFC9113}} for how streams are created.

A `MAX_STREAMS` frame MUST be sent on stream 0.  Receipt of a `MAX_STREAMS`
frame on any other stream MUST be treated as a connection error of type
PROTOCOL_ERROR; see {{Section 5.4.1 of RFC9113}}.

An endpoint MUST treat receipt of a `MAX_STREAMS` frame with a length other than
4 as a connection error of type FRAME_TYPE_ERROR; see {{Section 5.4.1 of
RFC9113}}.

A client MUST treat receipt of an odd-numbered Maximum Stream Identifier as a
connection error of type PROTOCOL_ERROR; see {{Section 5.4.1 of RFC9113}}.
Similarly, a server MUST treat receipt of an even-numbered Maximum Stream
Identifier as a connection error, with an exception of a value of 0, which can
be used to indicate support for the feature without enabling the creation of
streams (see {{negotiating}}).


## Applying Stream Limits {#limits}

An endpoint that receives a `MAX_STREAMS` frame MUST NOT create or reserve a
stream with a number that exceeds the value of the Maximum Stream Identifier
field from that frame, until it receives a `MAX_STREAMS` frame with a larger
value.

An endpoint MUST treat the creation or reservation of a stream with a higher
valued stream identifier than it included in a `MAX_STREAMS` frame as a
connection error of type FLOW_CONTROL_ERROR; see {{Section 5.4.1 of RFC9113}}.

Endpoints can only increase the value that they include in a `MAX_STREAMS`
frame.  An endpoint MUST treat receipt of a Maximum Stream Identifier that is
equal to or smaller than a value that it has previously received as a connection
error of type PROTOCOL_ERROR; see {{Section 5.4.1 of RFC9113}}.  Note that a
value of 0, which can be used to indicate support for this feature (see
{{negotiating}}) without permitting the creation of streams, is permitted for
both client and server.

An implementation can support a similar concurrency limit to that provided by
`SETTINGS_MAX_CONCURRENT_STREAMS`.  The initial value can be set to twice the
value of `SETTINGS_MAX_CONCURRENT_STREAMS`, with a client adding 1 if the value
is non-zero.  The endpoint then increases the value of the Maximum Stream
Identifier field as the streams its peer initiates are closed.  An endpoint can
avoid sending redundant `MAX_STREAMS` frames by processing all incoming data
before increasing the maximum.  This approach differs from
`SETTINGS_MAX_CONCURRENT_STREAMS` in that a peer is not able to create and
cancel streams arbitrarily, as new streams do not become available until after
receiving a `MAX_STREAMS` frame.


## Negotiating MAX_STREAMS Usage {#negotiating}

This extension is not negotiated using the `SETTINGS` frame.  Instead, the
receipt of a `MAX_STREAMS` frame indicates support for the feature.

An endpoint that supports this extension MUST send a `MAX_STREAMS` frame after
establishing a connection, after the HTTP/2 connection preface ({{Section 3.4 of
RFC9113}}).  When a `MAX_STREAMS` frame is received, the endpoint MUST
subsequently only create streams according to the rules in {{limits}} and
ignore any value of the `SETTINGS_MAX_CONCURRENT_STREAMS` setting.


# Security Considerations

HTTP/2 considered the cancellation of a stream to reclaim the resources that
might have been committed during its creation.  The stream limits in HTTP/2
therefore did not provide a means to limit stream creation.  Though cancellation
is a potential source of abusive traffic, it was not explicitly mentioned (see
{{Section 10.5 of RFC9113}}).  However, experience has shown that the creation
of a stream has costs that cannot always be recovered when that stream is
cancelled.

The use of the `MAX_STREAMS` frame provides endpoints with a means of limiting
stream creation, using a method that has proven to be effective in QUIC.
However, repeated use of the `MAX_STREAMS` frame is also a potential source of
abuse, as described in {{Section 10.5 of RFC9113}}.  Though processing a
`MAX_STREAMS` frame is likely to be trivial, receiving significantly more
`MAX_STREAMS` frames than the number of streams that have been closed might
indicate an attempt to waste effort.


# IANA Considerations

This document registers a new entry in the "HTTP/2 Frame Type" registry, as
documented in {{Section 11 of RFC9113}}.  This entry has the following values.

Frame Type:

: MAX_STREAMS

Code:

: 0xTBD

Specification:

: {{max-streams}}


--- back

# Acknowledgments
{:numbered="false"}

This document is written in response to the problems discovered as part of
{{CVE-2023-44487}}, so maybe those behind the botnet responsible for that attack
deserve some credit.
