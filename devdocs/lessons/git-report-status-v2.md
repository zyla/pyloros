# Git report-status-v2 capability

## Problem
When generating git `receive-pack` error responses, the proxy checked for
`report-status` capability but git 2.43+ sends `report-status-v2` instead.
This caused the sideband report-status response to not be generated, and git
showed "the remote end hung up unexpectedly" instead of per-ref errors.

## Solution
Check for both `report-status` and `report-status-v2`. The v1 response format
(`unpack ok\n` + `ng <ref> <msg>\n` + flush) is a valid subset of v2, so the
same response works for both capabilities.

## Git smart HTTP sideband format
When `side-band-64k` is negotiated:
- The entire report-status buffer (inner pkt-lines + inner `0000` flush) is
  sent as **one** sideband packet on channel 1
- Stderr messages go on channel 2 (displayed as `remote: ...`)
- An outer `0000` flush terminates the sideband stream

The key detail: the inner report-status is bundled as one sideband payload, not
split across multiple sideband packets.
