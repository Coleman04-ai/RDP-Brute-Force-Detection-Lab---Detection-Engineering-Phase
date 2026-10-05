title: RDP Failed Logon (Base Detection)
id: 7f3a1e2c-9b4d-4c6e-8a1f-2d5e6f7a8b9c
status: experimental
description: >
    Detects a single failed logon attempt (Event ID 4625) with a Logon Type
    consistent with an RDP session - RemoteInteractive (10) or Network (3),
    since testing showed RDP client/attack-tool failures can log as either
    depending on the negotiated security layer. Used as the base event for
    the brute-force correlation rule below.
author: Coleman04
date: 2026-09-24
modified: 2026-09-26
references:
    - https://github.com/Coleman04-ai/rdp-brute-force-detection-lab
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
        LogonType:
            - 10
            - 3
    condition: selection
fields:
    - TargetUserName
    - SourceNetworkAddress
    - LogonType
    - IpPort
falsepositives:
    - Legitimate user repeatedly mistyping their password
    - Other Logon Type 3 (Network) authentication failures unrelated to RDP -
      this logon type is not exclusive to RDP traffic and would need an
      additional filter (e.g. destination port 3389) in a multi-service
      environment
level: low
---
title: RDP Brute Force - Multiple Failed Logons from Single Source
id: 3c6e9a1f-2d5e-4b6e-8f7a-8b9c7f3a1e2c
status: experimental
description: >
    Correlates the base failed-RDP-logon rule to detect 5 or more failed
    attempts from the same source IP within a 5-minute window, consistent
    with an RDP brute-force attack.
author: Coleman04
date: 2026-09-26
references:
    - https://github.com/Coleman04-ai/rdp-brute-force-detection-lab
correlation:
    type: event_count
    rules:
        - 7f3a1e2c-9b4d-4c6e-8a1f-2d5e6f7a8b9c
    group-by:
        - SourceNetworkAddress
    timespan: 5m
    condition:
        gte: 5
falsepositives:
    - Legitimate user repeatedly mistyping their password
    - Shared NAT/gateway IP producing many distinct users' failed logons within
      the same window
level: medium
