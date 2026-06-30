## ADDED Requirements

### Requirement: Discovery and Probe Control Center
The user interface SHALL present a list of discovered devices and enable triggering target probes with a single user action.

#### Scenario: Select device and trigger probe
- **WHEN** the user navigates to the Discovery tab, clicks "Scan", and clicks on a target row
- **THEN** the UI highlights the target and automatically triggers an SDP probe, rendering the collected attributes and continuation states inside the probe details card.

### Requirement: Configuration Form and Strategy Recommendation
The user interface SHALL provide a configuration form to select strategies, seed, concurrency, delay, and rate limit, with visual guides.

#### Scenario: Auto-recommendation of strategy
- **WHEN** a target probe completes and returns one or more valid continuation states
- **THEN** the UI auto-selects the "continuation-bytes" mode and highlights it with a recommendation badge.

### Requirement: Live Performance dashboard
The user interface SHALL display stats, radial meters, dynamic line charts, and a scrolling packet logs console during an active session.

#### Scenario: Live monitoring updates
- **WHEN** a fuzzing session is started via WebSocket connection
- **THEN** the UI updates the radial status meter, increments packet metrics, maps the throughput rates on a line chart, and appends color-coded packet logs to the console window in real-time.
