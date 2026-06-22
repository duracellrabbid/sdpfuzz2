## ADDED Requirements

### Requirement: Device Discovery via BlueZ
The system SHALL scan for nearby Bluetooth devices using BlueZ adapter and return a list of discovered devices with names and MAC addresses.

#### Scenario: Successful device discovery
- **WHEN** user initiates device discovery scan
- **THEN** system queries BlueZ D-Bus APIs for available adapters and scans for nearby devices
- **THEN** system returns list of devices with device name, MAC address, and signal strength

#### Scenario: No devices found
- **WHEN** user initiates device discovery scan with no nearby devices
- **THEN** system returns empty list and informs user

#### Scenario: Adapter not available
- **WHEN** user initiates device discovery but no Bluetooth adapter is available
- **THEN** system throws an error with clear message about adapter unavailability

### Requirement: Interactive Device Selection
The system SHALL allow users to interactively select a target device from the discovered device list.

#### Scenario: User selects device by index
- **WHEN** user views numbered list of discovered devices
- **THEN** user inputs index number of desired target
- **THEN** system confirms selection and returns device name and MAC address

#### Scenario: Invalid index selection
- **WHEN** user inputs index outside the range of available devices
- **THEN** system displays error and prompts user to select valid index

#### Scenario: User cancels selection
- **WHEN** user requests to cancel device selection
- **THEN** system exits selection flow and returns to discovery menu
