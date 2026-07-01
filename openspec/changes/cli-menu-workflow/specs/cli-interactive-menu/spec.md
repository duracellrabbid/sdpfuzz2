## ADDED Requirements

### Requirement: Main Menu Presentation
The system SHALL display an interactive main menu when the CLI command `sdpfuzz2` is executed without subcommands.

#### Scenario: Display main menu on startup
- **WHEN** user executes `sdpfuzz2` command with no arguments or subcommands
- **THEN** system prints the menu options and prompts the user to select one

### Requirement: Discover and Fuzz Workflow
The system SHALL support a combined workflow that discovers nearby devices, lets the user select one, automatically runs an initial SDP probe, prompts for a fuzzing mode, and immediately begins the fuzzing loop.

#### Scenario: Run unified discover and fuzz workflow
- **WHEN** user selects the "Discover & Fuzz Target" option from the main menu, chooses a discovered target device, selects a fuzzing mode, and starts execution
- **THEN** system runs scanning, target selection, SDP probing, and begins fuzzing in a single continuous session

### Requirement: Corpus Management Interactive Menu
The system SHALL present a submenu for corpus operations when the "Corpus Management" option is chosen.

#### Scenario: Navigate to corpus management submenu
- **WHEN** user selects the "Corpus Management" option from the main menu
- **THEN** system displays options to list sequences, replay a sequence, run corpus-mutation fuzzing, or return to the main menu

### Requirement: Standalone Discovery Workflow
The system SHALL allow running a standalone device discovery scan from the main menu.

#### Scenario: Run standalone discovery scan
- **WHEN** user selects "Standalone Discovery" option from the main menu
- **THEN** system lists discovered nearby devices and returns to the main menu

### Requirement: Standalone Probing Workflow
The system SHALL allow running a standalone SDP probe on a discovered device from the main menu.

#### Scenario: Run standalone probing scan
- **WHEN** user selects "Standalone Probing" option from the main menu, selects a target device, and executes probing
- **THEN** system performs SDP probe and prints probe result summary before returning to the main menu

### Requirement: Cleanup Corpus Workflow
The system SHALL allow cleaning the corpus from the main menu.

#### Scenario: Run corpus cleanup
- **WHEN** user selects "Cleanup Corpus" option from the main menu
- **THEN** system deletes orphaned database records and files, prints a summary, and returns to the main menu
