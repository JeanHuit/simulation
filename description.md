# HISOL VANET Simulation Files Description

This document describes the three `hisol-*` simulation files in the root directory, detailing their common features and unique characteristics.

## Common Features

All three files share the following core functionality:

### Core Simulation Components
- **WiFi 802.11p VANET Communication**: Implements vehicular ad-hoc network communication using the 802.11p standard for V2V communication
- **BSM (Basic Safety Message) Broadcast Application**: Each vehicle broadcasts safety messages containing position, velocity, and timing information at 10Hz
- **Security Attack Simulations**: Includes implementations of Sybil, Replay, and Jamming attacks
- **Data Logging**: Provides comprehensive logging capabilities with separate output files for each subsystem

### Logging Subsystems
- **BSM Logging**: Records Basic Safety Messages with vehicle ID, position coordinates, velocity, and timestamps
- **RSSI Logging**: Captures Received Signal Strength Indicator values for communication quality analysis
- **Neighbor Count Logging**: Tracks the number of nearby vehicles within communication range (approx. 250m)
- **Attack Logging**: Documents occurrences and details of security attacks

### Attack Implementations
- **Sybil Attack**: Simulates a node creating multiple fake identities to appear as multiple vehicles
- **Replay Attack**: Records and retransmits previously captured BSM messages to simulate malicious replay
- **Jammer Node**: Continuously transmits interference signals to disrupt legitimate communication

### Technical Framework
- Compatible with NS-3.46 simulation environment
- Uses UDP broadcast communication on port 5000 for BSM messages
- Implements IPv4 addressing with 10.55.0.0 network base
- Standard 60-second simulation time with adjustable vehicle counts

## Unique Features by File

### `hisol-vanets-congestion-mixed-scenario.cc`
- **Mixed Congestion Mobility Model**: Implements variable density zones where 60% of vehicles are concentrated in congested areas (center) while 40% are in free-flow areas (outer zones)
- **High Vehicle Density**: Default of 150 vehicles to simulate congested conditions
- **Variable Speed Limits**: Lower speed (8.9 m/s ~20 mph) in congested areas vs higher speed (22.2 m/s ~50 mph) in free-flow areas
- **Area-Based Distribution**: Vehicles distributed between high-density (40m) and low-density (100m) zones

### `hisol-vanets-highway-low-density.cc`
- **Highway Mobility Model**: Implements constant velocity movement in lanes with predefined lane spacing
- **Low Vehicle Density**: Default of 50 vehicles, suitable for highway scenarios with sufficient spacing
- **Structured Lane Movement**: Three lanes with vehicles following constant velocity models (25 m/s ~90 km/h) in straight lines
- **Constant Velocity Mobility**: Vehicles maintain fixed speeds and directions, simulating highway conditions

### `hisol-vanets-urban-grid-high-density.cc`
- **Urban Grid Mobility Model**: Implements RandomWalk2dMobility in a grid pattern simulating city streets
- **High Vehicle Density**: Default of 100 vehicles for urban environment simulation
- **Grid-Based Movement**: 10x10 grid of intersections with 100m blocks, simulating realistic urban navigation
- **Variable Speeds**: Speeds range from 5.0 to 13.4 m/s (~30 mph) to simulate urban driving conditions
- **Bounded Movement**: Vehicles confined to urban grid boundaries with random direction changes

## Output Files
All three simulations generate identical output files for comparison:
- `bsm_log.csv` - Basic Safety Messages
- `rssi_log.csv` - Received Signal Strength Indicators
- `neighbor_log.csv` - Neighbor count statistics
- `sybil_log.csv` - Sybil attack records
- `replay_log.csv` - Replay attack records
- `jammer_log.csv` - Jammer activity logs

## Analysis Pipeline

The simulation output is designed to work with the analysis notebook `hisol_multi_scenario_analysis_extended.ipynb`, which provides:

- **Multi-Scenario Analysis**: Comparative analysis across highway, mixed, and urban scenarios
- **Feature Extraction**: Windowed feature computation for machine learning applications
- **Machine Learning Pipeline**: Random Forest-based attack detection with performance metrics (accuracy, precision, recall, F1, ROC-AUC)
- **Trust Computation**: Exponential smoothing trust model for evaluating node reliability
- **Results Visualization**: ROC curves, trust score visualizations, and comparative plots
- **Cross-Scenario Validation**: Evaluation of security algorithms across different traffic conditions and densities

The notebook assumes a directory structure of `/home/jeanhuit/Documents/Thesis/results/[scenario]/[density]/run-[n]/` where scenario is one of {highway, mixed, urban} and density is one of {density-50, density-100, density-150}.