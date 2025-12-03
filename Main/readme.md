  1. Highway Low Density (hisol-vanets-highway-low-density.cc)
   - Mobility Model: Constant velocity highway with multiple lanes
   - Parameters: Lower number of vehicles (50), higher speeds (~90 km/h), spaced out
   - Use Case: Simulates highway conditions with vehicles in lanes moving at consistent speeds

  2. Urban Grid High Density (hisol-vanets-urban-grid-high-density.cc)
   - Mobility Model: Random walk in a grid pattern
   - Parameters: Higher number of vehicles (100), lower speeds (~30 mph), urban grid layout
   - Use Case: Simulates city conditions with many vehicles in a confined area with random movement

  3. Congestion Mixed Scenario (hisol-vanets-congestion-mixed-scenario.cc)
   - Mobility Model: Mixed density pattern with congested center and free-flow outer zones
   - Parameters: Highest number of vehicles (150), variable speeds and densities
   - Use Case: Simulates mixed conditions with congested areas in the center and free-flow in outer regions

  All versions include:
   - WiFi 802.11p VANET communication
   - BSM Broadcast Application
   - Sybil Attack with logging
   - Replay Attack with logging
   - Jammer Node with logging
   - RSSI Logging
   - Neighbor Count Logging
   - Separate log files for each subsystem



  1. Highway Low Density Version:
  ```bash
   ./ns3 run hisol-vanets-highway-low-density --  --simTime=60.0 --numVehicles=50
```
  2. Urban Grid High Density Version:
```bash
   ./ns3 run hisol-vanets-urban-grid-high-density -- --simTime=60.0 --numVehicles=100
```
  3. Congestion Mixed Scenario Version:
```bash
   ./ns3 run hisol-vanets-congestion-mixed-scenario -- --simTime=60.0 --numVehicles=150
```
  
  Custom Parameters:
  You can also adjust the simulation parameters as needed:

   1 # Example with custom parameters
   2  ./ns3 run hisol-vanets-urban-grid-high-density
     -- --simTime=30.0 --numVehicles=75

  After running, all versions will generate these output files:
   - bsm_log.csv - Basic Safety Messages
   - rssi_log.csv - Signal strength data
   - neighbor_log.csv - Neighbor count statistics
   - sybil_log.csv - Sybil attack events
   - replay_log.csv - Replay attack events
   - jammer_log.csv - Jammer activity logs