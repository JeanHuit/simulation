./ns3 run scratch/hisol-vanets-highway-low-density --  --simTime=900.0 --numVehicles=50
./ns3 run scratch/hisol-vanets-highway-low-density --  --simTime=900.0 --numVehicles=100
./ns3 run scratch/hisol-vanets-highway-low-density --  --simTime=900.0 --numVehicles=150

./ns3 run scratch/hisol-vanets-urban-grid-high-density -- --simTime=900.0 --numVehicles=50
./ns3 run scratch/hisol-vanets-urban-grid-high-density -- --simTime=900.0 --numVehicles=100
./ns3 run scratch/hisol-vanets-urban-grid-high-density -- --simTime=900.0 --numVehicles=150


./ns3 run scratch/hisol-vanets-congestion-mixed-scenario -- --simTime=900.0 --numVehicles=50
./ns3 run scratch/hisol-vanets-congestion-mixed-scenario -- --simTime=900.0 --numVehicles=100
./ns3 run scratch/hisol-vanets-congestion-mixed-scenario -- --simTime=900.0 --numVehicles=150



folder structure:
results/
  highway/
    density-50/
      run-1/
      run-2/
      ...
    density-100/
    density-150/

  urban/
    density-50/
    density-100/
    density-150/

  mixed/
    density-50/
    density-100/
    density-150/


After running, all versions will generate these output files:
   - bsm_log.csv - Basic Safety Messages
   - rssi_log.csv - Signal strength data
   - neighbor_log.csv - Neighbor count statistics
   - sybil_log.csv - Sybil attack events
   - replay_log.csv - Replay attack events
   - jammer_log.csv - Jammer activity logs