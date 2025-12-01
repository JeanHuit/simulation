#!/bin/bash

# Script to run all experiments and save output in organized folder structure
# This version accounts for the correct ns3 working directory structure

set -e  # Exit on any error

# Configuration
NUM_RUNS=1  # Change this if you want multiple runs for statistical analysis
BASE_SIM_TIME=900.0

# Ensure we're in the ns3 root directory
if [ ! -f "ns3" ]; then
    echo "Error: Cannot find the ns3 executable. Please run this script from the ns3 root directory."
    exit 1
fi

# Create results directory structure
echo "Setting up directory structure..."
mkdir -p results/highway/density-50
mkdir -p results/highway/density-100
mkdir -p results/highway/density-150

mkdir -p results/urban/density-50
mkdir -p results/urban/density-100
mkdir -p results/urban/density-150

mkdir -p results/mixed/density-50
mkdir -p results/mixed/density-100
mkdir -p results/mixed/density-150

# Function to run experiment and move results
run_experiment() {
    local sim_name=$1
    local density=$2
    local scenario=$3
    local run_num=$4

    echo "Running: $sim_name with numVehicles=$density, scenario=$scenario, run=$run_num"

    # Run the simulation from the ns3 root directory
    ./ns3 run "$sim_name" -- --simTime="$BASE_SIM_TIME" --numVehicles="$density"

    # Determine output directory based on scenario
    case "$scenario" in
        "highway")
            run_dir="results/highway/density-$density/run-$run_num"
            ;;
        "urban")
            run_dir="results/urban/density-$density/run-$run_num"
            ;;
        "mixed")
            run_dir="results/mixed/density-$density/run-$run_num"
            ;;
        *)
            echo "Error: Unknown scenario $scenario"
            exit 1
            ;;
    esac

    # Create run directory
    mkdir -p "$run_dir"

    # Move the output files to the appropriate run directory
    for file in bsm_log.csv rssi_log.csv neighbor_log.csv sybil_log.csv replay_log.csv jammer_log.csv; do
        if [ -f "$file" ]; then
            mv "$file" "$run_dir/"
            echo "  -> Moved $file to $run_dir/"
        else
            echo "  -> Warning: $file not found after running simulation"
        fi
    done
}

# Run all experiments
echo "Starting experiments..."

# Highway experiments
for density in 50 100 150; do
    for run in $(seq 1 $NUM_RUNS); do
        run_experiment "hisol-vanets-highway-low-density" "$density" "highway" "$run"
    done
done

# Urban experiments
for density in 50 100 150; do
    for run in $(seq 1 $NUM_RUNS); do
        run_experiment "hisol-vanets-urban-grid-high-density" "$density" "urban" "$run"
    done
done

# Mixed scenario experiments
for density in 50 100 150; do
    for run in $(seq 1 $NUM_RUNS); do
        run_experiment "hisol-vanets-congestion-mixed-scenario" "$density" "mixed" "$run"
    done
done

echo ""
echo "All experiments completed!"
echo "Results are organized in the 'results' directory:"
echo "  - results/highway/density-[50|100|150]/run-[1..$NUM_RUNS]/"
echo "  - results/urban/density-[50|100|150]/run-[1..$NUM_RUNS]/"
echo "  - results/mixed/density-[50|100|150]/run-[1..$NUM_RUNS]/"
echo ""
echo "Each run directory contains:"
echo "  - bsm_log.csv (Basic Safety Messages)"
echo "  - rssi_log.csv (Signal strength data)"
echo "  - neighbor_log.csv (Neighbor count statistics)"
echo "  - sybil_log.csv (Sybil attack events)"
echo "  - replay_log.csv (Replay attack events)"
echo "  - jammer_log.csv (Jammer activity logs)"