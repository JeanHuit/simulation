#!/usr/bin/env python3
"""
This script tests if the data in the results directory can be properly loaded by the notebook code
"""

import pandas as pd
import numpy as np
import os

# Define the root path
ROOT = "/home/jeanhuit/Documents/Workspace/simulation/results"
scenario_dirs = ['highway','mixed','urban']
densities = ['density-50','density-100','density-150']

runs = []
for scen in scenario_dirs:
    for dens in densities:
        runpath = os.path.join(ROOT, scen, dens, "run-1")
        if os.path.exists(runpath):
            files = {f: os.path.join(runpath, f) for f in [
                'bsm_log.csv','rssi_log.csv','neighbor_log.csv',
                'sybil_log.csv','replay_log.csv','jammer_log.csv'
            ] if os.path.exists(os.path.join(runpath,f))}
            runs.append({'scenario':scen,'density':dens,'path':runpath,'files':files})

print("Discovered", len(runs), "runs")
for r in runs:
    print(r['scenario'], r['density'], "files:", list(r['files'].keys()))

def load_run_files(run):
    data = {}
    for name,path in run['files'].items():
        try:
            df = pd.read_csv(path)
            print(f"File: {name}, Shape: {df.shape}, Columns: {list(df.columns)}")
            print(f"First few rows of {name}:")
            print(df.head(3))
            print("-" * 50)
            data[name] = df
        except Exception as e:
            print("Error loading", path, e)
            data[name] = None
    return data

# Test with first run
if runs:
    print("\nTesting first run:")
    print(f"Path: {runs[0]['path']}")
    test_data = load_run_files(runs[0])
    
    # Check BSM structure specifically
    bsm = test_data.get('bsm_log.csv')
    if bsm is not None:
        print(f"\nBSM data structure:")
        print(f"Shape: {bsm.shape}")
        print(f"Columns: {list(bsm.columns)}")
        print(f"Data types: {bsm.dtypes}")
        print(f"First 10 rows:")
        print(bsm.head(10))
        
        # Check if columns align with expected names
        expected_cols = ['node', 'x', 'y', 'vx', 'vy', 'time']
        actual_cols = list(bsm.columns)
        
        print(f"\nExpected columns: {expected_cols}")
        print(f"Actual columns: {actual_cols}")
        
        if len(actual_cols) >= 6:
            print(f"Using first 6 columns as: {expected_cols}")
            bsm_df = bsm.iloc[:,0:6].copy()
            bsm_df.columns = expected_cols
            print(f"Renamed BSM head:\n{bsm_df.head()}")
        else:
            print(f"ERROR: Not enough columns in BSM file")