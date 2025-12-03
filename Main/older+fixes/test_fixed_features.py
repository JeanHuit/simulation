#!/usr/bin/env python3
"""
This script tests the fixed version of the feature extraction function
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

def load_run_files(run):
    data = {}
    for name,path in run['files'].items():
        try:
            df = pd.read_csv(path)
            data[name] = df
        except Exception as e:
            print("Error loading", path, e)
            data[name] = None
    return data

# Feature extraction parameters
WINDOW = 5.0  # seconds per aggregation window
MIN_MESSAGES_PER_WINDOW = 1

def extract_features_from_run_fixed(run):
    data = load_run_files(run)
    bsm = data.get('bsm_log.csv')
    rssi = data.get('rssi_log.csv')
    neighbor = data.get('neighbor_log.csv')
    sybil = data.get('sybil_log.csv')
    replay = data.get('replay_log.csv')
    jammer = data.get('jammer_log.csv')

    # parse bsm: based on data analysis, columns are [time, x, y, vx, vy, node]
    if bsm is None:
        return None
    # Take first 6 columns and assign them to [time, x, y, vx, vy, node]
    bsm_df = bsm.iloc[:,0:6].copy()
    bsm_df.columns = ['time', 'x', 'y', 'vx', 'vy', 'node']
    bsm_df['time'] = pd.to_numeric(bsm_df['time'], errors='coerce')
    bsm_df['node'] = bsm_df['node'].astype(int)

    # parse rssi: node,msg,rssi or node,rawmsg,rssi
    rssi_df = None
    if rssi is not None:
        cols = list(rssi.columns)
        if len(cols) >= 3:
            tmp = rssi.iloc[:,0:3].copy()
            tmp.columns = ['node','msg','rssi']
            tmp['node'] = tmp['node'].astype(int)
            tmp['rssi'] = pd.to_numeric(tmp['rssi'], errors='coerce')
            # extract sender id from msg if possible
            def get_sender(msg):
                try:
                    if isinstance(msg, str) and msg.startswith("BSM,"):
                        return int(msg.split(",")[1])
                except:
                    return np.nan
                return np.nan
            tmp['sender'] = tmp['msg'].apply(get_sender)
            rssi_df = tmp
    # parse neighbor: time,node,count (if available)
    neighbor_df = None
    if neighbor is not None:
        nd = neighbor.copy()
        if nd.shape[1] >= 3:
            nd = nd.iloc[:,0:3]
            nd.columns = ['time','node','count']
            nd['time'] = pd.to_numeric(nd['time'], errors='coerce')
            nd['node'] = nd['node'].astype(int)
            nd['count'] = pd.to_numeric(nd['count'], errors='coerce')
            neighbor_df = nd

    # Build time windows
    t_min = bsm_df['time'].min()
    t_max = bsm_df['time'].max()
    windows = np.arange(t_min, t_max+WINDOW, WINDOW)

    features = []
    labels = []  # 0 benign, 1 sybil/replay/jam (we'll label windows that have attacks)

    # gather attack times if present
    attack_times = []
    if sybil is not None:
        # try extract numeric times from first column
        try:
            attack_times += list(pd.to_numeric(sybil.iloc[:,0], errors='coerce').dropna().unique())
        except:
            pass
    if replay is not None:
        try:
            attack_times += list(pd.to_numeric(replay.iloc[:,0], errors='coerce').dropna().unique())
        except:
            pass
    if jammer is not None:
        try:
            attack_times += list(pd.to_numeric(jammer.iloc[:,0], errors='coerce').dropna().unique())
        except:
            pass
    attack_times = sorted([float(x) for x in attack_times if not pd.isna(x)])

    # For each window compute features
    for i in range(len(windows)-1):
        t0 = windows[i]
        t1 = windows[i+1]
        win_bsm = bsm_df[(bsm_df['time'] >= t0) & (bsm_df['time'] < t1)]
        if win_bsm.empty:
            continue
        # feature: total messages, unique senders, mean speed, var speed
        total_msgs = len(win_bsm)
        unique_senders = win_bsm['node'].nunique()
        speeds = np.sqrt(win_bsm['vx']**2 + win_bsm['vy']**2)
        mean_speed = speeds.mean()
        var_speed = speeds.var()
        # neighbor features if available: mean neighbor count in window
        mean_neighbors = np.nan
        if neighbor_df is not None:
            nd = neighbor_df[(neighbor_df['time'] >= t0) & (neighbor_df['time'] < t1)]
            if not nd.empty:
                mean_neighbors = nd['count'].mean()
        # rssi features: mean rssi for messages in window
        mean_rssi = np.nan
        if rssi_df is not None:
            # match rssi sender to window senders
            # some rssi entries may not have valid sender; dropna
            r = rssi_df[(rssi_df['sender'].notna()) & (rssi_df['sender'].isin(win_bsm['node'].unique()))]
            if not r.empty:
                mean_rssi = r['rssi'].mean()
        # label: if any attack time falls inside window -> label 1 else 0
        has_attack = any((t >= t0) and (t < t1) for t in attack_times)
        features.append({
            't0': t0, 't1': t1,
            'total_msgs': total_msgs,
            'unique_senders': unique_senders,
            'mean_speed': mean_speed,
            'var_speed': var_speed,
            'mean_neighbors': mean_neighbors,
            'mean_rssi': mean_rssi,
            'scenario': run['scenario'],
            'density': run['density']
        })
        labels.append(1 if has_attack else 0)
    if len(features)==0:
        return None
    X = pd.DataFrame(features)
    y = pd.Series(labels, name='label')
    return X, y

# Test the fixed function with first run
if runs:
    print(f"Testing feature extraction on first run: {runs[0]['path']}")
    result = extract_features_from_run_fixed(runs[0])
    if result:
        X, y = result
        print(f"Successfully extracted features:")
        print(f"X shape: {X.shape}")
        print(f"y shape: {y.shape}")
        print(f"Number of attack windows (y=1): {(y == 1).sum()}")
        print(f"Number of benign windows (y=0): {(y == 0).sum()}")
        print(f"Feature columns: {list(X.columns)}")
        print(f"Sample features:\n{X.head()}")
        print(f"Sample labels:\n{y.head()}")
    else:
        print("Feature extraction returned None - there might be an issue")
else:
    print("No runs found")