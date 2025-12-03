#!/usr/bin/env python3
"""
This script fixes the column name issue in the HISOL notebook
"""

import json

def fix_notebook_column_names():
    # Read the final notebook
    with open('/home/jeanhuit/Documents/Workspace/simulation/hisol_multi_scenario_analysis_extended_final.ipynb', 'r') as f:
        notebook = json.load(f)
    
    # Find the feature extraction function and fix the column assignment
    for i, cell in enumerate(notebook['cells']):
        if cell['cell_type'] == 'code':
            source_text = ''.join(cell['source'])
            if 'def extract_features_from_run' in source_text or 'bsm_df = bsm.iloc[:,0:6].copy()' in source_text:
                # Update the cell to fix the column mapping based on our analysis
                new_source = []
                for line in cell['source']:
                    if 'bsm_df = bsm[[' in line and 'node' in line:
                        # Skip this line and replace with proper column assignment
                        continue
                    elif 'bsm_df = bsm.iloc[:,0:6].copy()' in line:
                        # Replace with mapping based on the actual data structure
                        # From our test, it seems the data is [time, x, y, vx, vy, node] but in numeric columns
                        new_source.append("        bsm_df = bsm.iloc[:,0:6].copy()\n")
                        new_source.append("        # Based on data analysis, columns appear to be: [time, x, y, vx, vy, node]\n")
                        new_source.append("        bsm_df.columns = ['time', 'x', 'y', 'vx', 'vy', 'node']\n")
                    elif "bsm_df['time'] = pd.to_numeric(bsm_df['time']" in line:
                        new_source.append(line)
                    elif "bsm_df['node'] = bsm_df['node'].astype(int)" in line:
                        new_source.append(line)
                    else:
                        new_source.append(line)
                cell['source'] = new_source
                print(f"Fixed column assignment in cell {i}")
                break

    # Write the updated notebook
    with open('/home/jeanhuit/Documents/Workspace/simulation/hisol_multi_scenario_analysis_extended_final2.ipynb', 'w') as f:
        json.dump(notebook, f, indent=1)

if __name__ == "__main__":
    fix_notebook_column_names()