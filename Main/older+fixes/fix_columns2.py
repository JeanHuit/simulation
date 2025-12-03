#!/usr/bin/env python3
"""
This script properly fixes the column name issue in the HISOL notebook
"""

import json

def fix_notebook_column_names():
    # Read the final notebook
    with open('/home/jeanhuit/Documents/Workspace/simulation/hisol_multi_scenario_analysis_extended_final2.ipynb', 'r') as f:
        notebook = json.load(f)
    
    # Find the feature extraction function and fix the column assignment
    for i, cell in enumerate(notebook['cells']):
        if cell['cell_type'] == 'code':
            source_text = ''.join(cell['source'])
            if 'def extract_features_from_run' in source_text and 'parse bsm:' in source_text:
                new_source = []
                for line in cell['source']:
                    if 'bsm_df = bsm[[' in line and 'node' in line:
                        # This line should be removed since the expected columns don't match the actual data
                        continue
                    elif 'if set([' in line and 'node' in line and 'time' in line:
                        # Skip this line as well since condition will fail
                        continue
                    elif 'bsm_df[' in line and 'node' in line and 'time' in line and 'issubset' in line:
                        # Skip this entire conditional block
                        continue
                    elif 'try assign first 6 columns' in line:
                        # We'll add our logic right after this comment
                        new_source.append("        # try assign first 6 columns - but in the correct order for actual data: [time, x, y, vx, vy, node]\n")
                        new_source.append("        bsm_df = bsm.iloc[:,0:6].copy()\n")
                        new_source.append("        bsm_df.columns = ['time', 'x', 'y', 'vx', 'vy', 'node']\n")
                    elif "bsm_df = bsm.iloc[:,0:6].copy()" in line and "bsm_df.columns" not in line:
                        # Skip this line since we handle it with the previous one
                        continue
                    elif "bsm_df.columns = ['node','x','y','vx','vy','time']" in line:
                        # Skip this line as well
                        continue
                    else:
                        new_source.append(line)
                cell['source'] = new_source
                print(f"Fixed column assignment in cell {i}")
                break

    # Write the updated notebook
    with open('/home/jeanhuit/Documents/Workspace/simulation/hisol_multi_scenario_analysis_extended_fixed_complete.ipynb', 'w') as f:
        json.dump(notebook, f, indent=1)

if __name__ == "__main__":
    fix_notebook_column_names()