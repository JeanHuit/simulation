#!/usr/bin/env python3
"""
This script properly fixes the column mapping in the HISOL notebook
"""

import json

def fix_notebook_column_mapping():
    # Read the final notebook
    with open('/home/jeanhuit/Documents/Workspace/simulation/hisol_multi_scenario_analysis_extended_final.ipynb', 'r') as f:
        notebook = json.load(f)
    
    # Find the feature extraction function and fix the column assignment
    for i, cell in enumerate(notebook['cells']):
        if cell['cell_type'] == 'code':
            source_text = ''.join(cell['source'])
            if 'def extract_features_from_run' in source_text and '# parse bsm:' in source_text:
                # Replace the problematic column assignment logic
                new_source = []
                skip_next_line = False
                
                for line_idx, line in enumerate(cell['source']):
                    if skip_next_line:
                        skip_next_line = False
                        continue
                    
                    if 'bsm_df[[' in line and 'node' in line and 'time' in line and 'copy()' in line:
                        # Replace the wrong column selection logic
                        new_source.append("        # Based on data analysis, columns are in order: [time, x, y, vx, vy, node]\n")
                        new_source.append("        bsm_df = bsm.iloc[:,0:6].copy()\n")
                        new_source.append("        bsm_df.columns = ['time', 'x', 'y', 'vx', 'vy', 'node']\n")
                    elif "if set(['node','x','y','vx','vy','time']).issubset(set(cols)):" in line:
                        # Skip the entire conditional and its body
                        # The next few lines should be skipped
                        skip_next_line = True  # Skip the immediate next line
                        # We'll also skip processing for a few more lines based on the known structure
                        continue  
                    elif 'bsm_df[[' in line and 'node' in line and 'copy()' in line and 'cols' not in line:
                        continue  # Skip this line too
                    elif 'cols = list(' in line and 'bsm.columns' in line:
                        continue  # Skip this line
                    elif 'try assign first 6 columns' in line:
                        # Replace with the correct logic
                        new_source.append("        # Based on data analysis, take first 6 columns and map to [time, x, y, vx, vy, node]\n")
                        new_source.append("        bsm_df = bsm.iloc[:,0:6].copy()\n")
                        new_source.append("        bsm_df.columns = ['time', 'x', 'y', 'vx', 'vy', 'node']\n")
                    else:
                        new_source.append(line)
                        
                cell['source'] = new_source
                print(f"Fixed column mapping in cell {i}")
                break

    # Write the updated notebook
    with open('/home/jeanhuit/Documents/Workspace/simulation/hisol_multi_scenario_analysis_extended_fixed_complete.ipynb', 'w') as f:
        json.dump(notebook, f, indent=1)

if __name__ == "__main__":
    fix_notebook_column_mapping()