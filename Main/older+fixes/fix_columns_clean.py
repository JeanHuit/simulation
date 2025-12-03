#!/usr/bin/env python3
"""
This script fixes the column mapping with cleaner logic in the HISOL notebook
"""

import json

def fix_notebook_column_mapping_clean():
    # Read the final notebook
    with open('/home/jeanhuit/Documents/Workspace/simulation/hisol_multi_scenario_analysis_extended_final.ipynb', 'r') as f:
        notebook = json.load(f)
    
    # Find the feature extraction function and fix the column assignment
    for i, cell in enumerate(notebook['cells']):
        if cell['cell_type'] == 'code':
            source_text = ''.join(cell['source'])
            if 'def extract_features_from_run' in source_text and '# parse bsm:' in source_text:
                # Completely rewrite the column assignment logic
                new_source = []
                in_bsm_parsing_section = False
                skip_lines = 0
                
                for line in cell['source']:
                    if skip_lines > 0:
                        skip_lines -= 1
                        continue
                    
                    # Detect when we're in the BSM parsing section that needs to be replaced
                    if 'parse bsm: expect columns node,x,y,vx,vy,time (if not, try infer)' in line:
                        in_bsm_parsing_section = True
                        # Add our new logic
                        new_source.append("    # parse bsm: based on data analysis, columns are [time, x, y, vx, vy, node]\n")
                        new_source.append("    if bsm is None:\n")
                        new_source.append("        return None\n")
                        new_source.append("    # Take first 6 columns and assign them to [time, x, y, vx, vy, node]\n")
                        new_source.append("    bsm_df = bsm.iloc[:,0:6].copy()\n")
                        new_source.append("    bsm_df.columns = ['time', 'x', 'y', 'vx', 'vy', 'node']\n")
                        new_source.append("    bsm_df['time'] = pd.to_numeric(bsm_df['time'], errors='coerce')\n")
                        new_source.append("    bsm_df['node'] = bsm_df['node'].astype(int)\n")
                        # Skip the next few lines that are being replaced
                        skip_lines = 6  # Estimated number of lines to skip
                        continue
                    elif in_bsm_parsing_section:
                        # Check if we've reached the next section (RSSI parsing)
                        if 'parse rssi:' in line:
                            in_bsm_parsing_section = False
                        continue
                    
                    new_source.append(line)
                
                cell['source'] = new_source
                print(f"Fixed column mapping cleanly in cell {i}")
                break

    # Write the updated notebook
    with open('/home/jeanhuit/Documents/Workspace/simulation/hisol_multi_scenario_analysis_clean_fixed.ipynb', 'w') as f:
        json.dump(notebook, f, indent=1)

if __name__ == "__main__":
    fix_notebook_column_mapping_clean()