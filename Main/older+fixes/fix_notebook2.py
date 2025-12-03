#!/usr/bin/env python3
"""
This script fixes the /mnt/data paths in the HISOL notebook
"""

import json

def fix_mnt_paths():
    # Read the fixed notebook
    with open('/home/jeanhuit/Documents/Workspace/simulation/hisol_multi_scenario_analysis_extended_fixed.ipynb', 'r') as f:
        notebook = json.load(f)
    
    # Replace /mnt/data paths with local paths
    for cell in notebook['cells']:
        if cell['cell_type'] == 'code':
            new_source = []
            for line in cell['source']:
                if '"/mnt/data/hisol_models"' in line:
                    new_source.append(line.replace('"/mnt/data/hisol_models"', '"/home/jeanhuit/Documents/Workspace/simulation/models"'))
                elif '"/mnt/data/hisol_figs"' in line:
                    new_source.append(line.replace('"/mnt/data/hisol_figs"', '"/home/jeanhuit/Documents/Workspace/simulation/figures"'))
                elif '"/mnt/data/hisol_analysis_output"' in line:
                    new_source.append(line.replace('"/mnt/data/hisol_analysis_output"', '"/home/jeanhuit/Documents/Workspace/simulation/output"'))
                else:
                    new_source.append(line)
            cell['source'] = new_source

    # Write the updated notebook
    with open('/home/jeanhuit/Documents/Workspace/simulation/hisol_multi_scenario_analysis_extended_final.ipynb', 'w') as f:
        json.dump(notebook, f, indent=1)

if __name__ == "__main__":
    fix_mnt_paths()