#!/usr/bin/env python3
"""
This script fixes the issues in the HISOL notebook
"""

import json

def fix_notebook():
    # Read the original notebook
    with open('/home/jeanhuit/Documents/Workspace/simulation/hisol_multi_scenario_analysis_extended.ipynb', 'r') as f:
        notebook = json.load(f)
    
    # Fix the ROOT path in cell 2
    for cell in notebook['cells']:
        if cell['cell_type'] == 'code':
            source = ''.join(cell['source'])
            if 'ROOT = r"/home/jeanhuit/Documents/Thesis/results"' in source:
                cell['source'] = [line.replace('/home/jeanhuit/Documents/Thesis/results', 
                                             '/home/jeanhuit/Documents/Workspace/simulation/results') 
                                 for line in cell['source']]
                print("Fixed ROOT path in cell")
                break
    
    # Fix the IndexError issue in cell 6 (predict_proba)
    # Find the cell with the problematic predict_proba code
    for i, cell in enumerate(notebook['cells']):
        if cell['cell_type'] == 'code':
            source = ''.join(cell['source'])
            if 'y_prob = clf.predict_proba(X_test_s)[:,1]' in source:
                # Replace the problematic code with safe version
                new_source = []
                for line in cell['source']:
                    if 'y_prob = clf.predict_proba(X_test_s)[:,1]' in line:
                        # Replace the entire problematic section
                        new_source.extend([
                            "# evaluate\n",
                            "y_pred = clf.predict(X_test_s)\n",
                            "# Fix for IndexError: check number of probability columns\n",
                            "if hasattr(clf, 'predict_proba'):\n",
                            "    prob_pred = clf.predict_proba(X_test_s)\n",
                            "    if prob_pred.shape[1] > 1:\n",
                            "        y_prob = prob_pred[:, 1]\n",
                            "    else:\n",
                            "        # If only one class in prediction, use probabilities as-is\n",
                            "        # For evaluation metrics, make predictions reflect the single class issue\n",
                            "        y_prob = prob_pred[:, 0]\n",
                            "else:\n",
                            "    y_prob = None\n"
                        ])
                    elif 'predict_proba' in line and 'y_prob' in line and '[:,1]' not in line:
                        continue  # Skip old lines that are replaced
                    else:
                        new_source.append(line)
                cell['source'] = new_source
                print(f"Fixed predict_proba issue in cell {i}")
                break
    
    # Fix the KeyError issue in cell 7 (trust calculation)
    # Look for the compute_trust_over_time function
    for i, cell in enumerate(notebook['cells']):
        if cell['cell_type'] == 'code' and any('compute_trust_over_time' in line for line in cell['source']):
            # Add safety check for 'node' column
            source_text = ''.join(cell['source'])
            if 'nodes = sorted(bsm[\'node\'].unique())' in source_text:
                # Replace with safer version that checks for the existence of 'node' column
                new_source = []
                for line in cell['source']:
                    if 'nodes = sorted(bsm[\'node\'].unique())' in line:
                        new_source.append("    # Check if required columns exist\n")
                        new_source.append("    if 'node' not in bsm.columns:\n")
                        new_source.append("        print('Error: \"node\" column not found in BSM data')\n")
                        new_source.append("        print('Available columns:', list(bsm.columns))\n")
                        new_source.append("        return None\n")
                        new_source.append("    nodes = sorted(bsm['node'].unique())\n")
                    elif 't_min = bsm[\'time\'].min()' in line:
                        new_source.append("    # Also check for 'time' column\n")
                        new_source.append("    if 'time' not in bsm.columns:\n")
                        new_source.append("        print('Error: \"time\" column not found in BSM data')\n")
                        new_source.append("        return None\n")
                        new_source.append("    t_min = bsm['time'].min()\n")
                    else:
                        new_source.append(line)
                cell['source'] = new_source
                print(f"Fixed KeyError issue in cell {i}")
                break

    # Write the fixed notebook
    with open('/home/jeanhuit/Documents/Workspace/simulation/hisol_multi_scenario_analysis_extended_fixed.ipynb', 'w') as f:
        json.dump(notebook, f, indent=1)

if __name__ == "__main__":
    fix_notebook()