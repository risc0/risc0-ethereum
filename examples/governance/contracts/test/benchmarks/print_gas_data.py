import csv
from prettytable import PrettyTable

def print_nice_table(filename):
    baseline_data = {}
    risczero_data = {}

    # Read the CSV file
    with open(filename, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            governor, accounts, gas = row
            accounts = int(accounts)
            gas = int(gas)
            if governor == 'BaselineGovernor':
                baseline_data[accounts] = gas
            else:
                risczero_data[accounts] = gas

    # Create a sorted list of all unique account numbers
    all_accounts = sorted(set(baseline_data.keys()) | set(risczero_data.keys()))

    # Create and populate the table
    table = PrettyTable()
    table.field_names = ["Votes", "BaselineGovernor Gas", "RiscZeroGovernor Gas", "Gas Savings", "% Savings"]
    table.align["Votes"] = "r"
    table.align["BaselineGovernor Gas"] = "r"
    table.align["RiscZeroGovernor Gas"] = "r"
    table.align["Gas Savings"] = "r"
    table.align["% Savings"] = "r"

    for accounts in all_accounts:
        baseline_gas = baseline_data.get(accounts, "N/A")
        risczero_gas = risczero_data.get(accounts, "N/A")
        
        if baseline_gas != "N/A" and risczero_gas != "N/A":
            gas_savings = baseline_gas - risczero_gas
            percent_savings = (gas_savings / baseline_gas) * 100
            table.add_row([
                accounts,
                f"{baseline_gas:,}",
                f"{risczero_gas:,}",
                f"{gas_savings:,}",
                f"{percent_savings:.2f}%"
            ])
        else:
            table.add_row([accounts, baseline_gas, risczero_gas, "N/A", "N/A"])

    print(table)

# Usage
print_nice_table('gas_data.csv')
