import csv
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import ScalarFormatter, NullFormatter

def plot_gas_data(filename):
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

    # Sort the data
    baseline_sorted = sorted(baseline_data.items())
    risczero_sorted = sorted(risczero_data.items())

    # Separate x and y for plotting
    baseline_x, baseline_y = zip(*baseline_sorted)
    risczero_x, risczero_y = zip(*risczero_sorted)

    # Calculate average gas savings
    common_x = set(baseline_x) & set(risczero_x)
    savings = [(baseline_data[x] - risczero_data[x]) / baseline_data[x] * 100 for x in common_x]
    avg_savings = np.mean(savings)

    # Create the plot
    fig, ax = plt.subplots(figsize=(12, 8))
    ax.plot(baseline_x, baseline_y, label='BaselineGovernor', marker='o', linestyle='-', linewidth=2)
    ax.plot(risczero_x, risczero_y, label='RiscZeroGovernor', marker='s', linestyle='--', linewidth=2)

    ax.set_xlabel('Number of Votes')
    ax.set_ylabel('Gas Spent')
    ax.set_title('Gas Data Comparison: BaselineGovernor vs RiscZeroGovernor')
    
    # Move legend to upper left
    ax.legend(loc='upper left')
    
    ax.grid(True, which="both", ls="-", alpha=0.2)

    # Use logarithmic scale for better visibility
    ax.set_xscale('log')
    ax.set_yscale('log')

    # Customize x-axis
    ax.xaxis.set_major_formatter(ScalarFormatter())
    ax.xaxis.set_minor_formatter(NullFormatter())

    # Customize y-axis
    ax.yaxis.set_major_formatter(ScalarFormatter(useMathText=True))
    ax.ticklabel_format(style='sci', axis='y', scilimits=(0,0))

    # Add some key data points with adjusted positions
    for x in [100, 500, 1000]:
        if x in baseline_data and x in risczero_data:
            # BaselineGovernor label
            ax.annotate(f'({x}, {baseline_data[x]:,})', 
                        xy=(x, baseline_data[x]), xytext=(5, -20), 
                        textcoords='offset points', fontsize=8,
                        arrowprops=dict(arrowstyle='->', connectionstyle='arc3,rad=0'))
            
            # RiscZeroGovernor label (now also moved down)
            ax.annotate(f'({x}, {risczero_data[x]:,})', 
                        xy=(x, risczero_data[x]), xytext=(5, -15), 
                        textcoords='offset points', fontsize=8,
                        arrowprops=dict(arrowstyle='->', connectionstyle='arc3,rad=0'))

    # Add summary statistics
    stats_text = f'Average Gas Savings: {avg_savings:.2f}%'
    ax.text(0.95, 0.05, stats_text, transform=ax.transAxes, fontsize=10,
            verticalalignment='bottom', horizontalalignment='right',
            bbox=dict(boxstyle='round', facecolor='white', alpha=0.8))

    # Save the plot as a PNG file (removed '_improved')
    plt.savefig('gas_data_comparison.png', dpi=300, bbox_inches='tight')
    print("Plot saved as gas_data_comparison.png")

# Usage
plot_gas_data('gas_data.csv')
