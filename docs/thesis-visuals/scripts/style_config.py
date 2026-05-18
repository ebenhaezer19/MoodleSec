"""MoodleSec Thesis — Shared Style Configuration"""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import os

# Paths
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PNG = os.path.join(BASE, "output", "png")
SVG = os.path.join(BASE, "output", "svg")
os.makedirs(PNG, exist_ok=True)
os.makedirs(SVG, exist_ok=True)

# Color palette — SOC/SIEM professional
C_PRIMARY = '#1e3a5f'
C_SECONDARY = '#2563eb'
C_ACCENT = '#00bcd4'
C_SUCCESS = '#10b981'
C_WARNING = '#f59e0b'
C_DANGER = '#ef4444'
C_PURPLE = '#8b5cf6'
C_PINK = '#ec4899'
C_GRAY = '#6b7280'
C_LIGHT = '#f3f4f6'
C_BG = '#ffffff'

PALETTE = [C_SECONDARY, C_SUCCESS, C_WARNING, C_DANGER, C_PURPLE, C_PINK, C_ACCENT, C_PRIMARY]

# Apply global style
plt.rcParams.update({
    'font.family': 'sans-serif',
    'font.sans-serif': ['DejaVu Sans', 'Arial', 'Helvetica'],
    'font.size': 11,
    'axes.titlesize': 14,
    'axes.titleweight': 'bold',
    'axes.labelsize': 12,
    'axes.facecolor': C_BG,
    'figure.facecolor': C_BG,
    'figure.dpi': 300,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
    'savefig.pad_inches': 0.3,
    'axes.grid': True,
    'grid.alpha': 0.2,
    'grid.linestyle': '--',
    'axes.spines.top': False,
    'axes.spines.right': False,
    'legend.framealpha': 0.9,
    'legend.edgecolor': '#e5e7eb',
})

def save(fig, name):
    """Save figure as both PNG and SVG."""
    fig.savefig(os.path.join(PNG, f"{name}.png"))
    fig.savefig(os.path.join(SVG, f"{name}.svg"))
    plt.close(fig)
    print(f"  [OK] {name}")
