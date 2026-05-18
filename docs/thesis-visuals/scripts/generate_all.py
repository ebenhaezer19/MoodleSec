"""MoodleSec Thesis — Generate All Visual Assets"""
import subprocess, sys, os

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))

scripts = [
    "generate_eval_charts.py",
    "generate_soc_charts.py",
]

if __name__ == '__main__':
    print("=" * 60)
    print("MoodleSec Thesis Visual Asset Generator")
    print("=" * 60)
    for s in scripts:
        path = os.path.join(SCRIPTS_DIR, s)
        print(f"\n>>> Running {s}...")
        result = subprocess.run([sys.executable, path], capture_output=True, text=True)
        print(result.stdout)
        if result.returncode != 0:
            print(f"ERROR in {s}:\n{result.stderr}")
    # List outputs
    base = os.path.dirname(SCRIPTS_DIR)
    png_dir = os.path.join(base, "output", "png")
    svg_dir = os.path.join(base, "output", "svg")
    mmd_dir = os.path.join(base, "mermaid")
    print("\n" + "=" * 60)
    print("GENERATED ASSETS SUMMARY")
    print("=" * 60)
    for label, d in [("PNG Charts", png_dir), ("SVG Charts", svg_dir), ("Mermaid Diagrams", mmd_dir)]:
        if os.path.isdir(d):
            files = sorted(os.listdir(d))
            print(f"\n{label} ({len(files)} files) -> {d}")
            for f in files:
                size = os.path.getsize(os.path.join(d, f))
                print(f"  {f:45s} {size:>8,} bytes")
    print("\n" + "=" * 60)
    print("Done! All assets ready for thesis.")
