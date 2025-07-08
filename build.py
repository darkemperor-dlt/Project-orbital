import os
import sys
import subprocess

def build_executable():
    print("Building Orbital executable...")
    
    # Install required packages with hash validation
    print("Installing dependencies with hash validation...")
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--require-hashes", "-r", "requirements.txt"],
            check=True
        )
    except subprocess.CalledProcessError as e:
        print(f"Error: Dependency installation failed. {e}")
        print("Please ensure your requirements.txt file includes hashes for all packages.")
        sys.exit(1)

    # Build the executable
    print("Building executable with PyInstaller...")
    build_command = [
        "pyinstaller",
        "--onefile",
        "--windowed",
        "--name", "Orbital",
        "--add-data", "README.md;.",
        "--add-data", "filter_presets.json;.",
        "--hidden-import", "cryptography",
        "--uac-admin",
        "orbital.py"
    ]
    
    subprocess.run(build_command)
    
    print("\nBuild complete! The executable can be found in the 'dist' folder.")
    print("The application will now prompt for administrator rights on launch.")

if __name__ == "__main__":
    build_executable()
 