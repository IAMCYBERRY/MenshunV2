#!/usr/bin/env python3
"""
Simple Python starter script for Menshen PAM
Automatically handles port conflicts and starts the application
"""

import subprocess
import sys
import os

def main():
    print("🚀 Menshen PAM Quick Start")
    print("=" * 40)
    
    try:
        # Run the port checker first
        print("🔍 Checking and configuring ports...")
        result = subprocess.run([sys.executable, "scripts/check_ports.py"], 
                              capture_output=False, text=True)
        
        if result.returncode not in [0, 1]:  # 0 = no port changes, 1 = ports changed
            print("❌ Error during port configuration")
            return 1
        
        print("\n" + "=" * 40)
        choice = input("🐳 Start Docker services? (y/N): ").strip().lower()
        
        if choice in ['y', 'yes']:
            print("🔄 Starting Docker Compose...")
            subprocess.run(["docker-compose", "up", "--build", "-d"], check=True)
            
            print("⏳ Services starting... Please wait...")
            
            # Get the web port from the updated docker-compose.yml
            try:
                with open('docker-compose.yml', 'r') as f:
                    content = f.read()
                    for line in content.split('\n'):
                        if '"' in line and ':8000"' in line:
                            port = line.split('"')[1].split(':')[0]
                            break
                    else:
                        port = "8001"  # fallback
            except:
                port = "8001"  # fallback
            
            print(f"\n🎉 Menshen PAM is starting!")
            print(f"\n🌐 Once ready, access at:")
            print(f"   Dashboard: http://localhost:{port}")
            print(f"   Admin Panel: http://localhost:{port}/admin")
            print(f"   API: http://localhost:{port}/api")
            print(f"\n💡 Run 'docker-compose logs -f' to see startup logs")
            print(f"🛑 Run 'docker-compose down' to stop services")
            
        else:
            print("❌ Startup cancelled")
            return 0
            
    except subprocess.CalledProcessError as e:
        print(f"❌ Error: {e}")
        return 1
    except KeyboardInterrupt:
        print("\n❌ Cancelled by user")
        return 1

if __name__ == "__main__":
    sys.exit(main())