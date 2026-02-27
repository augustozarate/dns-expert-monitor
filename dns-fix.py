#!/usr/bin/env python3
"""
DNS Expert Monitor - Professional JSON Repairer
Uso: dns-fix [OPTIONS] ARCHIVO.json

Opciones:
  --diagnostic    Only diagnose, not repair
  --force         Force repair with aggressive methods
  --no-backup     Do not create backup file
  --output, -o    Output file (default overwrites)
  --help          Show this help
"""
import sys
import os
import json
import re
import shutil
from datetime import datetime

# ANSI Colors
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

def print_help():
    """Show detailed help"""
    print(f"""{Colors.CYAN}╔══════════════════════════════════════════════════════════════╗
║                                                                  ║
║   {Colors.BOLD}🔧 DNS EXPERT MONITOR - JSON REPAIR{Colors.END}{Colors.CYAN}                  ║
║   {Colors.DIM}Advanced Repair of Corrupt JSON Files{Colors.END}{Colors.CYAN}           ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════╝{Colors.END}

{Colors.BOLD}USE:{Colors.END}
  dns-fix [OPTIONS] FILE.json

{Colors.BOLD}OPTIONS:{Colors.END}
  {Colors.CYAN}--diagnostic{Colors.END}    Only diagnose, not repair
  {Colors.CYAN}--force{Colors.END}         Force repair with aggressive methods
  {Colors.CYAN}--no-backup{Colors.END}     Do not create backup file
  {Colors.CYAN}--output, -o{Colors.END}    Output file (default overwrites)
  {Colors.CYAN}--help{Colors.END}          Show this help

{Colors.BOLD}EXAMPLES:{Colors.END}
  {Colors.GREEN}dns-fix --diagnostic capture.json{Colors.END}
  {Colors.GREEN}dns-fix --force capture.json{Colors.END}
  {Colors.GREEN}dns-fix captura.json --output repaired.json{Colors.END}
  {Colors.GREEN}dns-fix --no-backup capture.json{Colors.END}
""")

def diagnostic(filename):
    """Diagnostic mode"""
    print(f"\n{Colors.BOLD}📋 FILE DIAGNOSIS:{Colors.END}")
    print(f"  Archive: {Colors.CYAN}{filename}{Colors.END}")
    
    try:
        size = os.path.getsize(filename)
        print(f"  Size: {size:,} bytes")
        
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
        
        print(f"  Length: {len(content):,} characters")
        print(f"  Start with '[': {content.strip().startswith('[')}")
        print(f"  End with ']': {content.strip().endswith(']')}")
        
        # try to parse
        try:
            data = json.loads(content)
            print(f"{Colors.GREEN}  ✅ VALID JSON{Colors.END}")
            print(f"  Records: {len(data)}")
            return True
        except json.JSONDecodeError as e:
            print(f"{Colors.RED}  ❌ INVALID JSON{Colors.END}")
            print(f"  Error: {e.msg}")
            print(f"  Line: {e.lineno}, Column: {e.colno}")
            print(f"  Position: {e.pos}")
            
            # Show preview of the problem
            start = max(0, e.pos - 50)
            end = min(len(content), e.pos + 50)
            preview = content[start:end]
            print(f"\n{Colors.YELLOW}  Problem Preview:{Colors.END}")
            print(f"  ...{preview}...")
            
            return False
            
    except Exception as e:
        print(f"{Colors.RED}  ❌ Error reading file: {e}{Colors.END}")
        return False

def repair(filename, output=None, force=False, backup=True):
    """Repair JSON file"""
    print(f"\n{Colors.BOLD}🔧 REPAIRING FILE:{Colors.END}")
    
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        content = content.strip()
        
        print(f"  {Colors.CYAN}1.{Colors.END} Correcting basic formatting...")
        
        # STRATEGY 1: Basic correction
        content = re.sub(r',\s*\]', ']', content)
        content = re.sub(r',\s*\}', '}', content)
        
        if not content.startswith('['):
            content = '[' + content.lstrip(',')
        
        content = content.rstrip(',')
        if not content.endswith(']'):
            content += ']'
        
        # try to parse
        try:
            data = json.loads(content)
            print(f"  {Colors.GREEN}  ✅ Successful strategy 1{Colors.END}")
        except json.JSONDecodeError:
            if not force:
                print(f"  {Colors.YELLOW}  ⚠️ Basic error, use --force for advanced recovery{Colors.END}")
                return False
            
            print(f"  {Colors.YELLOW}  ⚠️ Trying advanced recovery...{Colors.END}")
            
            # STRATEGY 2: Extract individual objects
            print(f"  {Colors.CYAN}2.{Colors.END} Extracting JSON objects...")
            pattern = r'\{(?:[^{}]|(?:\{[^{}]*\}))*\}'
            objects = []
            
            for match in re.finditer(pattern, content):
                try:
                    obj = json.loads(match.group())
                    objects.append(obj)
                except:
                    continue
            
            if objects:
                data = objects
                print(f"  {Colors.GREEN}  ✅ Removed {len(objects)} objects{Colors.END}")
            else:
                # STRATEGY 3: Last resort
                print(f"  {Colors.CYAN}3.{Colors.END} Recovery of last resort...")
                lines = content.replace('[', '').replace(']', '').split('\n')
                objects = []
                
                for line in lines:
                    line = line.strip().rstrip(',')
                    if not line:
                        continue
                    
                    try:
                        obj = json.loads(line)
                        objects.append(obj)
                    except:
                        # Try to close keys
                        if line.count('{') > line.count('}'):
                            line += '}'
                        try:
                            obj = json.loads(line)
                            objects.append(obj)
                        except:
                            pass
                
                if objects:
                    data = objects
                    print(f"  {Colors.GREEN} ✅ Recovered {len(objects)} objects {Colors.END}")
                else:
                    print(f"  {Colors.RED} ❌ Could not retrieve any objects {Colors.END}")
                    return False
        
        # Save repaired file
        output_file = output if output else filename
        
        if backup and output_file == filename:
            backup_file = f"{filename}.bak"
            shutil.copy2(filename, backup_file)
            print(f"  {Colors.BLUE}  📦 Backup: {backup_file}{Colors.END}")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"\n{Colors.GREEN}✅ REPAIR COMPLETED{Colors.END}")
        print(f"  📊 Recovered Records: {len(data)}")
        print(f"  💾 Saved file: {output_file}")
        
        return True
        
    except Exception as e:
        print(f"\n{Colors.RED}❌ Error repairing: {e}{Colors.END}")
        return False

def main():
    """Main function"""
    if len(sys.argv) == 1 or '--help' in sys.argv or '-h' in sys.argv:
        print_help()
        sys.exit(0)
    
    # Parse arguments
    diagnostic_mode = '--diagnostic' in sys.argv
    force_mode = '--force' in sys.argv
    no_backup = '--no-backup' in sys.argv
    output_file = None
    
    args = sys.argv[1:]
    filename = None
    
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == '--output' or arg == '-o':
            if i + 1 < len(args):
                output_file = args[i + 1]
                i += 2
                continue
        elif not arg.startswith('--'):
            filename = arg
        i += 1
    
    if not filename:
        print(f"{Colors.RED}❌ Error: No file specified{Colors.END}")
        print_help()
        sys.exit(1)
    
    if not os.path.exists(filename):
        print(f"{Colors.RED}❌ Error: File not found: {filename}{Colors.END}")
        sys.exit(1)
    
    # Run diagnostic mode
    if diagnostic_mode:
        sys.exit(0 if diagnostic(filename) else 1)
    
    # Run repair
    success = repair(filename, output=output_file, force=force_mode, backup=not no_backup)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()