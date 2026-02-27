#!/usr/bin/env python3
"""
🔧 DNS Expert Monitor - JSON Repair Tool
Uso: python fix_json.py [opciones] <archivo.json>

Options:
  --diagnostic    - Only diagnose, not repair
  --force         - Force repair with aggressive methods
  --no-backup     - Do not create backup file
  --output, -o    - Output file (default overwrites)
"""
import sys
import os
import json
import re
import shutil
from datetime import datetime
from typing import List, Any, Optional

# Colors
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

def print_banner():
    """Sample banner"""
    print(f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════╗
║                                                                  ║
║   {Colors.BOLD}🔧 DNS EXPERT MONITOR - JSON REPAIR{Colors.END}{Colors.CYAN}                  ║
║   {Colors.DIM}Advanced Repair of Corrupt JSON Files{Colors.END}{Colors.CYAN}           ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════╝{Colors.END}
""")

def extract_json_objects(content: str) -> List[Any]:
    """Extract individual JSON objects from content"""
    objects = []
    
    # Find complete JSON objects
    pattern = r'\{(?:[^{}]|(?:\{[^{}]*\}))*\}'
    matches = re.finditer(pattern, content)
    
    for match in matches:
        try:
            obj_str = match.group()
            obj = json.loads(obj_str)
            objects.append(obj)
        except:
            continue
    
    return objects

def diagnostic_file(filename: str) -> dict:
    """Diagnose problems in the JSON file"""
    print(f"{Colors.BOLD}📋 FILE DIAGNOSIS:{Colors.END}")
    print(f"  Archive: {Colors.CYAN}{filename}{Colors.END}")
    
    try:
        size = os.path.getsize(filename)
        print(f"  Size: {size:,} bytes")
        
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
        
        print(f"  Length: {len(content):,} characters")
        print(f"  Starts with '[': {content.strip().startswith('[')}")
        print(f"  End with ']': {content.strip().endswith(']')}")
        
        # try to parse
        try:
            data = json.loads(content)
            print(f"{Colors.GREEN}  ✅ VALID JSON{Colors.END}")
            print(f"  Records: {len(data)}")
            return {'valid': True, 'records': len(data)}
        except json.JSONDecodeError as e:
            print(f"{Colors.RED}  ❌ INVALID JSON{Colors.END}")
            print(f"  Error: {e.msg}")
            print(f"  Line: {e.lineno}, Columna: {e.colno}")
            print(f"  Position: {e.pos}")
            
            # Extract objects
            objects = extract_json_objects(content)
            print(f"  JSON objects found: {len(objects)}")
            
            # Show preview of the problem
            start = max(0, e.pos - 50)
            end = min(len(content), e.pos + 50)
            preview = content[start:end]
            print(f"\n{Colors.YELLOW}  Problem Preview:{Colors.END}")
            print(f"  ...{preview}...")
            
            return {'valid': False, 'error': e.msg, 'objects': len(objects)}
            
    except Exception as e:
        print(f"{Colors.RED}  ❌ Error reading file: {e}{Colors.END}")
        return {'valid': False, 'error': str(e)}

def repair_json_advanced(filename: str, output: Optional[str] = None, 
                         force: bool = False, backup: bool = True) -> bool:
    """Repair JSON file with multiple strategies"""
    
    print(f"{Colors.BOLD}🔧 REPAIRING FILE:{Colors.END}")
    
    try:
        # Read file
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        content = content.strip()
        
        # STRATEGY 1: Correct commas and brackets
        print(f"  {Colors.CYAN}1.{Colors.END} Correcting basic formatting...")
        
        # Remove commas before closing brackets
        content = re.sub(r',\s*\]', ']', content)
        content = re.sub(r',\s*\}', '}', content)
        
        # Ensure that it begins with [
        if not content.startswith('['):
            content = '[' + content.lstrip(',')
        
        # Ensure that it ends with ]
        content = content.rstrip(',')
        if not content.endswith(']'):
            content += ']'
        
        # try to parse
        try:
            data = json.loads(content)
            print(f"  {Colors.GREEN}  ✅ Successful strategy 1{Colors.END}")
        except json.JSONDecodeError:
            print(f"  {Colors.YELLOW}  ⚠️  Strategy 1 failed{Colors.END}")
            
            if force:
                # STRATEGY 2: Extract individual objects
                print(f"  {Colors.CYAN}2.{Colors.END} Extracting JSON objects...")
                objects = extract_json_objects(content)
                
                if objects:
                    data = objects
                    print(f"  {Colors.GREEN}  ✅ ERemoved {len(objects)} objects{Colors.END}")
                else:
                    # STRATEGY 3: Divide by lines
                    print(f"  {Colors.CYAN}3.{Colors.END} Processing line by line...")
                    lines = content.replace('[', '').replace(']', '').split('\n')
                    objects = []
                    
                    for i, line in enumerate(lines, 1):
                        line = line.strip().rstrip(',')
                        if not line:
                            continue
                        
                        try:
                            obj = json.loads(line)
                            objects.append(obj)
                        except:
                            # Intentar cerrar llaves
                            if line.count('{') > line.count('}'):
                                line += '}'
                            try:
                                obj = json.loads(line)
                                objects.append(obj)
                            except:
                                pass
                    
                    if objects:
                        data = objects
                        print(f"  {Colors.GREEN} ✅ Extracted {len(objects)} objects by lines {Colors.END}")
                    else:
                        # STRATEGY 4: Emergency Recovery
                        print(f"  {Colors.CYAN}4.{Colors.END} Emergency Recovery...")
                        import ast
                        try:
                            # Try to evaluate as Python literal
                            data = ast.literal_eval(content)
                            print(f"  {Colors.GREEN}  ✅ Recovered with ast.literal_eval{Colors.END}")
                        except:
                            raise Exception("Could not retrieve JSON")
        
        # Save repaired file
        output_file = output if output else filename
        
        if backup and output_file == filename:
            backup_file = f"{filename}.bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(filename, backup_file)
            print(f"  {Colors.BLUE}  📦 Backup created: {backup_file}{Colors.END}")
        
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
    print_banner()
    
    if len(sys.argv) < 2:
        print(f"{Colors.YELLOW}Usage:{Colors.END} python fix_json.py [options] <file.json>")
        print(f"\n{Colors.BOLD}Options:{Colors.END}")
        print("  --diagnostic    - Only diagnose, not repair")
        print("  --force         - Force repair with aggressive methods")
        print("  --no-backup     - Do not create backup file")
        print("  --output, -o    - Output file")
        print(f"\n{Colors.BOLD}Examples:{Colors.END}")
        print("  python fix_json.py captura.json")
        print("  python fix_json.py --diagnostic captura.json")
        print("  python fix_json.py --force captura.json --output reparado.json")
        sys.exit(1)
    
    # Parse arguments
    diagnostic = '--diagnostic' in sys.argv
    force = '--force' in sys.argv
    no_backup = '--no-backup' in sys.argv
    
    # Get file
    filename = None
    output = None
    
    args = sys.argv[1:]
    for i, arg in enumerate(args):
        if arg == '--output' or arg == '-o':
            if i + 1 < len(args):
                output = args[i + 1]
        elif not arg.startswith('--') and not filename:
            filename = arg
    
    if not filename:
        print(f"{Colors.RED}❌ Error: No file specified{Colors.END}")
        sys.exit(1)
    
    if not os.path.exists(filename):
        print(f"{Colors.RED}❌ Error: File not found: {filename}{Colors.END}")
        sys.exit(1)
    
    # Diagnostic mode
    if diagnostic:
        result = diagnostic_file(filename)
        sys.exit(0 if result.get('valid') else 1)
    
    # Repair mode
    success = repair_json_advanced(
        filename, 
        output=output,
        force=force,
        backup=not no_backup
    )
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()