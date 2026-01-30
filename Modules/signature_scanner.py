"""
Signature Scanner Module - YARA-based Ransomware Detection
Integrates signature-based detection for known ransomware families using YARA rules.

FEATURES:
- Loads and compiles YARA rules from a directory
- Scans process executables for matches
- Supports commoditized and HoR ransomware signatures
- Low-overhead scanning on process creation

DEPENDENCIES:
- yara-python (pip install yara-python)

RULE SOURCES:
- Incorporated samples from public repositories (ReversingLabs, etc.)
- Expand by adding .yar files to 'rules/' directory
- Update rules quarterly from sources like:
  - https://github.com/reversinglabs/reversinglabs-yara-rules
  - https://github.com/advanced-threat-research/Yara-Rules
  - https://github.com/Yara-Rules/rules
  - Malpedia, Ransomware.live

USAGE:
scanner = SignatureScanner(rules_dir='rules/')
hits = scanner.scan(executable_path)
"""

import yara
import logging
from pathlib import Path
from typing import List, Optional

class SignatureScanner:
    """
    YARA-based scanner for ransomware signatures.
    
    MAINTENANCE:
    - Add new .yar files to rules_dir for emerging threats
    - Compile once at init for performance
    - Handle large files via timeout (configurable)
    """
    
    def __init__(self, rules_dir: str = 'rules/', timeout: int = 30):
        self.rules_dir = Path(rules_dir)
        self.timeout = timeout
        self.compiled_rules: Optional[yara.Rules] = None
        self._setup_logging()
        self._compile_rules()
    
    def _setup_logging(self):
        """Configure logging."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger("SignatureScanner")
    
    def _compile_rules(self):
        """Compile all .yar files in rules_dir."""
        if not self.rules_dir.exists():
            self.rules_dir.mkdir(parents=True)
            self.logger.warning(f"Created empty rules directory: {self.rules_dir}")
            # Add sample rules as fallback
            self._create_sample_rules()
        
        rule_files = {}
        for yar_file in self.rules_dir.glob('*.yar'):
            if yar_file.is_file():
                rule_files[str(yar_file.stem)] = str(yar_file)
        
        if not rule_files:
            self.logger.error("No YARA rules found. Add .yar files to rules_dir.")
            return
        
        try:
            self.compiled_rules = yara.compile(filepaths=rule_files)
            self.logger.info(f"Compiled {len(rule_files)} YARA rules successfully.")
        except yara.SyntaxError as e:
            self.logger.error(f"YARA syntax error: {e}")
        except Exception as e:
            self.logger.error(f"Compilation failed: {e}")
    
    def _create_sample_rules(self):
        """Create sample YARA rules file if directory is empty."""
        sample_rules = """
// Sample LockBit Rule (from ReversingLabs)
rule Win32_Ransomware_LockBit : tc_detection malicious
{
    meta:
        author              = "ReversingLabs"
        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "LOCKBIT"
        description         = "Yara rule that detects LockBit ransomware."
        tc_detection_type   = "Ransomware"
        tc_detection_name   = "LockBit"
        tc_detection_factor = 5

    strings:
        // Truncated for brevity; full rule from source
        $enum_resources_v1 = { 55 8B EC 83 EC ?? 57 8D 45 ?? C7 45 ?? ?? ?? ?? ?? 50 51 6A ?? 6A ?? 6A ?? C7 45 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }

    condition:
        uint16(0) == 0x5A4D and $enum_resources_v1
}

// Add more samples here from sources like Conti and Ryuk (see comments in file header)
"""
        sample_path = self.rules_dir / 'sample_ransomware.yar'
        sample_path.write_text(sample_rules)
        self.logger.info(f"Created sample rules file: {sample_path}")

    def scan(self, file_path: Optional[str]) -> List[str]:
        """
        Scan a file for ransomware signatures.
        
        Args:
            file_path: Path to executable to scan (from ProcessEvent.executable_path)
        
        Returns:
            List of matched rule names (e.g., ['Win32_Ransomware_LockBit'])
        """
        if not self.compiled_rules:
            self.logger.warning("No compiled rules available. Skipping scan.")
            return []
        
        if not file_path or not Path(file_path).exists():
            self.logger.debug(f"Invalid or missing file path: {file_path}")
            return []
        
        try:
            matches = self.compiled_rules.match(filepath=file_path, timeout=self.timeout)
            hit_rules = [match.rule for match in matches]
            if hit_rules:
                self.logger.warning(f"Signature hits for {file_path}: {hit_rules}")
            return hit_rules
        except yara.TimeoutError:
            self.logger.error(f"Scan timeout for {file_path}")
            return []
        except yara.Error as e:
            self.logger.error(f"YARA error scanning {file_path}: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Unexpected error scanning {file_path}: {e}")
            return []

# Example usage (for testing)
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        scanner = SignatureScanner()
        hits = scanner.scan(sys.argv[1])
        print(f"Hits: {hits}")
    else:
        print("Usage: python signature_scanner.py <file_path>")
