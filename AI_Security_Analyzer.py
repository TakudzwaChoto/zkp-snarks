'''
###### Below is command prompt result to test if ai-security-analyzer is successfully installed:
(.venv) PS E:\zkp-snarks-main\.venv\Scripts> pip show ai-security-analyzer
Name: ai-security-analyzer
Version: 0.0.55
Summary:
Home-page:
Author: xvnpw
Author-email: 17719543+xvnpw@users.noreply.github.com
License: MIT
Location: E:\zkp-snarks-main\.venv\Lib\site-packages
Requires: langchain-anthropic, langchain-community, langchain-core, langchain-google-genai, langchain-openai, langchain-text-splitters, langgraph, langgraph-checkpoint-sqlite, langgraph-sdk, langsmith, pathvalidate, pyyaml, six, types-pyyaml
Required-by:
(.venv) PS E:\zkp-snarks-main\.venv\Scripts> 


######After  getting result, you can use command prompts from official documentation or using dynamic approach of a script but the same thing.
'''

#!/usr/bin/env python3
"""
AI Security Analyzer for ZKP Projects
"""

import os
import sys
import logging
import subprocess
import importlib.util
from pathlib import Path
from typing import Dict, Any, Optional, List

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SecurityAnalyzer:
    def __init__(self, project_path: str):
        self.project_path = Path(project_path).resolve()
        self.venv_python = sys.executable
        self.venv_site_packages = self._find_site_packages()
        
    def _find_site_packages(self) -> Optional[Path]:
        """Find site-packages directory in the current virtual environment"""
        try:
            import site
            return Path(site.getsitepackages()[0])
        except Exception as e:
            logger.warning(f"Could not find site-packages: {e}")
            return None

    def analyze(self, output_file: str = "security_report.md") -> bool:
        """Run security analysis on the project"""
        logger.info(f"Starting security analysis of: {self.project_path}")
        
        # Try different methods to run the analysis
        methods = [
            self._try_full_dir_scan,
            self._try_import_analyzer,
            self._try_cli_command,
            self._try_manual_analysis
        ]
        
        for method in methods:
            try:
                if method(output_file):
                    return True
            except Exception as e:
                logger.debug(f"Method {method.__name__} failed: {e}")
                continue
                
        logger.error("All analysis methods failed. Please check the logs for details.")
        return False

    def _try_full_dir_scan(self, output_file: str) -> bool:
        """Try using full_dir_scan_agents module directly"""
        logger.info("Attempting to use full_dir_scan_agents...")
        try:
            from ai_security_analyzer.full_dir_scan_agents import run_full_dir_scan
            run_full_dir_scan(
                target_dir=str(self.project_path),
                output_file=output_file,
                verbose=True
            )
            return True
        except ImportError as e:
            logger.debug(f"Could not import full_dir_scan_agents: {e}")
            return False

    def _try_import_analyzer(self, output_file: str) -> bool:
        """Try importing and using the analyzer directly"""
        logger.info("Attempting to import security analyzer...")
        try:
            # Try to find and import the main analyzer module
            if self.venv_site_packages:
                analyzer_path = self.venv_site_packages / 'ai_security_analyzer'
                if analyzer_path.exists():
                    # Try to find the main module
                    for module_file in analyzer_path.glob('*.py'):
                        if module_file.stem != '__init__':
                            module_name = f"ai_security_analyzer.{module_file.stem}"
                            try:
                                module = __import__(module_name, fromlist=['*'])
                                if hasattr(module, 'main'):
                                    logger.info(f"Found main function in {module_name}")
                                    # Run the module's main function
                                    module.main([
                                        str(self.project_path),
                                        '--output', output_file
                                    ])
                                    return True
                            except Exception as e:
                                logger.debug(f"Error importing {module_name}: {e}")
            return False
        except Exception as e:
            logger.debug(f"Error in _try_import_analyzer: {e}")
            return False

    def _try_cli_command(self, output_file: str) -> bool:
        """Try running the analyzer as a CLI command"""
        logger.info("Attempting to run as CLI command...")
        try:
            cmd = [
                self.venv_python,
                "-m", "ai_security_analyzer",
                str(self.project_path),
                "--output", output_file
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                return True
            logger.debug(f"CLI command failed: {result.stderr}")
            return False
        except Exception as e:
            logger.debug(f"Error running CLI command: {e}")
            return False

    def _try_manual_analysis(self, output_file: str) -> bool:
        """Fallback manual analysis if automated methods fail"""
        logger.info("Performing manual security analysis...")
        try:
            # Basic security checks
            issues = self._check_security_issues()
            
            # Write report
            with open(output_file, 'w') as f:
                f.write("# Security Analysis Report\n\n")
                f.write("## Summary\n")
                f.write(f"Scanned directory: {self.project_path}\n")
                f.write(f"Total issues found: {len(issues)}\n\n")
                
                if issues:
                    f.write("## Security Issues\n")
                    for i, issue in enumerate(issues, 1):
                        f.write(f"### Issue {i}: {issue['title']}\n")
                        f.write(f"**File:** {issue.get('file', 'N/A')}\n")
                        f.write(f"**Severity:** {issue.get('severity', 'medium')}\n")
                        f.write(f"**Description:** {issue.get('description', 'No description')}\n")
                        f.write(f"**Recommendation:** {issue.get('recommendation', 'No recommendation')}\n\n")
                else:
                    f.write("No security issues found.\n")
            
            logger.info(f"Manual analysis complete. Report saved to: {output_file}")
            return True
        except Exception as e:
            logger.error(f"Manual analysis failed: {e}")
            return False

    def _check_security_issues(self) -> List[Dict[str, Any]]:
        """Perform basic security checks on the project"""
        issues = []
        
        # Check for common security issues
        if (self.project_path / 'app.py').exists():
            issues.extend(self._check_flask_security())
            
        # Add more security checks as needed
        # issues.extend(self._check_other_security_issues())
        
        return issues

    def _check_flask_security(self) -> List[Dict[str, Any]]:
        """Check for common Flask security issues"""
        issues = []
        app_path = self.project_path / 'app.py'
        
        try:
            with open(app_path, 'r') as f:
                content = f.read()
                
                # Check for debug mode
                if 'debug=True' in content or 'debug = True' in content:
                    issues.append({
                        'title': 'Debug Mode Enabled in Production',
                        'file': str(app_path),
                        'severity': 'high',
                        'description': 'Debug mode is enabled in a production environment.',
                        'recommendation': 'Disable debug mode in production by setting debug=False'
                    })
                
                # Check for secret key
                if 'SECRET_KEY' not in content or 'your-secret-key' in content:
                    issues.append({
                        'title': 'Insecure or Missing Secret Key',
                        'file': str(app_path),
                        'severity': 'high',
                        'description': 'The application is using a default or missing secret key.',
                        'recommendation': 'Generate a strong secret key and store it in an environment variable'
                    })
                    
        except Exception as e:
            logger.error(f"Error checking Flask security: {e}")
            
        return issues

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='AI Security Analyzer')
    parser.add_argument(
        'path',
        nargs='?',
        default='.',
        help='Path to project directory (default: current directory)'
    )
    parser.add_argument(
        '-o', '--output',
        default='security_report.md',
        help='Output file path (default: security_report.md)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    try:
        analyzer = SecurityAnalyzer(args.path)
        success = analyzer.analyze(args.output)
        
        if success:
            logger.info(f"Analysis completed successfully! Report saved to: {args.output}")
            return 0
        else:
            logger.error("Analysis failed. Please check the logs for more information.")
            return 1
            
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        if args.verbose:
            import traceback
            logger.debug(traceback.format_exc())
        return 1

if __name__ == "__main__":
    sys.exit(main())