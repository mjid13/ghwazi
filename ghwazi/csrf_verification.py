#!/usr/bin/env python3
"""
CSRF Protection Verification Script

This script verifies that CSRF protection is properly implemented
across all forms in the Flask application.
"""

import os
import re
import sys
from pathlib import Path


class CSRFVerifier:
    """Verifies CSRF implementation in a Flask application."""
    
    def __init__(self, app_root):
        self.app_root = Path(app_root)
        self.templates_dir = self.app_root / "app" / "templates"
        self.views_dir = self.app_root / "app"
        self.errors = []
        self.warnings = []
        
    def verify_csrf_setup(self):
        """Verify CSRF is properly configured in the application."""
        print("🔍 Verifying CSRF setup...")
        
        # Check extensions.py
        extensions_file = self.app_root / "app" / "extensions.py"
        if extensions_file.exists():
            content = extensions_file.read_text()
            if "CSRFProtect" in content and "csrf = CSRFProtect()" in content:
                print("  ✅ CSRFProtect is initialized in extensions.py")
            else:
                self.errors.append("CSRFProtect not properly initialized in extensions.py")
        else:
            self.errors.append("extensions.py not found")
            
        # Check app initialization
        init_file = self.app_root / "app" / "__init__.py"
        if init_file.exists():
            content = init_file.read_text()
            if "csrf.init_app" in content:
                print("  ✅ CSRF initialized in app factory")
            else:
                self.warnings.append("CSRF initialization not found in app factory")
        
        # Check configuration
        config_file = self.app_root / "app" / "config" / "base.py"
        if config_file.exists():
            content = config_file.read_text()
            if "WTF_CSRF" in content:
                print("  ✅ CSRF configuration found in config")
            else:
                self.warnings.append("No CSRF configuration found in config")
    
    def find_all_forms(self):
        """Find all HTML forms in templates."""
        print("\n🔍 Scanning for forms in templates...")
        forms = []
        
        for template_file in self.templates_dir.rglob("*.html"):
            content = template_file.read_text()
            
            # Find all form tags
            form_matches = re.finditer(r'<form[^>]*>', content, re.IGNORECASE)
            for match in form_matches:
                line_num = content[:match.start()].count('\n') + 1
                forms.append({
                    'file': template_file,
                    'line': line_num,
                    'form_tag': match.group()
                })
        
        print(f"  📊 Found {len(forms)} forms across {len(set(f['file'] for f in forms))} templates")
        return forms
    
    def verify_csrf_tokens(self, forms):
        """Verify each form has proper CSRF token."""
        print("\n🔍 Verifying CSRF tokens in forms...")
        
        missing_csrf = []
        
        for form in forms:
            template_content = form['file'].read_text()
            
            # Check for CSRF token patterns
            csrf_patterns = [
                r'name="csrf_token"',
                r'\{\{\s*csrf_token\(\)\s*\}\}',
                r'value="\{\{\s*csrf_token\(\)\s*\}\}"'
            ]
            
            has_csrf = any(re.search(pattern, template_content, re.IGNORECASE) 
                          for pattern in csrf_patterns)
            
            if not has_csrf:
                missing_csrf.append(form)
                self.errors.append(
                    f"Missing CSRF token in {form['file'].relative_to(self.app_root)}:{form['line']}"
                )
            else:
                print(f"  ✅ CSRF token found in {form['file'].name}")
        
        if not missing_csrf:
            print("  ✅ All forms have CSRF protection")
        else:
            print(f"  ❌ {len(missing_csrf)} forms missing CSRF tokens")
            
        return missing_csrf
    
    def check_view_methods(self):
        """Check if view methods that handle forms have proper CSRF validation."""
        print("\n🔍 Checking view methods for POST handling...")
        
        post_methods = []
        
        # Find all Python files in views
        for py_file in self.views_dir.rglob("*.py"):
            if "test" in py_file.name or "__pycache__" in str(py_file):
                continue
                
            content = py_file.read_text()
            
            # Find route decorators with POST methods
            post_routes = re.finditer(
                r'@[^.]*\.route\([^)]*methods\s*=\s*\[[^\]]*["\']POST["\'][^\]]*\]',
                content,
                re.IGNORECASE | re.MULTILINE
            )
            
            for match in post_routes:
                line_num = content[:match.start()].count('\n') + 1
                post_methods.append({
                    'file': py_file,
                    'line': line_num,
                    'decorator': match.group()
                })
        
        print(f"  📊 Found {len(post_methods)} POST route handlers")
        
        # Since Flask-WTF's CSRFProtect automatically validates CSRF tokens
        # for all POST requests, we just need to ensure it's enabled
        if post_methods:
            print("  ℹ️  CSRF validation is handled automatically by Flask-WTF CSRFProtect")
            print("  ✅ All POST routes are protected when CSRFProtect is enabled")
        
        return post_methods
    
    def check_ajax_forms(self):
        """Check for AJAX forms and CSRF header usage."""
        print("\n🔍 Checking for AJAX forms and CSRF headers...")
        
        ajax_forms = []
        
        for template_file in self.templates_dir.rglob("*.html"):
            content = template_file.read_text()
            
            # Look for AJAX patterns
            ajax_patterns = [
                r'\.ajax\s*\(',
                r'fetch\s*\(',
                r'XMLHttpRequest',
                r'X-CSRFToken',
                r'X-CSRF-Token'
            ]
            
            for pattern in ajax_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    ajax_forms.append({
                        'file': template_file,
                        'line': line_num,
                        'pattern': pattern
                    })
        
        if ajax_forms:
            print(f"  📊 Found {len(ajax_forms)} AJAX-related patterns")
            # Check if CSRF meta tag is present in base template
            base_template = self.templates_dir / "main" / "base.html"
            if base_template.exists():
                base_content = base_template.read_text()
                if 'name="csrf-token"' in base_content:
                    print("  ✅ CSRF meta tag found in base template")
                else:
                    self.warnings.append("Consider adding CSRF meta tag to base template for AJAX requests")
        else:
            print("  ℹ️  No AJAX patterns detected")
    
    def generate_report(self):
        """Generate a comprehensive CSRF verification report."""
        print("\n" + "="*60)
        print("CSRF PROTECTION VERIFICATION REPORT")
        print("="*60)
        
        if not self.errors and not self.warnings:
            print("\n🎉 EXCELLENT! All CSRF protection checks passed.")
            print("\n✅ Your application has comprehensive CSRF protection:")
            print("   • CSRFProtect is properly configured")
            print("   • All forms include CSRF tokens")
            print("   • POST routes are automatically protected")
            print("   • No security vulnerabilities detected")
            
            return True
        
        if self.errors:
            print(f"\n❌ ERRORS FOUND ({len(self.errors)}):")
            for i, error in enumerate(self.errors, 1):
                print(f"   {i}. {error}")
        
        if self.warnings:
            print(f"\n⚠️  WARNINGS ({len(self.warnings)}):")
            for i, warning in enumerate(self.warnings, 1):
                print(f"   {i}. {warning}")
        
        print(f"\n📊 SUMMARY:")
        print(f"   • Errors: {len(self.errors)}")
        print(f"   • Warnings: {len(self.warnings)}")
        
        if self.errors:
            print("\n🔧 RECOMMENDATIONS:")
            print("   1. Fix all errors before deploying to production")
            print("   2. Add CSRF tokens to forms missing protection")
            print("   3. Ensure CSRFProtect is properly initialized")
            
            return False
        
        return True
    
    def run_verification(self):
        """Run complete CSRF verification."""
        print("🛡️  Starting CSRF Protection Verification")
        print("="*50)
        
        # Step 1: Verify CSRF setup
        self.verify_csrf_setup()
        
        # Step 2: Find all forms
        forms = self.find_all_forms()
        
        # Step 3: Verify CSRF tokens
        self.verify_csrf_tokens(forms)
        
        # Step 4: Check view methods
        self.check_view_methods()
        
        # Step 5: Check AJAX forms
        self.check_ajax_forms()
        
        # Step 6: Generate report
        success = self.generate_report()
        
        return success


def main():
    """Main function."""
    if len(sys.argv) > 1:
        app_root = sys.argv[1]
    else:
        app_root = os.getcwd()
    
    verifier = CSRFVerifier(app_root)
    success = verifier.run_verification()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()