#!/usr/bin/env python3
"""
TOR Unveil - Quick Integration Validator
Validates frontend-backend integration and core functionality
"""

import os
import json
from pathlib import Path

def check_file_exists(filepath, description):
    """Check if a file exists and return status"""
    path = Path(filepath)
    exists = path.exists()
    size = path.stat().st_size if exists else 0
    print(f"{'✅' if exists else '❌'} {description}: {'EXISTS' if exists else 'MISSING'} ({size} bytes)")
    return exists

def check_api_endpoints_in_backend():
    """Check if all required API endpoints are implemented in backend"""
    backend_file = Path("backend/working_backend.py")
    if not backend_file.exists():
        print("❌ Backend file not found")
        return False
    
    content = backend_file.read_text()
    
    required_endpoints = [
        "/api/health",
        "/api/status", 
        "/api/packets",
        "/api/sniffer/start",
        "/api/sniffer/stop",
        "/api/correlation/run",
        "/api/correlation/results",
        "/api/geo/lookup",
        "/api/geo/locations",
        "/api/reports/generate-pdf",
        "/api/pcap/upload",
        "/api/tor/connect"
    ]
    
    print("\n🔍 Checking API Endpoints in Backend:")
    all_present = True
    for endpoint in required_endpoints:
        present = endpoint in content
        print(f"{'✅' if present else '❌'} {endpoint}: {'IMPLEMENTED' if present else 'MISSING'}")
        if not present:
            all_present = False
    
    return all_present

def check_frontend_backend_integration():
    """Check if frontend properly calls backend APIs"""
    frontend_files = ["index.html", "main.js", "correlation-dashboard.js"]
    
    print("\n🔍 Checking Frontend-Backend Integration:")
    
    backend_calls = []
    for file in frontend_files:
        if Path(file).exists():
            content = Path(file).read_text()
            
            # Check for localhost:5000 calls (correct port)
            if "localhost:5000" in content:
                print(f"✅ {file}: Uses correct backend port (5000)")
            elif "localhost:5001" in content:
                print(f"⚠️  {file}: Uses incorrect backend port (5001) - should be 5000")
            else:
                print(f"❌ {file}: No backend calls found")
                
            # Check for API endpoint calls
            api_calls = content.count("/api/")
            if api_calls > 0:
                print(f"   📡 Found {api_calls} API calls")
                backend_calls.append(api_calls)
    
    return len(backend_calls) > 0

def check_dependencies():
    """Check if required dependencies are listed"""
    requirements_file = Path("requirements.txt")
    
    print("\n🔍 Checking Dependencies:")
    
    if not requirements_file.exists():
        print("❌ requirements.txt not found")
        return False
    
    content = requirements_file.read_text()
    required_deps = ["scapy", "numpy", "requests", "scikit-learn", "geoip2", "reportlab"]
    
    all_present = True
    for dep in required_deps:
        present = dep in content.lower()
        print(f"{'✅' if present else '❌'} {dep}: {'LISTED' if present else 'MISSING'}")
        if not present:
            all_present = False
    
    return all_present

def check_core_classes():
    """Check if core classes are properly implemented"""
    print("\n🔍 Checking Core Classes:")
    
    # Check correlation engine
    correlation_file = Path("backend/tor_correlation_engine.py")
    if correlation_file.exists():
        content = correlation_file.read_text()
        classes = ["TimingCorrelator", "TrafficAnalyzer", "WebsiteFingerprinter", "GeoIPService", "TORCorrelationEngine"]
        
        for cls in classes:
            present = f"class {cls}" in content
            print(f"{'✅' if present else '❌'} {cls}: {'IMPLEMENTED' if present else 'MISSING'}")
    else:
        print("❌ Correlation engine file not found")
        return False
    
    # Check packet sniffer
    sniffer_file = Path("backend/packet_sniffer.py")
    if sniffer_file.exists():
        content = sniffer_file.read_text()
        sniffer_present = "class PacketSniffer" in content
        print(f"{'✅' if sniffer_present else '❌'} PacketSniffer: {'IMPLEMENTED' if sniffer_present else 'MISSING'}")
    else:
        print("❌ Packet sniffer file not found")
        return False
    
    return True

def validate_json_configs():
    """Validate any JSON configuration files"""
    print("\n🔍 Checking JSON Configurations:")
    
    json_files = []
    for file in Path(".").glob("*.json"):
        json_files.append(file)
    
    if not json_files:
        print("ℹ️  No JSON config files found")
        return True
    
    all_valid = True
    for json_file in json_files:
        try:
            with open(json_file) as f:
                json.load(f)
            print(f"✅ {json_file.name}: Valid JSON")
        except json.JSONDecodeError as e:
            print(f"❌ {json_file.name}: Invalid JSON - {e}")
            all_valid = False
    
    return all_valid

def main():
    """Main validation function"""
    print("🔍 TOR Unveil - Integration Validator")
    print("=" * 50)
    
    # Check core files
    print("\n📁 Checking Core Files:")
    core_files = [
        ("index.html", "Main Dashboard"),
        ("backend/working_backend.py", "Backend Server"),
        ("backend/packet_sniffer.py", "Packet Sniffer"),
        ("backend/tor_correlation_engine.py", "Correlation Engine"),
        ("backend/pdf_report_generator.py", "Report Generator"),
        ("main.js", "Frontend Logic"),
        ("correlation-dashboard.js", "Correlation Dashboard"),
        ("requirements.txt", "Dependencies")
    ]
    
    files_present = 0
    for filepath, description in core_files:
        if check_file_exists(filepath, description):
            files_present += 1
    
    # Check API endpoints
    endpoints_ok = check_api_endpoints_in_backend()
    
    # Check frontend integration
    integration_ok = check_frontend_backend_integration()
    
    # Check dependencies
    deps_ok = check_dependencies()
    
    # Check core classes
    classes_ok = check_core_classes()
    
    # Validate JSON configs
    json_ok = validate_json_configs()
    
    # Generate summary
    print("\n" + "=" * 50)
    print("📊 VALIDATION SUMMARY")
    print("=" * 50)
    
    total_files = len(core_files)
    file_percentage = (files_present / total_files) * 100
    
    print(f"📁 Core Files: {files_present}/{total_files} ({file_percentage:.1f}%)")
    print(f"🔗 API Endpoints: {'✅ OK' if endpoints_ok else '❌ ISSUES'}")
    print(f"🌐 Frontend Integration: {'✅ OK' if integration_ok else '❌ ISSUES'}")
    print(f"📦 Dependencies: {'✅ OK' if deps_ok else '❌ ISSUES'}")
    print(f"🏗️  Core Classes: {'✅ OK' if classes_ok else '❌ ISSUES'}")
    print(f"⚙️  JSON Configs: {'✅ OK' if json_ok else '❌ ISSUES'}")
    
    # Overall assessment
    all_checks = [
        files_present == total_files,
        endpoints_ok,
        integration_ok,
        deps_ok,
        classes_ok,
        json_ok
    ]
    
    passed_checks = sum(all_checks)
    total_checks = len(all_checks)
    success_rate = (passed_checks / total_checks) * 100
    
    print(f"\n🎯 Overall Status: {passed_checks}/{total_checks} checks passed ({success_rate:.1f}%)")
    
    if success_rate == 100:
        print("🎉 ALL CHECKS PASSED - Ready for deployment!")
    elif success_rate >= 80:
        print("✅ MOSTLY READY - Minor issues to address")
    elif success_rate >= 60:
        print("⚠️  NEEDS ATTENTION - Several issues found")
    else:
        print("❌ MAJOR ISSUES - Significant problems detected")
    
    # Recommendations
    print("\n💡 RECOMMENDATIONS:")
    print("-" * 30)
    
    if files_present < total_files:
        print("• Ensure all core files are present in the project directory")
    
    if not endpoints_ok:
        print("• Verify all API endpoints are implemented in working_backend.py")
    
    if not integration_ok:
        print("• Check frontend files use correct backend port (5000)")
        print("• Ensure API calls are properly implemented")
    
    if not deps_ok:
        print("• Update requirements.txt with all necessary dependencies")
        print("• Run: pip install -r requirements.txt")
    
    if not classes_ok:
        print("• Verify core classes are properly implemented")
        print("• Check for syntax errors in Python files")
    
    print("\n🚀 To start the application:")
    print("1. Install dependencies: pip install -r requirements.txt")
    print("2. Start backend (as admin): python backend/working_backend.py")
    print("3. Open index.html in web browser")
    print("4. Run full test: python functionality_test.py")

if __name__ == "__main__":
    main()