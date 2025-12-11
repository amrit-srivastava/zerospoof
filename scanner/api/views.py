"""
API Views for ZeroSpoof Scanner

Provides the /api/check endpoint for domain scanning.
"""

import re
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.http import HttpResponse

from scanner.services.scoring_engine import get_scoring_engine
from scanner.services.pdf_generator import generate_pdf_report


def is_valid_domain(domain: str) -> bool:
    """
    Validate domain name format.
    
    Args:
        domain: The domain to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not domain:
        return False
    
    # Remove any protocol prefix
    domain = domain.lower().strip()
    if domain.startswith("http://"):
        domain = domain[7:]
    if domain.startswith("https://"):
        domain = domain[8:]
    
    # Remove trailing slashes and paths
    domain = domain.split("/")[0]
    
    # Basic domain pattern
    pattern = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
    return bool(re.match(pattern, domain))


def clean_domain(domain: str) -> str:
    """
    Clean and normalize a domain name.
    
    Args:
        domain: The domain to clean
        
    Returns:
        Cleaned domain name
    """
    domain = domain.lower().strip()
    
    # Remove protocol
    if domain.startswith("http://"):
        domain = domain[7:]
    if domain.startswith("https://"):
        domain = domain[8:]
    
    # Remove trailing slashes and paths
    domain = domain.split("/")[0]
    
    # Remove port if present
    domain = domain.split(":")[0]
    
    return domain


@api_view(['GET'])
def check_domain(request):
    """
    Check email security for a domain.
    
    Query Parameters:
        domain: The domain to check (required)
        
    Returns:
        JSON response with:
        - domain: The checked domain
        - score: Total score (0-100)
        - grade: Letter grade (A+ to F)
        - grade_color: CSS color for the grade
        - score_version: Scoring profile version
        - provider: Detected email provider
        - checks: Detailed results for each control
        - remediation: List of suggested fixes
    """
    domain = request.query_params.get('domain', '').strip()
    
    if not domain:
        return Response(
            {"error": "Domain parameter is required"},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Clean and validate domain
    domain = clean_domain(domain)
    
    if not is_valid_domain(domain):
        return Response(
            {"error": "Invalid domain format"},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Run the scan
        engine = get_scoring_engine()
        result = engine.scan(domain)
        
        return Response(result.to_dict())
    
    except Exception as e:
        return Response(
            {"error": f"Scan failed: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
def download_pdf(request):
    """
    Download PDF report for a domain scan.
    
    Query Parameters:
        domain: The domain to scan and generate PDF for (required)
        
    Returns:
        PDF file download
    """
    domain = request.query_params.get('domain', '').strip()
    
    if not domain:
        return Response(
            {"error": "Domain parameter is required"},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Clean and validate domain
    domain = clean_domain(domain)
    
    if not is_valid_domain(domain):
        return Response(
            {"error": "Invalid domain format"},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Run the scan
        engine = get_scoring_engine()
        result = engine.scan(domain)
        
        # Generate PDF
        pdf_bytes = generate_pdf_report(result.to_dict())
        
        # Return PDF as download
        response = HttpResponse(pdf_bytes, content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="zerospoof-{domain}-report.pdf"'
        return response
    
    except Exception as e:
        return Response(
            {"error": f"PDF generation failed: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
