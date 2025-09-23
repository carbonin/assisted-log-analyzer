"""
Signature analysis for OpenShift Assisted Installer logs.

This module provides the main interface to all signature analysis classes.
The actual implementations are organized in the signatures/ subdirectory by category.
"""

# Import all signatures from the organized modules
from .signatures.base import Signature, ErrorSignature, SignatureResult
from .signatures.basic_info import *
from .signatures.error_detection import *
from .signatures.performance import *
from .signatures.networking import *
from .signatures.advanced_analysis import *
from .signatures.platform_specific import *

# Automatically collect all signature classes
import sys
import inspect

ALL_SIGNATURES = []

# Get all signature classes from the current module
current_module = sys.modules[__name__]
for name, obj in inspect.getmembers(current_module):
    if (inspect.isclass(obj) and 
        issubclass(obj, Signature) and 
        obj is not Signature and 
        obj is not ErrorSignature):
        ALL_SIGNATURES.append(obj)

# Sort by name for consistent ordering
ALL_SIGNATURES.sort(key=lambda x: x.__name__)

# Export the main interface
__all__ = ["Signature", "ErrorSignature", "SignatureResult", "ALL_SIGNATURES"]
