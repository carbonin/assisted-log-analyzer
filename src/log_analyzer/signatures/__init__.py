"""
Signature analysis modules for OpenShift Assisted Installer logs.
"""

from .base import Signature, ErrorSignature, SignatureResult
from .basic_info import *
from .error_detection import *
from .performance import *
from .networking import *
from .advanced_analysis import *
from .platform_specific import *

# Collect all signatures from all modules
ALL_SIGNATURES = []

# Import all signature classes from each module
import sys
import inspect

current_module = sys.modules[__name__]
for name, obj in inspect.getmembers(current_module):
    if (inspect.isclass(obj) and 
        issubclass(obj, Signature) and 
        obj is not Signature and 
        obj is not ErrorSignature and
        obj is not SignatureResult):
        ALL_SIGNATURES.append(obj)

# Sort by name for consistent ordering
ALL_SIGNATURES.sort(key=lambda x: x.__name__)

__all__ = ["Signature", "ErrorSignature", "SignatureResult", "ALL_SIGNATURES"]
