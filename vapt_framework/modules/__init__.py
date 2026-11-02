from .base import BaseModule
from .auth_jwt import AuthJwtScanner
from .bola import BolaScanner
from .bfla import BflaScanner
from .mass_assignment import MassAssignmentScanner
from .injection_sql import SqlInjectionScanner
from .injection_cmd import CommandInjectionScanner
from .misconfig import MisconfigScanner
from .rate_limit import RateLimitScanner

ALL_MODULES = [
    AuthJwtScanner,
    BolaScanner,
    BflaScanner,
    MassAssignmentScanner,
    SqlInjectionScanner,
    CommandInjectionScanner,
    MisconfigScanner,
    RateLimitScanner
]
