from abc import ABC, abstractmethod
from typing import List, Dict, Any
from ..core.requester import VaptRequester
from ..core.vulnerability import Vulnerability
from ..core.config import FrameworkConfig

class BaseModule(ABC):
    """Abstract base class for all VAPT assessment modules."""
    name: str = "Base Module"
    description: str = "Base assessment module"
    category: str = "API Security"

    def __init__(self, requester: VaptRequester, config: FrameworkConfig, context: Dict[str, Any]):
        self.requester = requester
        self.config = config
        self.context = context  # Shared context e.g. active tokens, user IDs, etc.

    @abstractmethod
    def run(self) -> List[Vulnerability]:
        """Execute the security assessment module and return a list of findings."""
        pass
