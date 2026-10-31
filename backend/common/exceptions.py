"""PathWarden exception hierarchy."""

class PathWardenError(Exception):
    """Base exception for all PathWarden subsystem errors."""
    pass

class ParsingError(PathWardenError):
    """Raised when log parsing fails."""
    pass

class SchemaValidationError(PathWardenError):
    """Raised when normalized record violates schema constraints."""
    pass

class MemoryLimitExceeded(PathWardenError):
    """Raised when memory consumption approaches 8.0 GB budget ceiling."""
    pass

