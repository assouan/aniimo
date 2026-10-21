from __future__ import annotations


class ModkitError(RuntimeError):
    """A user-facing pipeline error with a stable process exit code."""

    def __init__(
        self, message: str, *, exit_code: int = 4, error_code: str = "pipeline_error"
    ) -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.error_code = error_code


class ConfigurationError(ModkitError):
    def __init__(
        self, message: str, *, error_code: str = "configuration_error"
    ) -> None:
        super().__init__(message, exit_code=2, error_code=error_code)


class CaptureError(ModkitError):
    def __init__(self, message: str, *, error_code: str = "capture_error") -> None:
        super().__init__(message, exit_code=3, error_code=error_code)


class ValidationError(ModkitError):
    def __init__(self, message: str, *, error_code: str = "validation_error") -> None:
        super().__init__(message, exit_code=5, error_code=error_code)
