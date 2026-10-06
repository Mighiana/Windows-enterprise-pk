@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # Console report is intentionally coloured; structured output is available via -OutputFormat Json / -PassThru.
        'PSAvoidUsingWriteHost'
        # New-LabCheckResult / test helpers only build in-memory objects; they change no system state.
        'PSUseShouldProcessForStateChangingFunctions'
        # RemoteCertificateValidationCallback must declare all four delegate parameters.
        'PSReviewUnusedParameter'
    )
}
