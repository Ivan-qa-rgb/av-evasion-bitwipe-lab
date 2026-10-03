rule Suspicious_Decryptor_Stub_Training {
    meta:
        description = "Training rule to detect common decryptor stub patterns in loaders"
        author = "SOC Team"
        severity = "high"
        disclaimer = "For educational use only; may produce false positives on legitimate tools"
    strings:
        $api1 = "VirtualAllocEx" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "CreateRemoteThread" ascii wide
        $mz = { 4D 5A }
    condition:
        $mz at 0 and 2 of ($api*)
}
