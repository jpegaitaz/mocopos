rule Suspicious_Python_Exec
{
  meta:
    description = "Flags Python files with os.system or subprocess.* risky usage"
    severity = "medium"
  strings:
    $a = /os\.system\s*\(/
    $b = /subprocess\.(Popen|call|run)\s*\(/
    $c = /shell\s*=\s*True/
  condition:
    any of ($a,$b) and (uint16be(0) != 0)  // cheap non-binary check
}
