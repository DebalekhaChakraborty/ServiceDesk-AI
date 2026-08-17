# Windows Time Desync and Resync Procedure
**KB ID:** 1024-W32TIME-UNSYNC  
**Title:** Windows Time Service (W32Time) Desync and Restart Procedure  
**Affected Service:** Windows Server / Workstation Time Synchronization  
**Category:** Infrastructure → Operating System  
**Last Updated:** 2025-11-05  

## 🧠 Problem Description
Windows hosts can drift out of sync with the domain controller or NTP source, causing login and authentication issues.

### Common Symptoms
- Kerberos authentication failure or logon errors  
- “Clock skew too great” warnings  
- Event Viewer logs showing **W32Time** service failures  
- `w32tm /query /status` shows time difference exceeding threshold  
**Keywords:** `windows`, `time sync`, `w32time`, `ntp`, `kerberos`, `clock drift`

## 🧩 Root Cause
The **Windows Time Service (W32Time)** is not synchronized with the domain’s authoritative time source.  
Causes may include:
- The service stopped or failed to restart after maintenance  
- NTP or domain controller unreachable  
- Excessive system clock drift  
- Registry or configuration corruption of time service parameters  

## 🧰 Manual Resolution (Reference for Admins)
If automation is unavailable, a Windows administrator can manually fix the issue as follows:
1. Open **Command Prompt** as Administrator  
2. Stop the Windows Time Service  
   ```cmd
   net stop w32time
   ```
3. (Optional) Re-register the service  
   ```cmd
   w32tm /unregister && w32tm /register
   ```
4. Force resynchronization  
   ```cmd
   w32tm /resync /force
   ```
5. Start the service again  
   ```cmd
   net start w32time
   ```
6. Verify synchronization  
   ```cmd
   w32tm /query /status
   ```
If the clock is still not aligned, validate firewall/NTP reachability or the domain controller settings.

## 🤖 Automation Notes (System Context)
- Automated remediation will identify the **target host** from the incident description and restart/resync the **W32Time** service remotely.  
- The remediation plan used is equivalent to restarting and resyncing Windows Time Service.  
- Post-execution, the system automatically updates the ServiceNow ticket:
  - ✅ *Success:* marks the incident as **Resolved** with work notes  
  - ⚠️ *Failure:* reassigns to **L2-Windows** with the error message  
- No manual ticket updates are required.

## 🪄 Validation Checklist
Step,Expected Result
`net start w32time`,Service starts successfully
`w32tm /resync /force`,Returns “Command completed successfully.”
`w32tm /query /status`,Reports source = domain controller
ServiceNow Ticket,Updated with remediation outcome

**End of Document**
