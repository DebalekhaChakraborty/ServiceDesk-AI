Azure AD Password Reset Procedure
**KB ID:** AAD-PWD-RESET-1001  
**Title:** Secure Password Reset for Azure AD Users  
**Affected Service:** Microsoft Azure Active Directory (AAD)  
**Category:** Identity & Access Management → User Account Support  
**Last Updated:** 2025-11-30  

Problem Description
A user is unable to log in to corporate systems due to a forgotten or expired password.

Common Symptoms
- User reports login failure or password expired
- Account is locked due to multiple failed login attempts
- Service Desk ticket requesting password reset
- Identity verification required before reset
**Keywords:** `password reset`, `AAD`, `forgot password`, `account unlock`, `Azure AD`

Root Cause
The user's password has expired, been forgotten, or the account has been locked due to security policies.  
Azure AD must be used to securely reset credentials following identity validation.

Manual Resolution (Reference for Admins)
If automation is unavailable, an administrator can reset the password manually:
1. Open **Azure Portal**
2. Go to **Azure Active Directory → Users**
3. Search for the user (UPN)
4. Click **Reset Password**
5. Select **Force change password on next sign-in**
6. Share the reset instructions with the user via secure channel

Automation Notes (System Context)
- Automation must:
  - Validate caller identity & role (`caller_is_self_or_manager`)
  - Use Microsoft Graph API for secure password reset  
  - NEVER send password directly in chat  
  - Audit request with caller UPN + target UPN  
- After execution:
  - Notify end user via secure email/SMS
  - Optionally update ServiceNow ticket (if applicable)

Validation Checklist
Step,Expected Result
Identity verified,Caller is self OR manager
Password reset,Graph API returns 200/204
Force change at login,Enabled via API
Audit logged,Request stored with caller + target
Notification sent,Secure delivery method**End of Document**
