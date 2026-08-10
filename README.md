# ServiceDesk AI

## Account Access demo backend

Account status, unlock, and enable operations default to the non-executing
`AD_ACCOUNT_MODE=off` mode. Enable the deterministic in-process demo explicitly:

```ini
AD_ACCOUNT_MODE=demo
AD_DEMO_LOCKED_UPNS=locked.user@example.com,locked.disabled.user@example.com
AD_DEMO_DISABLED_UPNS=disabled.user@example.com,locked.disabled.user@example.com
```

The locked and disabled lists are independent, comma-separated fixtures and are
restored from the environment whenever the backend restarts. Unlocking never
enables an account, and enabling never clears lockout.
