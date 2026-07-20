# OWASP A04:2021 – Insecure Design

**Category:** Insecure Design  
**OWASP ID:** A04  
**CWE References:** CWE-73, CWE-183, CWE-209, CWE-256, CWE-501, CWE-522

## Overview

Insecure design is a broad category representing different weaknesses expressed as "missing or ineffective control design." It refers to risks related to design flaws, as opposed to implementation defects. A secure design can still have implementation defects leading to vulnerabilities. An insecure design cannot be fixed by a perfect implementation — by definition, needed security controls were never created to defend against specific attacks.

## Description

Insecure design is not the source of all other Top 10 risk categories. There is a difference between insecure design and insecure implementation. We differentiate between design flaws and implementation defects for a reason — they have different root causes and remediation. A secure design can still have implementation bugs leading to vulnerabilities that may be exploited. An insecure design cannot be fixed by a perfect implementation as by definition, needed security controls were never created to defend against specific attacks.

One of the factors contributing to insecure design is the lack of business risk profiling inherent in the software or system being developed, and thus the failure to determine what level of security design is required.

## Common Attack Scenarios

**Scenario 1 — Credential Recovery Flow:**  
A credential recovery workflow might include "security questions," which is prohibited by NIST 800-63b, the OWASP ASVS, and the OWASP Top 10. Questions and answers cannot be trusted as evidence of identity as more than one person can know the answer, which is why they are prohibited.

**Scenario 2 — Cinema Booking:**  
A cinema chain allows group booking discounts and has a maximum of fifteen attendees before requiring a deposit. Attackers could threat model this flow and test if they could book six hundred seats and all cinemas at once in a few requests, causing a massive loss of income.

**Scenario 3 — Retail Bot:**  
A retail chain's e-commerce website does not have protection against bots run by scalpers buying high-end video cards to resell. This creates terrible publicity for the video card makers and retail chain owners and enduring bad blood with enthusiasts who cannot obtain these cards at any price.

## Prevention

- Establish and use a secure development lifecycle with AppSec professionals to help evaluate and design security and privacy-related controls.
- Establish and use a library of secure design patterns or paved road ready to use components.
- Use threat modeling for critical authentication, access control, business logic, and key flows.
- Integrate security language and controls into user stories.
- Integrate plausibility checks at each tier of your application (from frontend to backend).
- Write unit and integration tests to validate that all critical flows are resistant to the threat model.
- Tier your system according to the exposure needs and protection requirements.
- Limit resource consumption by user or service.

## Secure Design Patterns

### Defense in Depth
Apply multiple layers of security controls. If one layer fails, others catch the issue. Never rely on a single control point.

### Fail Secure
When a system fails, it should fail in a secure state. Do not expose sensitive data on exceptions. Return generic error messages to users while logging detailed errors server-side.

### Least Privilege
Grant every module and user only the minimum level of access — or permissions — needed to perform its legitimate functions. Reduce the attack surface by limiting what any single component can do.

### Separation of Duties
Ensure no single individual or component has exclusive control over critical functions. Require multi-party authorization for sensitive operations.

### Complete Mediation
Check every access to every resource for authorization. Do not cache access-control decisions unless they can be invalidated correctly.

### Secure by Default
Default configurations should be the most secure option. Users should consciously opt into less-secure configurations rather than accidentally using insecure defaults.

## Code-Level Anti-Patterns to Avoid

### God Classes / God Functions
A single class or function that knows too much or does too much. This makes security controls hard to audit and enforce consistently.

```python
# BAD — God function doing everything
def process_user_request(request):
    # authentication
    # authorization  
    # business logic
    # data access
    # response formatting
    # logging
    # ... 200 more lines
    pass

# GOOD — Separated concerns
def authenticate_request(request): ...
def authorize_action(user, action): ...
def execute_business_logic(params): ...
```

### Magic Numbers and Hardcoded Business Rules
Hardcoded values for security-sensitive thresholds (e.g., max login attempts, session timeout) make the system fragile and hard to adjust.

### Missing Input Validation at Design
Input validation must be designed in — not added as an afterthought. Every external boundary crossing must validate data type, length, format, and range before processing.

### Business Logic Bypass Paths
Design must account for all possible paths through business logic. Race conditions, parameter manipulation, and state-machine attacks often exploit design gaps.

## References
- OWASP Top 10 A04:2021 — https://owasp.org/Top10/A04_2021-Insecure_Design/
- OWASP ASVS — https://owasp.org/www-project-application-security-verification-standard/
- NIST SP 800-160 — Systems Security Engineering
- CWE-209: Generation of Error Message Containing Sensitive Information
- CWE-522: Insufficiently Protected Credentials
