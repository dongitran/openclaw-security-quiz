/** Security & Best Practices Quiz - 100 Questions */
const quizData = [
    // ===== OWASP Top 10 (15 questions) =====
    {
        id: 1,
        category: "OWASP",
        question: "What is the #1 vulnerability in the OWASP Top 10 (2021)?",
        options: [
            "Cryptographic Failures",
            "Injection",
            "Broken Access Control",
            "Security Misconfiguration"
        ],
        correct: 2,
        explanation: "<strong>Broken Access Control</strong> is the #1 vulnerability in OWASP Top 10 2021. It moved up from #5 in 2017 due to increased prevalence of access control vulnerabilities in modern applications."
    },
    {
        id: 2,
        category: "OWASP",
        question: "What does 'Cryptographic Failures' in OWASP Top 10 refer to?",
        options: [
            "Using outdated encryption algorithms",
            "Failures related to cryptography that lead to sensitive data exposure",
            "SSL certificate expiration",
            "Weak password hashing"
        ],
        correct: 1,
        explanation: "<strong>Cryptographic Failures</strong> (formerly 'Sensitive Data Exposure') refers to failures in implementing cryptography properly, leading to exposure of sensitive data like passwords, credit cards, or health records."
    },
    {
        id: 3,
        category: "OWASP",
        question: "What is the primary defense against Injection attacks?",
        options: [
            "Using HTTPS only",
            "Input validation, parameterized queries, and escaping",
            "Strong password policies",
            "Web Application Firewall"
        ],
        correct: 1,
        explanation: "<strong>Input validation, parameterized queries (prepared statements), and escaping</strong> are the primary defenses against injection attacks including SQL, NoSQL, OS command, and LDAP injection."
    },
    {
        id: 4,
        category: "OWASP",
        question: "What is 'Insecure Design' in OWASP Top 10 2021?",
        options: [
            "Using outdated design patterns",
            "Missing or ineffective security controls in application design",
            "Poor UI/UX design",
            "Not using CSS frameworks"
        ],
        correct: 1,
        explanation: "<strong>Insecure Design</strong> is a new category in 2021 focusing on missing or ineffective security controls during the design phase. It's different from implementation flaws - it's about fundamental design weaknesses."
    },
    {
        id: 5,
        category: "OWASP",
        question: "What is Security Misconfiguration?",
        options: [
            "Using default passwords and unnecessary features enabled",
            "Writing insecure code",
            "Not using SSL certificates",
            "Using open source libraries"
        ],
        correct: 0,
        explanation: "<strong>Security Misconfiguration</strong> includes default configurations, incomplete configurations, default passwords, unnecessary features enabled, verbose error messages, and improper cloud permissions."
    },
    {
        id: 6,
        category: "OWASP",
        question: "What is the best defense against Vulnerable and Outdated Components?",
        options: [
            "Use only proprietary software",
            "Regular patching, inventory management, and removal of unused dependencies",
            "Disable JavaScript in browsers",
            "Use only LTS versions"
        ],
        correct: 1,
        explanation: "<strong>Regular patching, maintaining an inventory of components, and removing unused dependencies</strong> are essential. Tools like OWASP Dependency-Check and Snyk can help automate this process."
    },
    {
        id: 7,
        category: "OWASP",
        question: "What is 'Identification and Authentication Failures'?",
        options: [
            "Users forgetting passwords",
            "Vulnerabilities that allow attackers to compromise passwords, keys, or session tokens",
            "Using social login only",
            "Not having 2FA"
        ],
        correct: 1,
        explanation: "<strong>Identification and Authentication Failures</strong> occur when functions related to authentication and session management are implemented incorrectly, allowing attackers to compromise passwords, keys, or session tokens."
    },
    {
        id: 8,
        category: "OWASP",
        question: "What is Software and Data Integrity Failure?",
        options: [
            "Corrupted databases",
            "Assumptions related to software updates, critical data, and CI/CD pipelines without verification",
            "Using Git without commits",
            "Not backing up data"
        ],
        correct: 1,
        explanation: "<strong>Software and Data Integrity Failures</strong> relate to code and infrastructure that does not protect against integrity violations, including insecure deserialization and supply chain attacks."
    },
    {
        id: 9,
        category: "OWASP",
        question: "What is Security Logging and Monitoring Failure?",
        options: [
            "Not having enough disk space for logs",
            "Insufficient logging, detection, monitoring, and active response",
            "Using plaintext logs",
            "Logging only errors"
        ],
        correct: 1,
        explanation: "<strong>Security Logging and Monitoring Failure</strong> occurs when applications don't log security-relevant events, making it difficult to detect active breaches, respond to incidents, or perform forensic analysis."
    },
    {
        id: 10,
        category: "OWASP",
        question: "What is Server-Side Request Forgery (SSRF)?",
        options: [
            "A type of DDoS attack",
            "When a web application fetches remote resources without validating user-supplied URLs",
            "Cross-site scripting on the server",
            "SQL injection from the server side"
        ],
        correct: 1,
        explanation: "<strong>SSRF</strong> occurs when a web application fetches remote resources without validating the user-supplied URL. Attackers can use this to access internal services, scan internal networks, or access cloud metadata endpoints."
    },
    {
        id: 11,
        category: "OWASP",
        question: "What is the recommended approach for handling sensitive data at rest?",
        options: [
            "Store in plaintext with strong access control",
            "Encrypt using strong algorithms with proper key management",
            "Compress the data",
            "Use BASE64 encoding"
        ],
        correct: 1,
        explanation: "<strong>Encrypt using strong algorithms with proper key management</strong>. Use AES-256 for symmetric encryption, RSA-2048+ for asymmetric, and ensure keys are stored separately from the encrypted data."
    },
    {
        id: 12,
        category: "OWASP",
        question: "What is the principle of least privilege?",
        options: [
            "Give users minimal access to perform their tasks",
            "Always use the minimum encryption strength",
            "Use the smallest possible database",
            "Run applications with root access"
        ],
        correct: 0,
        explanation: "<strong>The principle of least privilege</strong> means giving users, processes, and systems only the minimum level of access necessary to perform their authorized functions."
    },
    {
        id: 13,
        category: "OWASP",
        question: "What is Insecure Deserialization?",
        options: [
            "Not using JSON.parse() correctly",
            "Untrusted data used to abuse application logic or execute arbitrary code",
            "Using XML instead of JSON",
            "Not validating form data"
        ],
        correct: 1,
        explanation: "<strong>Insecure Deserialization</strong> occurs when untrusted data is used to abuse the logic of an application, inflict a DoS attack, or execute arbitrary code upon deserialization."
    },
    {
        id: 14,
        category: "OWASP",
        question: "What is the best way to prevent security misconfiguration?",
        options: [
            "Use automated hardening and minimal platform configuration",
            "Change default passwords only",
            "Use the latest software versions",
            "Disable all security features"
        ],
        correct: 0,
        explanation: "<strong>Automated hardening, minimal platform configuration, and regular security patches</strong> are the best defenses. Use automated tools to locate configuration flaws and maintain consistent environments."
    },
    {
        id: 15,
        category: "OWASP",
        question: "What is a supply chain attack in the context of software security?",
        options: [
            "Attacking package delivery services",
            "Compromising legitimate software through malicious dependencies or build processes",
            "Stealing source code from repositories",
            "DDoS attacks on software vendors"
        ],
        correct: 1,
        explanation: "<strong>Supply chain attacks</strong> compromise legitimate software by injecting malicious code into dependencies, build processes, or update mechanisms. Examples include the SolarWinds and Log4Shell incidents."
    },

    // ===== Authentication & Authorization (15 questions) =====
    {
        id: 16,
        category: "Auth",
        question: "What is the difference between authentication and authorization?",
        options: [
            "They are the same thing",
            "Authentication verifies identity, authorization determines access rights",
            "Authentication is for users, authorization is for admins",
            "Authentication uses passwords, authorization uses tokens"
        ],
        correct: 1,
        explanation: "<strong>Authentication</strong> verifies who you are (identity verification). <strong>Authorization</strong> determines what you're allowed to do (access control). Authentication comes first, then authorization."
    },
    {
        id: 17,
        category: "Auth",
        question: "What is Multi-Factor Authentication (MFA)?",
        options: [
            "Using multiple passwords",
            "Requiring two or more verification factors to grant access",
            "Authenticating on multiple devices",
            "Using multiple authentication providers"
        ],
        correct: 1,
        explanation: "<strong>MFA</strong> requires two or more verification factors: something you know (password), something you have (phone/token), or something you are (biometric). It significantly improves security."
    },
    {
        id: 18,
        category: "Auth",
        question: "What is the recommended minimum password length in 2024?",
        options: [
            "6 characters",
            "8 characters",
            "12-16 characters",
            "Exactly 20 characters"
        ],
        correct: 2,
        explanation: "<strong>12-16 characters</strong> is the current recommended minimum. NIST guidelines suggest 8 characters minimum but recommend longer passwords. Passphrases of 16+ characters are preferred over complex short passwords."
    },
    {
        id: 19,
        category: "Auth",
        question: "What is RBAC (Role-Based Access Control)?",
        options: [
            "Random-Based Access Control",
            "Restricting access based on user roles",
            "Rule-Based Authentication Check",
            "Remote Browser Access Control"
        ],
        correct: 1,
        explanation: "<strong>RBAC</strong> restricts system access based on user roles. Users are assigned roles (admin, editor, viewer) and permissions are associated with roles rather than individual users."
    },
    {
        id: 20,
        category: "Auth",
        question: "What is the purpose of account lockout policies?",
        options: [
            "To prevent users from logging in during maintenance",
            "To prevent brute force and dictionary attacks",
            "To force users to change passwords regularly",
            "To lock accounts of terminated employees"
        ],
        correct: 1,
        explanation: "<strong>Account lockout</strong> prevents brute force attacks by temporarily disabling an account after a specified number of failed login attempts. It should be combined with rate limiting for optimal protection."
    },
    {
        id: 21,
        category: "Auth",
        question: "What is the risk of storing passwords in plaintext?",
        options: [
            "Passwords take up more storage space",
            "Anyone with database access can see all passwords",
            "Passwords will expire faster",
            "It slows down authentication"
        ],
        correct: 1,
        explanation: "<strong>Never store passwords in plaintext</strong>. Anyone with database access (including attackers) can see all user passwords. Always use strong, salted hashing algorithms like bcrypt, Argon2, or PBKDF2."
    },
    {
        id: 22,
        category: "Auth",
        question: "What is the recommended hashing algorithm for passwords in 2024?",
        options: [
            "MD5",
            "SHA-1",
            "bcrypt, Argon2, or PBKDF2",
            "Base64"
        ],
        correct: 2,
        explanation: "<strong>bcrypt, Argon2, or PBKDF2</strong> are recommended. They are adaptive hashing algorithms designed to be slow (computationally expensive) to resist brute force attacks. Avoid MD5 and SHA-1 for passwords."
    },
    {
        id: 23,
        category: "Auth",
        question: "What is 'privilege escalation'?",
        options: [
            "Upgrading user accounts to premium",
            "Gaining unauthorized access to elevated permissions or resources",
            "Increasing password complexity requirements",
            "Elevating user satisfaction"
        ],
        correct: 1,
        explanation: "<strong>Privilege escalation</strong> occurs when a user gains access to elevated permissions they shouldn't have. It can be vertical (gaining higher privileges) or horizontal (accessing other users' data)."
    },
    {
        id: 24,
        category: "Auth",
        question: "What is the purpose of rate limiting in authentication?",
        options: [
            "To make the system faster",
            "To prevent brute force and automated attacks",
            "To limit the number of users",
            "To reduce server costs"
        ],
        correct: 1,
        explanation: "<strong>Rate limiting</strong> restricts the number of authentication attempts from a single IP or user within a time window, preventing brute force attacks, credential stuffing, and automated abuse."
    },
    {
        id: 25,
        category: "Auth",
        question: "What is ABAC (Attribute-Based Access Control)?",
        options: [
            "Access control based on user attributes, resource attributes, and environmental conditions",
            "Access control based only on user roles",
            "Always Block All Connections",
            "Authentication Based Access Control"
        ],
        correct: 0,
        explanation: "<strong>ABAC</strong> grants access based on attributes of the user, resource, action, and environment. It's more flexible than RBAC (e.g., 'allow access if user is manager AND during business hours')."
    },
    {
        id: 26,
        category: "Auth",
        question: "What is credential stuffing?",
        options: [
            "Filling password fields automatically",
            "Using leaked username/password pairs from other breaches to gain unauthorized access",
            "Encrypting credentials",
            "Storing many credentials in a database"
        ],
        correct: 1,
        explanation: "<strong>Credential stuffing</strong> uses leaked username/password pairs from previous data breaches to attempt logins on other services. Users often reuse passwords across sites, making this attack highly effective."
    },
    {
        id: 27,
        category: "Auth",
        question: "What is the best practice for handling session timeouts?",
        options: [
            "Never timeout sessions for user convenience",
            "Implement idle timeout and absolute timeout",
            "Timeout only on browser close",
            "Use 24-hour timeouts for all users"
        ],
        correct: 1,
        explanation: "<strong>Implement both idle timeout</strong> (after period of inactivity) <strong>and absolute timeout</strong> (maximum session duration regardless of activity). This limits the window of opportunity for session hijacking."
    },
    {
        id: 28,
        category: "Auth",
        question: "What is the risk of using 'remember me' functionality improperly?",
        options: [
            "Users might forget their passwords",
            "Persistent tokens can be stolen and used by attackers",
            "It uses too much browser storage",
            "It makes login slower"
        ],
        correct: 1,
        explanation: "<strong>'Remember me' tokens</strong> stored in cookies can be stolen through XSS or if an attacker has physical access. Implement secure, HTTP-only cookies with expiration and tie tokens to device/browser fingerprints."
    },
    {
        id: 29,
        category: "Auth",
        question: "What is the purpose of password salt?",
        options: [
            "To make passwords taste better",
            "To ensure identical passwords have different hashes",
            "To encrypt passwords",
            "To compress password storage"
        ],
        correct: 1,
        explanation: "<strong>Salting</strong> adds random data to each password before hashing. This ensures identical passwords produce different hashes, preventing rainbow table attacks and making brute force attacks harder."
    },
    {
        id: 30,
        category: "Auth",
        question: "What is a 'secure password reset' process?",
        options: [
            "Emailing the current password to the user",
            "Sending a time-limited, single-use token to the registered email with additional verification",
            "Allowing users to answer security questions only",
            "Resetting to a default password like 'password123'"
        ],
        correct: 1,
        explanation: "<strong>Secure password reset</strong> sends a time-limited, single-use token to the verified email address, optionally with additional verification. Never email the current password or use weak security questions."
    },

    // ===== HTTPS/TLS/Encryption (10 questions) =====
    {
        id: 31,
        category: "TLS",
        question: "What is the main purpose of HTTPS?",
        options: [
            "To make websites faster",
            "To encrypt data transmitted between browser and server",
            "To block ads",
            "To improve SEO rankings only"
        ],
        correct: 1,
        explanation: "<strong>HTTPS</strong> (HTTP Secure) encrypts data transmitted between the browser and server using TLS/SSL, preventing eavesdropping, tampering, and man-in-the-middle attacks."
    },
    {
        id: 32,
        category: "TLS",
        question: "What is the difference between TLS and SSL?",
        options: [
            "They are the same thing",
            "TLS is the modern successor to SSL; SSL is deprecated",
            "SSL is more secure than TLS",
            "TLS is only for mobile apps"
        ],
        correct: 1,
        explanation: "<strong>TLS (Transport Layer Security)</strong> is the modern, more secure successor to SSL (Secure Sockets Layer). SSL versions 2.0 and 3.0 are deprecated and should not be used. Use TLS 1.2 or 1.3."
    },
    {
        id: 33,
        category: "TLS",
        question: "What is a man-in-the-middle (MITM) attack?",
        options: [
            "A server sitting between two clients",
            "An attacker intercepts and potentially alters communication between two parties",
            "A proxy server for caching",
            "Load balancing between servers"
        ],
        correct: 1,
        explanation: "<strong>MITM attacks</strong> occur when an attacker secretly intercepts and potentially alters communication between two parties who believe they're communicating directly. HTTPS/TLS helps prevent this."
    },
    {
        id: 34,
        category: "TLS",
        question: "What is perfect forward secrecy (PFS)?",
        options: [
            "Keeping session data forever",
            "Ensuring session keys cannot be compromised even if private keys are leaked",
            "Always using the same encryption key",
            "Storing encryption keys in plaintext"
        ],
        correct: 1,
        explanation: "<strong>Perfect Forward Secrecy</strong> ensures that session keys are not compromised even if the server's private key is leaked later. Each session uses unique ephemeral keys (achieved with ECDHE or DHE)."
    },
    {
        id: 35,
        category: "TLS",
        question: "What is HSTS (HTTP Strict Transport Security)?",
        options: [
            "A type of SSL certificate",
            "A header that forces browsers to use HTTPS connections only",
            "A way to compress HTTP responses",
            "A type of firewall"
        ],
        correct: 1,
        explanation: "<strong>HSTS</strong> is a response header that tells browsers to only access the site using HTTPS, preventing downgrade attacks and cookie hijacking. It includes a max-age directive and can include subdomains."
    },
    {
        id: 36,
        category: "TLS",
        question: "What is the purpose of a Certificate Authority (CA)?",
        options: [
            "To issue SSL/TLS certificates and verify domain ownership",
            "To encrypt all website traffic",
            "To host websites securely",
            "To generate random numbers"
        ],
        correct: 0,
        explanation: "<strong>Certificate Authorities (CAs)</strong> are trusted entities that issue SSL/TLS certificates after verifying domain ownership. Browsers trust certificates signed by recognized CAs."
    },
    {
        id: 37,
        category: "TLS",
        question: "What is certificate pinning?",
        options: [
            "Pinning a certificate to a wall",
            "Hardcoding expected certificate/public key in the application",
            "Using multiple SSL certificates",
            "Renewing certificates daily"
        ],
        correct: 1,
        explanation: "<strong>Certificate pinning</strong> hardcodes the expected certificate or public key in the application, preventing MITM attacks even if a rogue CA issues a fraudulent certificate for your domain."
    },
    {
        id: 38,
        category: "TLS",
        question: "What is the risk of using self-signed certificates in production?",
        options: [
            "They are too expensive",
            "Browsers will show security warnings and users may ignore them, enabling MITM attacks",
            "They encrypt data too strongly",
            "They expire too quickly"
        ],
        correct: 1,
        explanation: "<strong>Self-signed certificates</strong> aren't trusted by browsers by default, causing security warnings. Users may click through warnings, making them vulnerable to MITM attacks. Use certificates from trusted CAs in production."
    },
    {
        id: 39,
        category: "TLS",
        question: "What is the TLS handshake?",
        options: [
            "A physical greeting between servers",
            "The process of establishing a secure connection between client and server",
            "Signing a certificate",
            "Updating TLS versions"
        ],
        correct: 1,
        explanation: "<strong>TLS handshake</strong> is the process where client and server agree on encryption algorithms, authenticate each other (via certificates), and generate session keys for symmetric encryption."
    },
    {
        id: 40,
        category: "TLS",
        question: "Which TLS version should be used in 2024?",
        options: [
            "SSL 3.0",
            "TLS 1.0 or 1.1",
            "TLS 1.2 or 1.3",
            "Any version works"
        ],
        correct: 2,
        explanation: "<strong>TLS 1.2 or 1.3</strong> should be used. TLS 1.0 and 1.1 are deprecated due to security vulnerabilities. SSL 2.0 and 3.0 are obsolete and insecure. TLS 1.3 is the latest and most secure version."
    },

    // ===== XSS, CSRF, SQL Injection prevention (15 questions) =====
    {
        id: 41,
        category: "Injection",
        question: "What is Cross-Site Scripting (XSS)?",
        options: [
            "A server-side scripting language",
            "Injecting malicious scripts into web pages viewed by other users",
            "Cross-browser compatibility issues",
            "A type of SQL injection"
        ],
        correct: 1,
        explanation: "<strong>XSS (Cross-Site Scripting)</strong> allows attackers to inject client-side scripts into web pages viewed by other users. This can steal cookies, session tokens, or deface websites."
    },
    {
        id: 42,
        category: "Injection",
        question: "What are the three main types of XSS?",
        options: [
            "SQL, NoSQL, and LDAP",
            "Stored, Reflected, and DOM-based",
            "GET, POST, and PUT",
            "Local, Session, and Cookie"
        ],
        correct: 1,
        explanation: "<strong>Stored XSS</strong> - malicious script stored on the server. <strong>Reflected XSS</strong> - script in URL reflected in response. <strong>DOM-based XSS</strong> - client-side JavaScript writes unsanitized data to DOM."
    },
    {
        id: 43,
        category: "Injection",
        question: "What is the primary defense against XSS?",
        options: [
            "Using HTTPS only",
            "Input validation and output encoding/escaping",
            "Strong password policies",
            "Database encryption"
        ],
        correct: 1,
        explanation: "<strong>Input validation and output encoding</strong> are the primary defenses. Validate input on the server side, and encode/escape output based on context (HTML, JavaScript, URL, CSS) before rendering."
    },
    {
        id: 44,
        category: "Injection",
        question: "What is a Content Security Policy (CSP)?",
        options: [
            "A document describing company security",
            "An HTTP header that controls resources the browser can load",
            "A type of SSL certificate",
            "A password policy"
        ],
        correct: 1,
        explanation: "<strong>CSP</strong> is an HTTP header that specifies which dynamic resources are allowed to load. It helps prevent XSS by restricting inline scripts, eval(), and specifying allowed script sources."
    },
    {
        id: 45,
        category: "Injection",
        question: "What is Cross-Site Request Forgery (CSRF)?",
        options: [
            "A type of XSS attack",
            "Tricking users into performing unwanted actions on authenticated websites",
            "Forging SSL certificates",
            "Creating fake user accounts"
        ],
        correct: 1,
        explanation: "<strong>CSRF</strong> tricks authenticated users into submitting requests they didn't intend to, such as changing passwords or making purchases. The attack exploits the fact that browsers automatically send cookies with requests."
    },
    {
        id: 46,
        category: "Injection",
        question: "What is the primary defense against CSRF?",
        options: [
            "Using HTTPS",
            "CSRF tokens (synchronizer tokens)",
            "Input validation",
            "Output encoding"
        ],
        correct: 1,
        explanation: "<strong>CSRF tokens</strong> are unique, secret, unpredictable values embedded in forms. The server validates the token with each request. Since attackers can't read the token (same-origin policy), they can't forge requests."
    },
    {
        id: 47,
        category: "Injection",
        question: "What is SQL Injection?",
        options: [
            "Injecting SQL code into databases for optimization",
            "Inserting malicious SQL statements through application input",
            "A method of database backup",
            "Encrypting SQL queries"
        ],
        correct: 1,
        explanation: "<strong>SQL Injection</strong> occurs when attackers insert malicious SQL code into input fields. This can read, modify, or delete database data, bypass authentication, or execute administrative operations."
    },
    {
        id: 48,
        category: "Injection",
        question: "What is the best defense against SQL Injection?",
        options: [
            "Input validation only",
            "Parameterized queries (prepared statements)",
            "Using NoSQL databases",
            "Escaping special characters manually"
        ],
        correct: 1,
        explanation: "<strong>Parameterized queries (prepared statements)</strong> are the most effective defense. They separate SQL code from data, ensuring user input is never interpreted as SQL commands."
    },
    {
        id: 49,
        category: "Injection",
        question: "What is a blind SQL injection attack?",
        options: [
            "SQL injection that doesn't return errors",
            "Inferring database structure through true/false questions",
            "Invisible to firewalls",
            "Attacking without knowing the database type"
        ],
        correct: 1,
        explanation: "<strong>Blind SQL injection</strong> occurs when the application doesn't return error messages or query results. Attackers infer information by asking true/false questions and observing application behavior differences."
    },
    {
        id: 50,
        category: "Injection",
        question: "What is the SameSite cookie attribute?",
        options: [
            "A cookie's expiration time",
            "Controls when cookies are sent with cross-site requests",
            "The cookie's encryption method",
            "The domain a cookie belongs to"
        ],
        correct: 1,
        explanation: "<strong>SameSite</strong> controls when cookies are sent with cross-site requests. 'Strict' never sends cross-site, 'Lax' sends for top-level navigation, 'None' sends always (requires Secure). Helps prevent CSRF."
    },
    {
        id: 51,
        category: "Injection",
        question: "What is the X-XSS-Protection header?",
        options: [
            "A modern replacement for CSP",
            "A legacy header that enables browser's XSS filter (deprecated)",
            "A server-side XSS protection",
            "An encryption method"
        ],
        correct: 1,
        explanation: "<strong>X-XSS-Protection</strong> was a header that enabled browser's built-in XSS filters. It's now deprecated and can even introduce vulnerabilities. Modern best practice is to use CSP with X-XSS-Protection: 0."
    },
    {
        id: 52,
        category: "Injection",
        question: "What is a NoSQL injection attack?",
        options: [
            "Not possible with NoSQL databases",
            "Injecting malicious code into NoSQL queries",
            "Only affects MongoDB",
            "A type of network attack"
        ],
        correct: 1,
        explanation: "<strong>NoSQL injection</strong> is similar to SQL injection but targets NoSQL databases like MongoDB. Attackers manipulate query structures using special operators like $ne, $gt, or $where to bypass authentication or extract data."
    },
    {
        id: 53,
        category: "Injection",
        question: "What is the HttpOnly cookie attribute?",
        options: [
            "Makes cookies accessible only via HTTPS",
            "Prevents JavaScript from accessing the cookie",
            "Limits cookie to specific paths",
            "Makes cookies expire quickly"
        ],
        correct: 1,
        explanation: "<strong>HttpOnly</strong> prevents JavaScript from accessing the cookie through document.cookie. This mitigates the risk of cookie theft via XSS attacks. Combine with Secure and SameSite attributes."
    },
    {
        id: 54,
        category: "Injection",
        question: "What is the Secure cookie attribute?",
        options: [
            "Encrypts cookie contents",
            "Cookie is only sent over HTTPS connections",
            "Requires authentication to access",
            "Validates cookie signature"
        ],
        correct: 1,
        explanation: "<strong>Secure</strong> attribute ensures the cookie is only sent over HTTPS connections. This prevents cookie theft via network sniffing on unencrypted connections (man-in-the-middle attacks)."
    },
    {
        id: 55,
        category: "Injection",
        question: "What is DOM-based XSS?",
        options: [
            "XSS in the Document Object Model",
            "Client-side XSS where JavaScript writes unsanitized data to the DOM",
            "Server-side XSS only",
            "XSS that affects database storage"
        ],
        correct: 1,
        explanation: "<strong>DOM-based XSS</strong> occurs when client-side JavaScript writes unsanitized user input to the DOM. The attack happens entirely in the browser, often through vulnerable JavaScript functions like innerHTML, document.write(), or eval()."
    },

    // ===== JWT, OAuth, Session management (10 questions) =====
    {
        id: 56,
        category: "Session",
        question: "What is a JSON Web Token (JWT)?",
        options: [
            "A type of database token",
            "A compact, URL-safe token format for claims transfer",
            "A password hashing algorithm",
            "A session storage mechanism only"
        ],
        correct: 1,
        explanation: "<strong>JWT (JSON Web Token)</strong> is a compact, URL-safe token format (header.payload.signature) for securely transmitting claims between parties. Commonly used for authentication and information exchange."
    },
    {
        id: 57,
        category: "Session",
        question: "What are the three parts of a JWT?",
        options: [
            "Header, Body, Footer",
            "Header, Payload, Signature",
            "Algorithm, Data, Hash",
            "Start, Middle, End"
        ],
        correct: 1,
        explanation: "<strong>JWT structure</strong>: Header (algorithm & token type), Payload (claims/data), and Signature (verification). Format: base64Url(header).base64Url(payload).base64Url(signature)"
    },
    {
        id: 58,
        category: "Session",
        question: "What is the main security concern with storing JWTs in localStorage?",
        options: [
            "It's too slow",
            "Vulnerable to XSS attacks - JavaScript can read and steal tokens",
            "Tokens expire too quickly",
            "It uses too much memory"
        ],
        correct: 1,
        explanation: "<strong>localStorage is vulnerable to XSS</strong>. Any JavaScript running on the page can access localStorage and steal JWTs. Use HttpOnly cookies for JWTs when possible, or implement proper XSS defenses."
    },
    {
        id: 59,
        category: "Session",
        question: "What is OAuth 2.0?",
        options: [
            "A password hashing algorithm",
            "An authorization framework for delegated access",
            "A type of SSL certificate",
            "A database authentication method"
        ],
        correct: 1,
        explanation: "<strong>OAuth 2.0</strong> is an authorization framework that enables applications to obtain limited access to user accounts on HTTP services. It allows delegated access (e.g., 'Login with Google') without sharing passwords."
    },
    {
        id: 60,
        category: "Session",
        question: "What is the difference between OAuth 2.0 and OpenID Connect?",
        options: [
            "They are the same",
            "OAuth 2.0 is for authorization, OpenID Connect adds authentication layer on top",
            "OAuth is newer than OpenID Connect",
            "OpenID is for mobile only"
        ],
        correct: 1,
        explanation: "<strong>OAuth 2.0</strong> handles authorization (access to resources). <strong>OpenID Connect (OIDC)</strong> is an authentication layer built on top of OAuth 2.0 that provides identity verification (who the user is)."
    },
    {
        id: 61,
        category: "Session",
        question: "What is a refresh token?",
        options: [
            "A token that reloads the page",
            "A long-lived token used to obtain new access tokens",
            "A token for refreshing the browser",
            "A token with updated permissions"
        ],
        correct: 1,
        explanation: "<strong>Refresh tokens</strong> are long-lived credentials used to obtain new access tokens when they expire. This allows users to stay logged in without re-authenticating while keeping access tokens short-lived."
    },
    {
        id: 62,
        category: "Session",
        question: "What is session fixation?",
        options: [
            "Fixing session timeouts",
            "Attacker sets a known session ID before user authenticates",
            "Creating too many sessions",
            "Session data corruption"
        ],
        correct: 1,
        explanation: "<strong>Session fixation</strong> occurs when an attacker sets a known session ID (via URL or cookie) and tricks the user into authenticating with that ID. After login, the attacker uses the same ID to access the session."
    },
    {
        id: 63,
        category: "Session",
        question: "What is the best practice for session ID generation?",
        options: [
            "Sequential numbers starting from 1",
            "Cryptographically secure random tokens of sufficient length (128+ bits)",
            "User's email address",
            "Current timestamp"
        ],
        correct: 1,
        explanation: "<strong>Session IDs</strong> must be cryptographically secure random values with at least 128 bits of entropy. This prevents attackers from guessing or predicting valid session IDs."
    },
    {
        id: 64,
        category: "Session",
        question: "What is the 'state' parameter in OAuth 2.0 used for?",
        options: [
            "Storing user state data",
            "CSRF protection - maintaining state between request and callback",
            "Application state management",
            "Session storage"
        ],
        correct: 1,
        explanation: "<strong>The 'state' parameter</strong> in OAuth 2.0 is used for CSRF protection. The client generates a random value, sends it to the authorization server, and validates it matches on callback to prevent CSRF attacks."
    },
    {
        id: 65,
        category: "Session",
        question: "What should you do when a user logs out?",
        options: [
            "Just clear the browser history",
            "Invalidate the session server-side and clear client-side tokens",
            "Refresh the page only",
            "Delete the user account"
        ],
        correct: 1,
        explanation: "<strong>Proper logout</strong> requires: 1) Invalidate session server-side (remove from session store), 2) Clear cookies and tokens client-side, 3) Potentially blacklist JWTs if using a token blacklist system."
    },

    // ===== CORS, CSP, Security headers (10 questions) =====
    {
        id: 66,
        category: "Headers",
        question: "What is CORS (Cross-Origin Resource Sharing)?",
        options: [
            "A type of database sharing",
            "A mechanism allowing restricted resources to be requested from another domain",
            "A password sharing protocol",
            "A type of encryption"
        ],
        correct: 1,
        explanation: "<strong>CORS</strong> is a security mechanism that allows web servers to specify which origins (domains) can access their resources. It uses HTTP headers to tell browsers to permit cross-origin requests."
    },
    {
        id: 67,
        category: "Headers",
        question: "What is a preflight request in CORS?",
        options: [
            "A request sent before the main request for non-simple methods",
            "A request for previewing content",
            "A request to check server status",
            "A type of GET request"
        ],
        correct: 0,
        explanation: "<strong>Preflight requests</strong> are OPTIONS requests sent by browsers before non-simple requests (PUT, DELETE, custom headers). The server must approve the actual request with appropriate CORS headers."
    },
    {
        id: 68,
        category: "Headers",
        question: "What is the Access-Control-Allow-Origin header?",
        options: [
            "A header that blocks all cross-origin requests",
            "Specifies which origins can access the resource",
            "Controls cookie access",
            "Sets the server timezone"
        ],
        correct: 1,
        explanation: "<strong>Access-Control-Allow-Origin</strong> specifies which origins can access the resource. Use specific origins (e.g., 'https://example.com') instead of '*' when credentials are involved."
    },
    {
        id: 69,
        category: "Headers",
        question: "What is the risk of using Access-Control-Allow-Origin: *?",
        options: [
            "It makes requests slower",
            "It allows any website to access your API, potentially exposing sensitive data",
            "It breaks HTTPS",
            "It causes CORS errors"
        ],
        correct: 1,
        explanation: "<strong>Wildcard (*)</strong> allows any origin to access your API. This can expose sensitive data to malicious websites. Avoid with credentials, and prefer specific origin whitelisting when possible."
    },
    {
        id: 70,
        category: "Headers",
        question: "What does the X-Frame-Options header prevent?",
        options: [
            "SQL injection",
            "Clickjacking attacks by controlling iframe embedding",
            "XSS attacks",
            "CSRF attacks"
        ],
        correct: 1,
        explanation: "<strong>X-Frame-Options</strong> prevents your site from being embedded in iframes on other sites, protecting against clickjacking attacks. Values: DENY, SAMEORIGIN, or ALLOW-FROM. Use CSP frame-ancestors as modern alternative."
    },
    {
        id: 71,
        category: "Headers",
        question: "What is the X-Content-Type-Options: nosniff header for?",
        options: [
            "Prevents MIME type sniffing attacks",
            "Blocks all JavaScript execution",
            "Prevents CSS injection",
            "Disables browser caching"
        ],
        correct: 0,
        explanation: "<strong>X-Content-Type-Options: nosniff</strong> prevents browsers from MIME-sniffing a response away from the declared content-type. This prevents attacks where malicious content is disguised as safe content."
    },
    {
        id: 72,
        category: "Headers",
        question: "What is the Referrer-Policy header?",
        options: [
            "Controls whether browser sends Referer header and how much info it includes",
            "Controls website access policies",
            "Sets cookie policies",
            "Defines password policies"
        ],
        correct: 0,
        explanation: "<strong>Referrer-Policy</strong> controls how much referrer information is included with requests. Options include no-referrer, no-referrer-when-downgrade, origin, strict-origin-when-cross-origin, etc."
    },
    {
        id: 73,
        category: "Headers",
        question: "What is a good CSP (Content Security Policy) for preventing XSS?",
        options: [
            "default-src *",
            "default-src 'self'; script-src 'self'; object-src 'none'",
            "allow all sources",
            "no CSP header"
        ],
        correct: 1,
        explanation: "<strong>A strict CSP</strong> like 'default-src 'self'; script-src 'self'; object-src 'none'' prevents inline scripts and restricts script sources. This significantly reduces XSS attack surface."
    },
    {
        id: 74,
        category: "Headers",
        question: "What is the Permissions-Policy header?",
        options: [
            "Sets user permissions",
            "Controls which browser features can be used (camera, microphone, geolocation)",
            "Manages file permissions",
            "Sets database permissions"
        ],
        correct: 1,
        explanation: "<strong>Permissions-Policy</strong> (formerly Feature-Policy) allows websites to control which browser features can be used. Example: 'camera=(), microphone=(), geolocation=(self)' disables camera and microphone, allows geolocation for same-origin."
    },
    {
        id: 75,
        category: "Headers",
        question: "What security headers should every web application have?",
        options: [
            "Only X-Powered-By",
            "CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy",
            "Only Cache-Control",
            "Only Access-Control-Allow-Origin"
        ],
        correct: 1,
        explanation: "<strong>Essential security headers</strong>: CSP (XSS prevention), HSTS (HTTPS enforcement), X-Content-Type-Options (MIME sniffing), X-Frame-Options (clickjacking), Referrer-Policy (privacy). Remove X-Powered-By (information disclosure)."
    },

    // ===== Secrets management, env variables (10 questions) =====
    {
        id: 76,
        category: "Secrets",
        question: "Why should secrets never be committed to version control?",
        options: [
            "They take up too much space",
            "Version control history persists even after deletion, exposing secrets forever",
            "It makes code harder to read",
            "GitHub doesn't allow it"
        ],
        correct: 1,
        explanation: "<strong>Never commit secrets to version control</strong>. Git history persists even after deletion. Secrets in git are exposed forever. Use .gitignore, pre-commit hooks like git-secrets, and secret scanning tools."
    },
    {
        id: 77,
        category: "Secrets",
        question: "What is the proper way to handle API keys in a Node.js application?",
        options: [
            "Hardcode them in the source code",
            "Store in environment variables accessed via process.env",
            "Store in localStorage",
            "Include them in the README"
        ],
        correct: 1,
        explanation: "<strong>Store secrets in environment variables</strong> (process.env in Node.js) loaded from .env files that are never committed. Use libraries like dotenv for local development, and proper secret management in production."
    },
    {
        id: 78,
        category: "Secrets",
        question: "What is a secrets manager (like AWS Secrets Manager, HashiCorp Vault)?",
        options: [
            "A password manager for individuals",
            "A centralized service for securely storing, accessing, and rotating secrets",
            "A type of database",
            "A code editor plugin"
        ],
        correct: 1,
        explanation: "<strong>Secrets managers</strong> provide secure storage, access control, automatic rotation, and audit logging for secrets. They eliminate hardcoded secrets and enable dynamic secret retrieval at runtime."
    },
    {
        id: 79,
        category: "Secrets",
        question: "What should you do if you accidentally commit a secret to git?",
        options: [
            "Just delete the file in the next commit",
            "Rotate the secret immediately and use tools like BFG Repo-Cleaner to remove from history",
            "It's fine, nobody will find it",
            "Create a new git branch"
        ],
        correct: 1,
        explanation: "<strong>Immediately rotate (revoke and regenerate) the secret</strong>, as it may already be compromised. Then use tools like BFG Repo-Cleaner or git-filter-repo to remove it from git history. Never just delete in a new commit."
    },
    {
        id: 80,
        category: "Secrets",
        question: "What is the .env file used for?",
        options: [
            "Storing environment descriptions",
            "Storing environment variables and secrets for local development",
            "Storing error messages",
            "Storing email templates"
        ],
        correct: 1,
        explanation: "<strong>.env files</strong> store environment variables for local development. They should never be committed to version control (add to .gitignore). Use .env.example to show required variables without values."
    },
    {
        id: 81,
        category: "Secrets",
        question: "What is key rotation and why is it important?",
        options: [
            "Physically rotating encryption keys",
            "Regularly replacing cryptographic keys to limit exposure if compromised",
            "Changing keyboard layouts",
            "Rotating SSH keys daily"
        ],
        correct: 1,
        explanation: "<strong>Key rotation</strong> is the practice of regularly replacing cryptographic keys. If a key is compromised, rotation limits the exposure window. Many cloud providers support automatic key rotation."
    },
    {
        id: 82,
        category: "Secrets",
        question: "What is the danger of logging sensitive data?",
        options: [
            "Logs become too large",
            "Logs may be accessible to unauthorized users and persist sensitive information",
            "Logging slows down the application",
            "Logs are difficult to read"
        ],
        correct: 1,
        explanation: "<strong>Never log sensitive data</strong> (passwords, tokens, PII, credit cards). Logs often have different access controls than databases and may be sent to third-party services. Filter sensitive fields before logging."
    },
    {
        id: 83,
        category: "Secrets",
        question: "How should database connection strings be handled?",
        options: [
            "Hardcoded in the application code",
            "Stored in environment variables or secrets manager, never in code",
            "Stored in the database itself",
            "Included in API responses"
        ],
        correct: 1,
        explanation: "<strong>Database credentials</strong> should be stored in environment variables or a secrets manager. Use connection string builders that read from secure sources, never hardcode credentials in source code."
    },
    {
        id: 84,
        category: "Secrets",
        question: "What is a .gitignore file used for?",
        options: [
            "Ignoring git commands",
            "Specifying files/directories that git should ignore",
            "Blocking git access",
            "Creating git branches"
        ],
        correct: 1,
        explanation: "<strong>.gitignore</strong> specifies patterns for files/directories that git should ignore. Always add .env, node_modules, build artifacts, and any files containing secrets to .gitignore."
    },
    {
        id: 85,
        category: "Secrets",
        question: "What is the best practice for managing secrets in Docker containers?",
        options: [
            "Embed secrets in the Dockerfile",
            "Use Docker secrets, environment variables at runtime, or mount secret files",
            "Store secrets in the container image layers",
            "Include secrets in docker-compose.yml"
        ],
        correct: 1,
        explanation: "<strong>Use Docker secrets</strong> (in Docker Swarm), pass environment variables at runtime, or mount secret files. Never bake secrets into images or Dockerfiles - they persist in image layers and registries."
    },

    // ===== Secure coding practices (15 questions) =====
    {
        id: 86,
        category: "Coding",
        question: "What is the principle of 'defense in depth'?",
        options: [
            "Writing deeply nested code",
            "Multiple layers of security controls throughout the application",
            "Using deep learning for security",
            "Deep code review only"
        ],
        correct: 1,
        explanation: "<strong>Defense in depth</strong> means implementing multiple layers of security controls throughout the application stack. If one layer fails, others provide protection. No single point of failure."
    },
    {
        id: 87,
        category: "Coding",
        question: "What is input validation?",
        options: [
            "Validating HTML forms only",
            "Verifying that input meets expected format, type, and constraints before processing",
            "Checking if input is valid JavaScript",
            "Validating database connections"
        ],
        correct: 1,
        explanation: "<strong>Input validation</strong> ensures data meets expected format, type, length, and constraints before processing. Validate on the server side (never trust client-side validation), whitelist allowed values rather than blacklisting."
    },
    {
        id: 88,
        category: "Coding",
        question: "What is the difference between whitelisting and blacklisting?",
        options: [
            "No difference",
            "Whitelisting allows only known-good input; blacklisting blocks known-bad input",
            "Whitelisting is for IP addresses only",
            "Blacklisting is more secure"
        ],
        correct: 1,
        explanation: "<strong>Whitelisting</strong> (allowlisting) only permits known-good input. <strong>Blacklisting</strong> tries to block known-bad input. Whitelisting is more secure because you can't anticipate all possible attacks."
    },
    {
        id: 89,
        category: "Coding",
        question: "What is the risk of using eval() in JavaScript?",
        options: [
            "It makes code run slower",
            "It can execute arbitrary code, leading to code injection vulnerabilities",
            "It's deprecated",
            "It doesn't work in modern browsers"
        ],
        correct: 1,
        explanation: "<strong>Avoid eval()</strong> and similar functions (Function constructor, setTimeout with strings). They execute arbitrary code and can lead to code injection if user input is passed to them. Use safer alternatives."
    },
    {
        id: 90,
        category: "Coding",
        question: "What is a race condition in security?",
        options: [
            "A competition between hackers",
            "When timing-dependent behavior can be exploited due to improper synchronization",
            "When two users access the same file",
            "A network latency issue"
        ],
        correct: 1,
        explanation: "<strong>Race conditions</strong> occur when the system's behavior depends on the timing of events. Security vulnerabilities arise when attackers can exploit the window between check and use (TOCTOU - Time of Check to Time of Use)."
    },
    {
        id: 91,
        category: "Coding",
        question: "What is the principle of 'fail securely'?",
        options: [
            "Applications should never fail",
            "When failures occur, default to a secure state",
            "Always show detailed error messages",
            "Fail loudly with maximum information"
        ],
        correct: 1,
        explanation: "<strong>Fail securely</strong> means that when failures occur (errors, exceptions, crashes), the system defaults to a secure state. Don't expose sensitive information in error messages or grant unintended access."
    },
    {
        id: 92,
        category: "Coding",
        question: "Why should you avoid exposing detailed error messages to users?",
        options: [
            "They might confuse users",
            "They can reveal system information useful to attackers (stack traces, database schemas, file paths)",
            "They slow down the application",
            "They use too much bandwidth"
        ],
        correct: 1,
        explanation: "<strong>Detailed error messages</strong> can expose sensitive information: stack traces, database schemas, file paths, technology versions, and internal system details. Log details internally, show generic messages to users."
    },
    {
        id: 93,
        category: "Coding",
        question: "What is the purpose of a Web Application Firewall (WAF)?",
        options: [
            "Replace secure coding practices",
            "Filter and monitor HTTP traffic between web application and the internet",
            "Speed up web applications",
            "Replace HTTPS"
        ],
        correct: 1,
        explanation: "<strong>WAFs</strong> filter and monitor HTTP traffic, blocking common attacks like SQL injection and XSS. However, they're not a replacement for secure coding - they're a defense-in-depth layer that can be bypassed."
    },
    {
        id: 94,
        category: "Coding",
        question: "What is dependency scanning?",
        options: [
            "Scanning for viruses in dependencies",
            "Checking third-party libraries for known security vulnerabilities",
            "Counting the number of dependencies",
            "Removing unused dependencies"
        ],
        correct: 1,
        explanation: "<strong>Dependency scanning</strong> checks third-party libraries for known vulnerabilities (CVEs). Use tools like Snyk, OWASP Dependency-Check, npm audit, or GitHub Dependabot to identify and update vulnerable dependencies."
    },
    {
        id: 95,
        category: "Coding",
        question: "What is SAST (Static Application Security Testing)?",
        options: [
            "Testing running applications",
            "Analyzing source code for security vulnerabilities without executing it",
            "Testing with static data",
            "Manual code review only"
        ],
        correct: 1,
        explanation: "<strong>SAST</strong> analyzes source code (static analysis) to find security vulnerabilities without executing the code. Tools like SonarQube, Checkmarx, and CodeQL can detect issues early in the development lifecycle."
    },
    {
        id: 96,
        category: "Coding",
        question: "What is DAST (Dynamic Application Security Testing)?",
        options: [
            "Testing static files",
            "Testing running applications by simulating attacks",
            "Testing database connections",
            "Unit testing security features"
        ],
        correct: 1,
        explanation: "<strong>DAST</strong> tests running applications from the outside by simulating attacks. Unlike SAST, it doesn't require source code access and can find runtime issues like authentication weaknesses and server misconfigurations."
    },
    {
        id: 97,
        category: "Coding",
        question: "What is the 'secure by default' principle?",
        options: [
            "Security is optional",
            "Systems are secure out of the box without requiring configuration",
            "Only default passwords are secure",
            "Security is added later"
        ],
        correct: 1,
        explanation: "<strong>Secure by default</strong> means systems are secure out of the box without requiring configuration. Security features should be enabled by default, and dangerous features should be opt-in rather than opt-out."
    },
    {
        id: 98,
        category: "Coding",
        question: "What is the risk of using components with known vulnerabilities?",
        options: [
            "They might be slower",
            "Attackers can exploit publicly known vulnerabilities with available exploits",
            "They use more memory",
            "They are harder to install"
        ],
        correct: 1,
        explanation: "<strong>Known vulnerabilities</strong> in components (libraries, frameworks) can be easily exploited using publicly available exploit code. Attackers actively scan for these vulnerabilities. Keep dependencies updated."
    },
    {
        id: 99,
        category: "Coding",
        question: "What is a security code review?",
        options: [
            "Checking if code compiles",
            "Manually examining code to identify security flaws and vulnerabilities",
            "Checking code formatting",
            "Testing code performance"
        ],
        correct: 1,
        explanation: "<strong>Security code reviews</strong> involve manually examining code to identify security flaws. They complement automated tools by finding logic errors and business logic vulnerabilities that tools miss."
    },
    {
        id: 100,
        category: "Coding",
        question: "What is the most important security principle for developers to remember?",
        options: [
            "Never use third-party code",
            "Never trust user input - validate everything on the server side",
            "Always use the latest frameworks",
            "Security is the ops team's responsibility"
        ],
        correct: 1,
        explanation: "<strong>Never trust user input</strong> is the foundational security principle. Always validate and sanitize input on the server side. Client-side validation can be bypassed. Assume all input is malicious until proven otherwise."
    }
];

// Shuffle function - Fisher-Yates algorithm
function shuffleArray(array) {
    const arr = [...array];
    for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
}

// Shuffle quiz data
function shuffleQuiz() {
    // Shuffle questions
    const shuffledQuestions = shuffleArray(quizData);
    
    // For each question, shuffle options and update correct index
    return shuffledQuestions.map(q => {
        // Create pairs of [option, originalIndex]
        const optionsWithIndex = q.options.map((opt, idx) => ({
            text: opt,
            originalIndex: idx
        }));
        
        // Shuffle options
        const shuffledOptions = shuffleArray(optionsWithIndex);
        
        // Find new correct index
        const newCorrectIndex = shuffledOptions.findIndex(
            opt => opt.originalIndex === q.correct
        );
        
        // Return with shuffled options
        return {
            ...q,
            options: shuffledOptions.map(opt => opt.text),
            correct: newCorrectIndex
        };
    });
}

// Shuffle quiz on load
let shuffledQuizData = shuffleQuiz();

// Game state
let currentQuestion = 0;
let score = 0;
let userAnswers = new Array(shuffledQuizData.length).fill(null);

// DOM Elements
const questionCounter = document.getElementById('questionCounter');
const categoryBadge = document.getElementById('categoryBadge');
const questionText = document.getElementById('questionText');
const optionsContainer = document.getElementById('optionsContainer');
const prevBtn = document.getElementById('prevBtn');
const nextBtn = document.getElementById('nextBtn');
const quizCard = document.querySelector('.quiz-card');
const quizComplete = document.getElementById('quizComplete');
const answerModal = document.getElementById('answerModal');

// Category icons
const categoryIcons = {
    'OWASP': '🔐',
    'Auth': '🔑',
    'TLS': '🔒',
    'Injection': '💉',
    'Session': '🎫',
    'Headers': '📋',
    'Secrets': '🤫',
    'Coding': '💻'
};

// Initialize quiz
function initQuiz() {
    loadQuestion(currentQuestion);
    updateNavigation();
}

// Load question
function loadQuestion(index) {
    const question = shuffledQuizData[index];
    
    // Update counter
    questionCounter.textContent = `Question ${index + 1}/${quizData.length}`;
    
    // Update category badge with icon
    const icon = categoryIcons[question.category] || '📝';
    categoryBadge.textContent = `${icon} ${question.category}`;
    
    // Update question text
    questionText.textContent = question.question;
    
    // Clear and rebuild options
    optionsContainer.innerHTML = '';
    question.options.forEach((option, i) => {
        const optionDiv = document.createElement('div');
        optionDiv.className = 'option';
        optionDiv.dataset.index = i;
        
        // Check if user already answered this question
        if (userAnswers[index] === i) {
            optionDiv.classList.add('selected');
            if (i === question.correct) {
                optionDiv.classList.add('correct');
            } else {
                optionDiv.classList.add('incorrect');
            }
        }
        
        optionDiv.innerHTML = `
            <span class="option-letter">${String.fromCharCode(65 + i)}</span>
            <span class="option-text">${escapeHtml(option)}</span>
        `;
        optionDiv.onclick = () => selectOption(i);
        optionsContainer.appendChild(optionDiv);
    });
    
    // If question already answered, show correct answer highlight
    if (userAnswers[index] !== null) {
        const options = optionsContainer.querySelectorAll('.option');
        options[question.correct].classList.add('correct');
    }
}

// Select option
function selectOption(optionIndex) {
    // Prevent re-answering
    if (userAnswers[currentQuestion] !== null) return;
    
    const question = shuffledQuizData[currentQuestion];
    const options = optionsContainer.querySelectorAll('.option');
    
    // Record answer
    userAnswers[currentQuestion] = optionIndex;
    
    // Visual feedback
    options[optionIndex].classList.add('selected');
    
    if (optionIndex === question.correct) {
        options[optionIndex].classList.add('correct');
        score++;
    } else {
        options[optionIndex].classList.add('incorrect');
        options[question.correct].classList.add('correct');
    }
}

// Navigate to previous question
function prevQuestion() {
    if (currentQuestion > 0) {
        currentQuestion--;
        loadQuestion(currentQuestion);
        updateNavigation();
    }
}

// Navigate to next question
function nextQuestion() {
    if (currentQuestion < shuffledQuizData.length - 1) {
        currentQuestion++;
        loadQuestion(currentQuestion);
        updateNavigation();
    } else {
        // Quiz complete
        showResults();
    }
}

// Update navigation buttons
function updateNavigation() {
    prevBtn.disabled = currentQuestion === 0;
    nextBtn.textContent = currentQuestion === shuffledQuizData.length - 1 ? 'Finish ✓' : 'Next →';
}

// Show answer modal
function showAnswer() {
    const question = shuffledQuizData[currentQuestion];
    const correctOption = question.options[question.correct];
    
    document.getElementById('correctAnswer').innerHTML = `
        <strong>Correct Answer: ${String.fromCharCode(65 + question.correct)}. ${escapeHtml(correctOption)}</strong>
    `;
    document.getElementById('explanation').innerHTML = question.explanation;
    
    answerModal.classList.add('active');
}

// Close modal
function closeModal(event) {
    if (!event || event.target === answerModal || event.target.classList.contains('modal-close')) {
        answerModal.classList.remove('active');
    }
}

// Show results
function showResults() {
    quizCard.style.display = 'none';
    quizComplete.style.display = 'block';
    
    document.getElementById('correctCount').textContent = score;
    
    const percentage = (score / shuffledQuizData.length) * 100;
    const resultMessage = document.getElementById('resultMessage');
    
    if (percentage >= 90) {
        resultMessage.textContent = '🏆 Outstanding! You\'re a security expert!';
    } else if (percentage >= 70) {
        resultMessage.textContent = '👍 Great job! Solid security knowledge.';
    } else if (percentage >= 50) {
        resultMessage.textContent = '📚 Good effort! Keep learning.';
    } else {
        resultMessage.textContent = '💪 Keep practicing! Security is a journey.';
    }
}

// Restart quiz
function restartQuiz() {
    // Reshuffle on restart
    shuffledQuizData = shuffleQuiz();
    currentQuestion = 0;
    score = 0;
    userAnswers = new Array(shuffledQuizData.length).fill(null);
    
    quizCard.style.display = 'block';
    quizCard.style.flexDirection = 'column';
    quizComplete.style.display = 'none';
    
    loadQuestion(0);
    updateNavigation();
}

// Utility: Escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Keyboard navigation
document.addEventListener('keydown', (e) => {
    // Number keys 1-4 for options
    if (e.key >= '1' && e.key <= '4') {
        const optionIndex = parseInt(e.key) - 1;
        if (optionIndex < shuffledQuizData[currentQuestion].options.length) {
            selectOption(optionIndex);
        }
    }
    
    // Arrow keys for navigation
    if (e.key === 'ArrowLeft') {
        prevQuestion();
    } else if (e.key === 'ArrowRight') {
        nextQuestion();
    }
    
    // Space or Enter for show answer
    if (e.key === ' ' || e.key === 'Enter') {
        if (answerModal.classList.contains('active')) {
            closeModal();
        } else {
            showAnswer();
        }
    }
    
    // Escape to close modal
    if (e.key === 'Escape') {
        closeModal();
    }
});

// Start when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    try {
        initQuiz();
    } catch (error) {
        console.error('Failed to initialize quiz:', error);
        questionText.textContent = 'Failed to load quiz. Please refresh the page.';
    }
});
